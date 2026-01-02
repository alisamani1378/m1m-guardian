import asyncio, shlex, ipaddress
from .nodes import NodeSpec, _ssh_base

SET_V4 = "m1m_guardian"
SET_V6 = "m1m_guardian6"
_RULE_ENSURED: set[str] = set()
MAX_PENDING = 20000  # backpressure cap per node

def _is_ipv6(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).version == 6
    except ValueError:
        return False

def _q(s: str) -> str:
    return shlex.quote(s)

def _cmd_flush_all(ip: str) -> str:
    qip = _q(ip)
    return f'''if command -v conntrack >/dev/null 2>&1; then
conntrack -D -s {qip} >/dev/null 2>&1 || true
conntrack -D -d {qip} >/dev/null 2>&1 || true
fi'''

def _remote_detect_backend() -> str:
    """
    Echo one of: IPTABLES, NFT
    - IPTABLES when iptables-nft/iptables/iptables-legacy exists
    - NFT when nft exists but no iptables tool is present/effective
    """
    return r'''BACKEND=""
IPT=$(command -v iptables-nft || command -v iptables || command -v iptables-legacy || true)
if [ -n "$IPT" ]; then BACKEND="IPTABLES"; fi
if [ -z "$BACKEND" ] && command -v nft >/dev/null 2>&1; then BACKEND="NFT"; fi
echo "$BACKEND"'''

import logging
log = logging.getLogger("guardian.firewall")

async def ensure_rule(spec: NodeSpec, force: bool = False):
    """
    Idempotently ensure drop-rules and timed sets exist.
    Supports both iptables(+ipset) and nftables-native.
    Now with verification and retry logic.
    """
    key = f"{spec.host}:{spec.ssh_port}"
    if not force and key in _RULE_ENSURED:
        return

    inner = f'''SUDO=""; if [ "$(id -u)" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi; fi

# Optionally bump nf_conntrack_max if too low (best-effort)
if [ -r /proc/sys/net/netfilter/nf_conntrack_max ]; then
  CUR=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 0)
  THRESH=524288
  if [ "$CUR" -lt "$THRESH" ] 2>/dev/null; then
    $SUDO sh -c 'sysctl -w net.netfilter.nf_conntrack_max=524288 >/dev/null 2>&1 || echo > /dev/null'
  fi
fi

# --- detect backend ---
BACKEND=$({_remote_detect_backend()})

case "$BACKEND" in
  "IPTABLES")
    # ensure ipset available
    ( command -v ipset >/dev/null 2>&1 ) || \
      ( $SUDO apt-get update -y >/dev/null 2>&1 && $SUDO apt-get install -y ipset >/dev/null 2>&1 ) || \
      ( $SUDO apk add --no-cache ipset >/dev/null 2>&1 ) || \
      ( $SUDO yum install -y ipset >/dev/null 2>&1 ) || true

    IPT=$(command -v iptables-nft || command -v iptables || command -v iptables-legacy || true)
    IPT6=$(command -v ip6tables-nft || command -v ip6tables || command -v ip6tables-legacy || true)
    if [ -z "$IPT" ] && [ -z "$IPT6" ]; then exit 0; fi

    # create timed sets with large capacity only if missing (suppress stderr to avoid noise)
    $SUDO ipset list {SET_V4} >/dev/null 2>&1 || $SUDO ipset create {SET_V4} hash:ip timeout 0 hashsize 16384 maxelem 1048576 2>/dev/null
    $SUDO ipset list {SET_V6} >/dev/null 2>&1 || $SUDO ipset create {SET_V6} hash:ip family inet6 timeout 0 hashsize 16384 maxelem 1048576 2>/dev/null

    # IPv4 rules (prefer DOCKER-USER if exists) with TCP reset + UDP reject, then DROP
    if [ -n "$IPT" ]; then
      if $IPT -S DOCKER-USER >/dev/null 2>&1; then
        $IPT -C DOCKER-USER -p tcp -m set --match-set {SET_V4} src -j REJECT --reject-with tcp-reset 2>/dev/null || $SUDO $IPT -I DOCKER-USER 1 -p tcp -m set --match-set {SET_V4} src -j REJECT --reject-with tcp-reset
        $IPT -C DOCKER-USER -p udp -m set --match-set {SET_V4} src -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || $SUDO $IPT -I DOCKER-USER 2 -p udp -m set --match-set {SET_V4} src -j REJECT --reject-with icmp-port-unreachable
        $IPT -C DOCKER-USER -m set --match-set {SET_V4} src -j DROP 2>/dev/null || $SUDO $IPT -I DOCKER-USER 3 -m set --match-set {SET_V4} src -j DROP
      else
        $IPT -C INPUT   -p tcp -m set --match-set {SET_V4} src -j REJECT --reject-with tcp-reset 2>/dev/null || $SUDO $IPT -I INPUT   1 -p tcp -m set --match-set {SET_V4} src -j REJECT --reject-with tcp-reset
        $IPT -C INPUT   -p udp -m set --match-set {SET_V4} src -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || $SUDO $IPT -I INPUT   2 -p udp -m set --match-set {SET_V4} src -j REJECT --reject-with icmp-port-unreachable
        $IPT -C INPUT   -m set --match-set {SET_V4} src -j DROP 2>/dev/null || $SUDO $IPT -I INPUT   3 -m set --match-set {SET_V4} src -j DROP
        $IPT -C FORWARD -p tcp -m set --match-set {SET_V4} src -j REJECT --reject-with tcp-reset 2>/dev/null || $SUDO $IPT -I FORWARD 1 -p tcp -m set --match-set {SET_V4} src -j REJECT --reject-with tcp-reset
        $IPT -C FORWARD -p udp -m set --match-set {SET_V4} src -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || $SUDO $IPT -I FORWARD 2 -p udp -m set --match-set {SET_V4} src -j REJECT --reject-with icmp-port-unreachable
        $IPT -C FORWARD -m set --match-set {SET_V4} src -j DROP 2>/dev/null || $SUDO $IPT -I FORWARD 3 -m set --match-set {SET_V4} src -j DROP
      fi
    fi

    # IPv6 rules using ip6tables (prefer DOCKER-USER if exists)
    if [ -n "$IPT6" ]; then
      if $IPT6 -S DOCKER-USER >/dev/null 2>&1; then
        $IPT6 -C DOCKER-USER -p tcp -m set --match-set {SET_V6} src -j REJECT --reject-with tcp-reset 2>/dev/null || $SUDO $IPT6 -I DOCKER-USER 1 -p tcp -m set --match-set {SET_V6} src -j REJECT --reject-with tcp-reset
        $IPT6 -C DOCKER-USER -p udp -m set --match-set {SET_V6} src -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null || $SUDO $IPT6 -I DOCKER-USER 2 -p udp -m set --match-set {SET_V6} src -j REJECT --reject-with icmp6-port-unreachable
        $IPT6 -C DOCKER-USER -m set --match-set {SET_V6} src -j DROP 2>/dev/null || $SUDO $IPT6 -I DOCKER-USER 3 -m set --match-set {SET_V6} src -j DROP
      else
        $IPT6 -C INPUT   -p tcp -m set --match-set {SET_V6} src -j REJECT --reject-with tcp-reset 2>/dev/null || $SUDO $IPT6 -I INPUT   1 -p tcp -m set --match-set {SET_V6} src -j REJECT --reject-with tcp-reset
        $IPT6 -C INPUT   -p udp -m set --match-set {SET_V6} src -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null || $SUDO $IPT6 -I INPUT   2 -p udp -m set --match-set {SET_V6} src -j REJECT --reject-with icmp6-port-unreachable
        $IPT6 -C INPUT   -m set --match-set {SET_V6} src -j DROP 2>/dev/null || $SUDO $IPT6 -I INPUT   3 -m set --match-set {SET_V6} src -j DROP
        $IPT6 -C FORWARD -p tcp -m set --match-set {SET_V6} src -j REJECT --reject-with tcp-reset 2>/dev/null || $SUDO $IPT6 -I FORWARD 1 -p tcp -m set --match-set {SET_V6} src -j REJECT --reject-with tcp-reset
        $IPT6 -C FORWARD -p udp -m set --match-set {SET_V6} src -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null || $SUDO $IPT6 -I FORWARD 2 -p udp -m set --match-set {SET_V6} src -j REJECT --reject-with icmp6-port-unreachable
        $IPT6 -C FORWARD -m set --match-set {SET_V6} src -j DROP 2>/dev/null || $SUDO $IPT6 -I FORWARD 3 -m set --match-set {SET_V6} src -j DROP
      fi
    fi
  ;;
  "NFT")
    # ensure table and base chains exist
    $SUDO nft list table inet filter >/dev/null 2>&1 || $SUDO nft add table inet filter
    $SUDO nft list chain inet filter INPUT   >/dev/null 2>&1 || $SUDO nft add chain inet filter INPUT   '{{ type filter hook input priority 0 ; }}'
    $SUDO nft list chain inet filter FORWARD >/dev/null 2>&1 || $SUDO nft add chain inet filter FORWARD '{{ type filter hook forward priority 0 ; }}'

    # sets با قابلیت timeout و ظرفیت بالا
    $SUDO nft list set inet filter {SET_V4}   >/dev/null 2>&1 || $SUDO nft add set inet filter {SET_V4}   '{{ type ipv4_addr; timeout 0s; flags timeout; size 1048576; }}'
    $SUDO nft list set inet filter {SET_V6}   >/dev/null 2>&1 || $SUDO nft add set inet filter {SET_V6}   '{{ type ipv6_addr; timeout 0s; flags timeout; size 1048576; }}'

    if $SUDO nft list chain inet filter DOCKER-USER >/dev/null 2>&1; then
      # Prefer Docker's DOCKER-USER chain (evaluated early in FORWARD path)
      $SUDO nft list ruleset | grep -q 'chain DOCKER-USER' && $SUDO nft list ruleset | grep -q "ip saddr @{SET_V4} .* reject with tcp reset" || $SUDO nft insert rule inet filter DOCKER-USER ip saddr @{SET_V4} tcp reject with tcp reset
      $SUDO nft list ruleset | grep -q 'chain DOCKER-USER' && $SUDO nft list ruleset | grep -q "ip saddr @{SET_V4} .* udp reject" || $SUDO nft insert rule inet filter DOCKER-USER ip saddr @{SET_V4} udp reject
      $SUDO nft list ruleset | grep -q 'chain DOCKER-USER' && $SUDO nft list ruleset | grep -q '@{SET_V4}.* drop' || $SUDO nft insert rule inet filter DOCKER-USER ip saddr @{SET_V4} drop

      $SUDO nft list ruleset | grep -q 'chain DOCKER-USER' && $SUDO nft list ruleset | grep -q "ip6 saddr @{SET_V6} .* reject with tcp reset" || $SUDO nft insert rule inet filter DOCKER-USER ip6 saddr @{SET_V6} tcp reject with tcp reset
      $SUDO nft list ruleset | grep -q 'chain DOCKER-USER' && $SUDO nft list ruleset | grep -q "ip6 saddr @{SET_V6} .* udp reject" || $SUDO nft insert rule inet filter DOCKER-USER ip6 saddr @{SET_V6} udp reject
      $SUDO nft list ruleset | grep -q 'chain DOCKER-USER' && $SUDO nft list ruleset | grep -q '@{SET_V6}.* drop' || $SUDO nft insert rule inet filter DOCKER-USER ip6 saddr @{SET_V6} drop
    else
      # Install rules in both INPUT and FORWARD at top (insert) to preempt established-accept rules
      $SUDO nft list ruleset | grep -q 'chain INPUT'   && $SUDO nft list ruleset | grep -q "ip saddr @{SET_V4} .* reject with tcp reset" || $SUDO nft insert rule inet filter INPUT   ip saddr @{SET_V4} tcp reject with tcp reset
      $SUDO nft list ruleset | grep -q 'chain INPUT'   && $SUDO nft list ruleset | grep -q "ip saddr @{SET_V4} .* udp reject" || $SUDO nft insert rule inet filter INPUT   ip saddr @{SET_V4} udp reject
      $SUDO nft list ruleset | grep -q 'chain INPUT'   && $SUDO nft list ruleset | grep -q '@{SET_V4}.* drop' || $SUDO nft insert rule inet filter INPUT   ip saddr @{SET_V4} drop

      $SUDO nft list ruleset | grep -q 'chain FORWARD' && $SUDO nft list ruleset | grep -q "ip saddr @{SET_V4} .* reject with tcp reset" || $SUDO nft insert rule inet filter FORWARD ip saddr @{SET_V4} tcp reject with tcp reset
      $SUDO nft list ruleset | grep -q 'chain FORWARD' && $SUDO nft list ruleset | grep -q "ip saddr @{SET_V4} .* udp reject" || $SUDO nft insert rule inet filter FORWARD ip saddr @{SET_V4} udp reject
      $SUDO nft list ruleset | grep -q 'chain FORWARD' && $SUDO nft list ruleset | grep -q '@{SET_V4}.* drop' || $SUDO nft insert rule inet filter FORWARD ip saddr @{SET_V4} drop

      $SUDO nft list ruleset | grep -q 'chain INPUT'   && $SUDO nft list ruleset | grep -q "ip6 saddr @{SET_V6} .* reject with tcp reset" || $SUDO nft insert rule inet filter INPUT   ip6 saddr @{SET_V6} tcp reject with tcp reset
      $SUDO nft list ruleset | grep -q 'chain INPUT'   && $SUDO nft list ruleset | grep -q "ip6 saddr @{SET_V6} .* udp reject" || $SUDO nft insert rule inet filter INPUT   ip6 saddr @{SET_V6} udp reject
      $SUDO nft list ruleset | grep -q 'chain INPUT'   && $SUDO nft list ruleset | grep -q '@{SET_V6}.* drop' || $SUDO nft insert rule inet filter INPUT   ip6 saddr @{SET_V6} drop
      $SUDO nft list ruleset | grep -q 'chain FORWARD' && $SUDO nft list ruleset | grep -q "ip6 saddr @{SET_V6} .* reject with tcp reset" || $SUDO nft insert rule inet filter FORWARD ip6 saddr @{SET_V6} tcp reject with tcp reset
      $SUDO nft list ruleset | grep -q 'chain FORWARD' && $SUDO nft list ruleset | grep -q "ip6 saddr @{SET_V6} .* udp reject" || $SUDO nft insert rule inet filter FORWARD ip6 saddr @{SET_V6} udp reject
      $SUDO nft list ruleset | grep -q 'chain FORWARD' && $SUDO nft list ruleset | grep -q '@{SET_V6}.* drop' || $SUDO nft insert rule inet filter FORWARD ip6 saddr @{SET_V6} drop
    fi
  ;;
  *)
    # هیچ بک‌اندی در دسترس نیست
    exit 0
  ;;
esac
true'''.strip()

    # Execute ensure_rule script
    cmd = _ssh_base(spec) + [inner]
    p = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    out, _ = await p.communicate()
    
    # Now verify that rules were actually added
    verify_script = f'''SUDO=""; if [ "$(id -u)" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi; fi
BACKEND=$({_remote_detect_backend()})
RULES_OK=0

case "$BACKEND" in
  "IPTABLES")
    # Check if ipset exists and has our sets
    if ! command -v ipset >/dev/null 2>&1; then
      echo "VERIFY_FAIL: ipset not installed"
      exit 1
    fi
    
    if ! $SUDO ipset list {SET_V4} >/dev/null 2>&1; then
      echo "VERIFY_FAIL: ipset {SET_V4} not created"
      exit 1
    fi
    
    IPT=$(command -v iptables-nft || command -v iptables || command -v iptables-legacy || true)
    if [ -z "$IPT" ]; then
      echo "VERIFY_FAIL: no iptables found"
      exit 1
    fi
    
    # Check if rules exist in DOCKER-USER or INPUT/FORWARD
    if $IPT -S DOCKER-USER 2>/dev/null | grep -q "{SET_V4}"; then
      RULES_OK=1
      echo "VERIFY_OK: rules in DOCKER-USER"
    elif $IPT -S INPUT 2>/dev/null | grep -q "{SET_V4}"; then
      RULES_OK=1
      echo "VERIFY_OK: rules in INPUT"
    elif $IPT -S FORWARD 2>/dev/null | grep -q "{SET_V4}"; then
      RULES_OK=1
      echo "VERIFY_OK: rules in FORWARD"
    fi
    
    if [ "$RULES_OK" -eq 0 ]; then
      echo "VERIFY_FAIL: no iptables rules found for {SET_V4}"
      # Try to add rules now
      if $IPT -S DOCKER-USER >/dev/null 2>&1; then
        echo "VERIFY_FIX: adding rules to DOCKER-USER"
        $SUDO $IPT -I DOCKER-USER 1 -p tcp -m set --match-set {SET_V4} src -j REJECT --reject-with tcp-reset 2>/dev/null || true
        $SUDO $IPT -I DOCKER-USER 2 -p udp -m set --match-set {SET_V4} src -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || true
        $SUDO $IPT -I DOCKER-USER 3 -m set --match-set {SET_V4} src -j DROP 2>/dev/null || true
      else
        echo "VERIFY_FIX: adding rules to INPUT/FORWARD"
        $SUDO $IPT -I INPUT 1 -m set --match-set {SET_V4} src -j DROP 2>/dev/null || true
        $SUDO $IPT -I FORWARD 1 -m set --match-set {SET_V4} src -j DROP 2>/dev/null || true
      fi
      # Verify again
      if $IPT -S DOCKER-USER 2>/dev/null | grep -q "{SET_V4}" || $IPT -S INPUT 2>/dev/null | grep -q "{SET_V4}"; then
        echo "VERIFY_FIXED: rules added successfully"
      else
        echo "VERIFY_FAIL: could not add rules"
        exit 1
      fi
    fi
  ;;
  "NFT")
    if ! $SUDO nft list set inet filter {SET_V4} >/dev/null 2>&1; then
      echo "VERIFY_FAIL: nft set {SET_V4} not created"
      exit 1
    fi
    if $SUDO nft list ruleset 2>/dev/null | grep -q "@{SET_V4}"; then
      echo "VERIFY_OK: nft rules exist"
    else
      echo "VERIFY_FAIL: no nft rules for {SET_V4}"
      exit 1
    fi
  ;;
  *)
    echo "VERIFY_FAIL: no firewall backend"
    exit 1
  ;;
esac
echo "VERIFY_COMPLETE"
'''
    
    verify_cmd = _ssh_base(spec) + [verify_script]
    vp = await asyncio.create_subprocess_exec(*verify_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    vout, _ = await vp.communicate()
    vtext = (vout or b'').decode(errors='ignore')
    
    if b'VERIFY_OK' in vout or b'VERIFY_FIXED' in vout or b'VERIFY_COMPLETE' in vout:
        log.info("ensure_rule verified node=%s status=ok output=%s", spec.name, vtext.strip()[:200])
        _RULE_ENSURED.add(key)
    else:
        log.error("ensure_rule FAILED node=%s output=%s", spec.name, vtext.strip()[:400])
        # Don't add to _RULE_ENSURED so it will retry next time

async def check_firewall_status(spec: NodeSpec) -> dict:
    """
    Check firewall status on a node and return diagnostic info.
    Returns dict with keys: ok, backend, sets_exist, rules_exist, details
    """
    check_script = f'''SUDO=""; if [ "$(id -u)" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi; fi
BACKEND=$({_remote_detect_backend()})
echo "BACKEND=$BACKEND"

case "$BACKEND" in
  "IPTABLES")
    if command -v ipset >/dev/null 2>&1; then
      echo "IPSET_INSTALLED=yes"
      if $SUDO ipset list {SET_V4} >/dev/null 2>&1; then
        COUNT4=$($SUDO ipset list {SET_V4} 2>/dev/null | grep -c "^[0-9]" || echo 0)
        echo "SET_V4_EXISTS=yes count=$COUNT4"
      else
        echo "SET_V4_EXISTS=no"
      fi
      if $SUDO ipset list {SET_V6} >/dev/null 2>&1; then
        COUNT6=$($SUDO ipset list {SET_V6} 2>/dev/null | grep -c "^[0-9]" || echo 0)
        echo "SET_V6_EXISTS=yes count=$COUNT6"
      else
        echo "SET_V6_EXISTS=no"
      fi
    else
      echo "IPSET_INSTALLED=no"
    fi
    
    IPT=$(command -v iptables-nft || command -v iptables || command -v iptables-legacy || true)
    if [ -n "$IPT" ]; then
      echo "IPTABLES_CMD=$IPT"
      # Check all chains separately
      HAS_DOCKER=0
      if $SUDO $IPT -S DOCKER-USER >/dev/null 2>&1; then
        HAS_DOCKER=1
        echo "HAS_DOCKER_USER=yes"
        if $SUDO $IPT -S DOCKER-USER 2>/dev/null | grep -q "{SET_V4}"; then
          echo "RULES_DOCKER_USER=yes"
        else
          echo "RULES_DOCKER_USER=no"
        fi
      else
        echo "HAS_DOCKER_USER=no"
      fi
      
      if $SUDO $IPT -S INPUT 2>/dev/null | grep -q "{SET_V4}"; then
        echo "RULES_INPUT=yes"
      else
        echo "RULES_INPUT=no"
      fi
      
      if $SUDO $IPT -S FORWARD 2>/dev/null | grep -q "{SET_V4}"; then
        echo "RULES_FORWARD=yes"
      else
        echo "RULES_FORWARD=no"
      fi
    else
      echo "IPTABLES_CMD=none"
    fi
  ;;
  "NFT")
    echo "NFT_INSTALLED=yes"
    if $SUDO nft list set inet filter {SET_V4} >/dev/null 2>&1; then
      COUNT4=$($SUDO nft list set inet filter {SET_V4} 2>/dev/null | grep -c "timeout" || echo 0)
      echo "SET_V4_EXISTS=yes count=$COUNT4"
    else
      echo "SET_V4_EXISTS=no"
    fi
    if $SUDO nft list set inet filter {SET_V6} >/dev/null 2>&1; then
      echo "SET_V6_EXISTS=yes"
    else
      echo "SET_V6_EXISTS=no"
    fi
    if $SUDO nft list ruleset 2>/dev/null | grep -q "@{SET_V4}"; then
      echo "RULES_EXIST=yes"
    else
      echo "RULES_EXIST=no"
    fi
  ;;
  *)
    echo "NO_BACKEND=true"
  ;;
esac
'''
    cmd = _ssh_base(spec) + [check_script]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await proc.communicate()
        text = (out or b'').decode(errors='ignore')

        result = {
            "ok": False,
            "backend": "unknown",
            "sets_exist": False,
            "rules_exist": False,
            "rules_input": False,
            "rules_forward": False,
            "rules_docker": False,
            "has_docker": False,
            "details": text.strip(),
            "cached_ensured": f"{spec.host}:{spec.ssh_port}" in _RULE_ENSURED
        }

        if "BACKEND=IPTABLES" in text:
            result["backend"] = "iptables"
            result["sets_exist"] = "SET_V4_EXISTS=yes" in text
            result["has_docker"] = "HAS_DOCKER_USER=yes" in text
            result["rules_input"] = "RULES_INPUT=yes" in text
            result["rules_forward"] = "RULES_FORWARD=yes" in text
            result["rules_docker"] = "RULES_DOCKER_USER=yes" in text

            # Rules are OK if INPUT is set AND (DOCKER-USER or FORWARD depending on Docker presence)
            if result["rules_input"]:
                if result["has_docker"]:
                    result["rules_exist"] = result["rules_docker"]
                else:
                    result["rules_exist"] = result["rules_forward"]
            else:
                result["rules_exist"] = False
        elif "BACKEND=NFT" in text:
            result["backend"] = "nftables"
            result["sets_exist"] = "SET_V4_EXISTS=yes" in text
            result["rules_exist"] = "RULES_EXIST=yes" in text

        result["ok"] = result["sets_exist"] and result["rules_exist"]
        return result
    except Exception as e:
        return {
            "ok": False,
            "backend": "error",
            "sets_exist": False,
            "rules_exist": False,
            "details": str(e),
            "cached_ensured": f"{spec.host}:{spec.ssh_port}" in _RULE_ENSURED
        }

async def check_all_nodes_firewall(nodes: list[NodeSpec]) -> dict[str, dict]:
    """
    Check firewall status on all nodes concurrently.
    Returns dict: node_name -> status_dict
    """
    tasks = {node.name: check_firewall_status(node) for node in nodes}
    results = {}
    for name, task in tasks.items():
        try:
            results[name] = await task
        except Exception as e:
            results[name] = {"ok": False, "error": str(e)}
    return results

async def force_ensure_all_nodes(nodes: list[NodeSpec]) -> dict[str, bool]:
    """
    Force re-run ensure_rule on all nodes and return status dict.
    Useful for manual verification/fix from manager.
    """
    results = {}
    for node in nodes:
        key = f"{node.host}:{node.ssh_port}"
        # Clear cache to force re-run
        _RULE_ENSURED.discard(key)
        try:
            await ensure_rule(node, force=True)
            results[node.name] = key in _RULE_ENSURED
        except Exception as e:
            log.error("force_ensure_all_nodes error node=%s err=%s", node.name, e)
            results[node.name] = False
    return results

async def ban_ip(spec: NodeSpec, ip: str, seconds: int) -> bool:
    """Add IP (v4/v6) with TTL to the appropriate set and flush conntrack. Returns True if membership confirmed."""
    # validate IP strictly to avoid malformed input or shell injection
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    is_v6 = _is_ipv6(ip)
    conntrack_block = _cmd_flush_all(ip)

    add_cmd = f'''SUDO=""; if [ "$(id -u)" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi; fi
BACKEND=$({_remote_detect_backend()})

case "$BACKEND" in
  "IPTABLES")
    ( command -v ipset >/dev/null 2>&1 ) || exit 1
    # ensure set exists (timed)
    if [ {1 if is_v6 else 0} -eq 1 ]; then
      $SUDO ipset list {SET_V6} >/dev/null 2>&1 || $SUDO ipset create {SET_V6} hash:ip family inet6 timeout 0 2>/dev/null
      $SUDO ipset add {SET_V6} {_q(ip)} timeout {int(seconds)} -exist
    else
      $SUDO ipset list {SET_V4} >/dev/null 2>&1 || $SUDO ipset create {SET_V4} hash:ip timeout 0 2>/dev/null
      $SUDO ipset add {SET_V4} {_q(ip)} timeout {int(seconds)} -exist
    fi
  ;;
  "NFT")
    # ensure table/sets exist
    $SUDO nft list table inet filter >/dev/null 2>&1 || $SUDO nft add table inet filter
    if [ {1 if is_v6 else 0} -eq 1 ]; then
      $SUDO nft list set inet filter {SET_V6} >/dev/null 2>&1 || $SUDO nft add set inet filter {SET_V6} '{{ type ipv6_addr; timeout 0s; flags timeout; }}'
      $SUDO nft add element inet filter {SET_V6} "{{ {ip} timeout {int(seconds)}s }}"
    else
      $SUDO nft list set inet filter {SET_V4} >/dev/null 2>&1 || $SUDO nft add set inet filter {SET_V4} '{{ type ipv4_addr; timeout 0s; flags timeout; }}'
      $SUDO nft add element inet filter {SET_V4} "{{ {ip} timeout {int(seconds)}s }}"
    fi
  ;;
  *)
    exit 1
  ;;
esac

{conntrack_block}
# membership test
case "$BACKEND" in
  "IPTABLES")
    if [ {1 if is_v6 else 0} -eq 1 ]; then
      ipset test {SET_V6} {_q(ip)} >/dev/null 2>&1 || echo '__TEST_FAIL__'
    else
      ipset test {SET_V4} {_q(ip)} >/dev/null 2>&1 || echo '__TEST_FAIL__'
    fi
  ;;
  "NFT")
    if [ {1 if is_v6 else 0} -eq 1 ]; then
      $SUDO nft get element inet filter {SET_V6} "{{ {ip} }}" >/dev/null 2>&1 || echo '__TEST_FAIL__'
    else
      $SUDO nft get element inet filter {SET_V4} "{{ {ip} }}" >/dev/null 2>&1 || echo '__TEST_FAIL__'
    fi
  ;;
  *)
    echo '__TEST_FAIL__'
  ;;
esac
true'''

    cmd = _ssh_base(spec) + [add_cmd]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT
    )
    out_bytes, _ = await proc.communicate()
    ok = b'__TEST_FAIL__' not in out_bytes
    return ok

async def is_banned(spec: NodeSpec, ip: str) -> bool:
    # validate IP to avoid running commands on invalid input
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    set_name = SET_V6 if _is_ipv6(ip) else SET_V4
    test_cmd = f'''SUDO=""; if [ "$(id -u)" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi; fi
BACKEND=$({_remote_detect_backend()})
case "$BACKEND" in
  "IPTABLES")
    ipset test {set_name} {_q(ip)} >/dev/null 2>&1
  ;;
  "NFT")
    $SUDO nft get element inet filter {set_name} "{{ {ip} }}" >/dev/null 2>&1
  ;;
  *)
    exit 1
  ;;
esac'''
    cmd = _ssh_base(spec) + [test_cmd]
    p = await asyncio.create_subprocess_exec(*cmd)
    rc = await p.wait()
    return rc == 0

async def unban_ip(spec: NodeSpec, ip: str) -> bool:
    """Remove IP from set (if present) and flush conntrack."""
    # validate IP to avoid malformed input
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    set_name = SET_V6 if _is_ipv6(ip) else SET_V4
    del_cmd = f'''SUDO=""; if [ "$(id -u)" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi; fi
BACKEND=$({_remote_detect_backend()})
case "$BACKEND" in
  "IPTABLES")
    (command -v ipset >/dev/null 2>&1) || exit 0
    $SUDO ipset del {set_name} {_q(ip)} 2>/dev/null || true
  ;;
  "NFT")
    # try to delete element if set exists
    $SUDO nft list set inet filter {set_name} >/dev/null 2>&1 && $SUDO nft delete element inet filter {set_name} "{{ {ip} }}" 2>/dev/null || true
  ;;
  *) ;;
  esac
{_cmd_flush_all(ip)}
true'''
    cmd = _ssh_base(spec) + [del_cmd]
    try:
        p = await asyncio.create_subprocess_exec(*cmd)
        await p.wait()
        return True
    except Exception:
        return False

# ---------------- Batching worker for bans ----------------
class _BanItem:
    __slots__ = ("ip","ttl","enq")
    def __init__(self, ip: str, ttl: int):
        self.ip = ip
        self.ttl = int(max(1, ttl))
        self.enq = asyncio.get_event_loop().time()

class _WorkerState:
    __slots__=("pending","event","task","latencies","last_report","lock")
    def __init__(self):
        self.pending: dict[str, _BanItem] = {}
        self.event = asyncio.Event()
        self.task: asyncio.Task | None = None
        self.latencies: list[float] = []  # rolling window
        self.last_report = 0.0
        self.lock = asyncio.Lock()

_workers: dict[str, _WorkerState] = {}

def _node_key(spec: NodeSpec) -> str:
    return f"{spec.host}:{spec.ssh_port}"

async def _ensure_worker(spec: NodeSpec) -> _WorkerState:
    key = _node_key(spec)
    st = _workers.get(key)
    if st is None:
        st = _WorkerState()
        _workers[key] = st
        st.task = asyncio.create_task(_worker_loop(spec, st))
    return st

async def schedule_ban(spec: NodeSpec, ip: str, seconds: int) -> bool:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False

    # Check if firewall rules are ensured for this node
    key = f"{spec.host}:{spec.ssh_port}"
    if key not in _RULE_ENSURED:
        # Try to ensure rules automatically before banning
        log.warning("firewall rules not ensured for node=%s, attempting auto-ensure before ban ip=%s", spec.name, ip)
        try:
            await ensure_rule(spec, force=False)
        except Exception as e:
            log.error("auto-ensure failed node=%s err=%s, ban may fail", spec.name, e)
        # even if ensure_rule fails, proceed with ban attempt in case rules exist but weren't cached

    st = await _ensure_worker(spec)
    async with st.lock:
        # backpressure: cap pending size; only refresh TTL for existing items when full
        cur = st.pending.get(ip)
        if cur is not None:
            if seconds > cur.ttl:
                cur.ttl = seconds
        else:
            if len(st.pending) >= MAX_PENDING:
                # overflow: drop this new IP to avoid unbounded growth
                if st.last_report == 0.0 or (asyncio.get_event_loop().time() - st.last_report) > 5.0:
                    st.last_report = asyncio.get_event_loop().time()
                    log.warning("[guardian.batch] node=%s pending_overflow size=%d cap=%d dropping_new=true", spec.name, len(st.pending), MAX_PENDING)
                return False
            st.pending[ip] = _BanItem(ip, seconds)
        st.event.set()
    return True

async def _worker_loop(spec: NodeSpec, st: _WorkerState):
    BATCH_MS = 0.25  # 250 ms
    MAX_BATCH = 500
    while True:
        try:
            # wait for event or timeout window
            try:
                await asyncio.wait_for(st.event.wait(), timeout=BATCH_MS)
            except asyncio.TimeoutError:
                pass
            st.event.clear()
            # drain a batch
            async with st.lock:
                if not st.pending:
                    continue
                items = []
                for _ in range(min(MAX_BATCH, len(st.pending))):
                    ip, itm = st.pending.popitem()
                    items.append(itm)
            # apply batch
            await _apply_batch(spec, items, st)
        except Exception as e:
            # log minimal; avoid crash loop
            log.error("[guardian.batch] worker error node=%s err=%s", spec.name, e)
            await asyncio.sleep(0.5)

async def _apply_batch(spec: NodeSpec, items: list[_BanItem], st: _WorkerState):
    if not items:
        return
    # split by ip family
    v4 = [it for it in items if ipaddress.ip_address(it.ip).version == 4]
    v6 = [it for it in items if ipaddress.ip_address(it.ip).version == 6]

    # For iptables backend: ipset restore payload only includes adds; create sets separately
    def _ipset_restore_payload():
        lines: list[str] = []
        if v4:
            for it in v4:
                lines.append(f"add {SET_V4} {it.ip} timeout {it.ttl} -exist")
        if v6:
            for it in v6:
                lines.append(f"add {SET_V6} {it.ip} timeout {it.ttl} -exist")
        return "\n".join(lines)

    def _nft_batch_script():
        parts = []
        parts.append("$SUDO nft list table inet filter >/dev/null 2>&1 || $SUDO nft add table inet filter")
        parts.append(f"$SUDO nft list set inet filter {SET_V4} >/dev/null 2>&1 || $SUDO nft add set inet filter {SET_V4} '{{ type ipv4_addr; timeout 0s; flags timeout; }}'")
        parts.append(f"$SUDO nft list set inet filter {SET_V6} >/dev/null 2>&1 || $SUDO nft add set inet filter {SET_V6} '{{ type ipv6_addr; timeout 0s; flags timeout; }}'")
        if v4:
            del_lines = "; ".join([f"$SUDO nft delete element inet filter {SET_V4} \"{{ {it.ip} }}\" 2>/dev/null || true" for it in v4])
            if del_lines:
                parts.append(del_lines)
            elems = ", ".join([f"{it.ip} timeout {it.ttl}s" for it in v4])
            parts.append(f"$SUDO nft add element inet filter {SET_V4} \"{{ {elems} }}\"")
        if v6:
            del_lines6 = "; ".join([f"$SUDO nft delete element inet filter {SET_V6} \"{{ {it.ip} }}\" 2>/dev/null || true" for it in v6])
            if del_lines6:
                parts.append(del_lines6)
            elems6 = ", ".join([f"{it.ip} timeout {it.ttl}s" for it in v6])
            parts.append(f"$SUDO nft add element inet filter {SET_V6} \"{{ {elems6} }}\"")
        return "\n".join(parts)

    ips = [it.ip for it in items]
    conntrack_cmds = []
    for ip in ips:
        q = shlex.quote(ip)
        conntrack_cmds.append(f"conntrack -D -s {q} >/dev/null 2>&1 || true; conntrack -D -d {q} >/dev/null 2>&1 || true")
    conntrack_block = ("if command -v conntrack >/dev/null 2>&1; then " + " ".join(conntrack_cmds) + "; fi") if conntrack_cmds else "true"

    remote = f'''SUDO=""; if [ "$(id -u)" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi; fi
BACKEND=$({_remote_detect_backend()})
true
case "$BACKEND" in
  "IPTABLES")
    if ! command -v ipset >/dev/null 2>&1; then exit 1; fi
    # ensure sets exist (silent if already there)
    $SUDO ipset list {SET_V4} >/dev/null 2>&1 || $SUDO ipset create {SET_V4} hash:ip timeout 0 hashsize 16384 maxelem 1048576 2>/dev/null
    $SUDO ipset list {SET_V6} >/dev/null 2>&1 || $SUDO ipset create {SET_V6} hash:ip family inet6 timeout 0 hashsize 16384 maxelem 1048576 2>/dev/null
    PAYLOAD=$(cat <<'__EOF__'
{_ipset_restore_payload()}
__EOF__
)
    if [ -n "$PAYLOAD" ]; then echo "$PAYLOAD" | $SUDO ipset restore -exist; fi
  ;;
  "NFT")
    { _nft_batch_script() }
  ;;
  *) exit 1;;
esac
{conntrack_block}
true'''

    cmd = _ssh_base(spec) + [remote]
    t0 = asyncio.get_event_loop().time()
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    out,_ = await proc.communicate()
    latency = asyncio.get_event_loop().time() - t0
    # record latency for each item
    batch_now = asyncio.get_event_loop().time()
    for it in items:
        st.latencies.append(batch_now - it.enq)
    # trim latencies to last 1000
    if len(st.latencies) > 1000:
        st.latencies = st.latencies[-1000:]
    if (st.last_report == 0.0) or (batch_now - st.last_report > 30.0):
        st.last_report = batch_now
        # compute approx p95
        xs = sorted(st.latencies)
        p95 = xs[int(0.95*len(xs))-1] if xs else 0.0
        log.info("[guardian.batch] node=%s size=%d pending=%d p95=%.3fs last_latency=%.3fs", spec.name, len(items), len(st.pending), p95, latency)
    if proc.returncode != 0:
        text = (out or b'').decode(errors='ignore')
        log.warning("[guardian.batch] node=%s rc=%s out=%s", spec.name, proc.returncode, text.strip()[:400])
        # Check if rule is properly ensured
        key = f"{spec.host}:{spec.ssh_port}"
        if key not in _RULE_ENSURED:
            log.error("firewall rules NOT ensured for node=%s - run ensure_rule manually or via Telegram bot", spec.name)
        # simple retry once: reinsert items
        async with st.lock:
            for it in items:
                # keep max ttl if already pending
                cur = st.pending.get(it.ip)
                if cur is None or it.ttl > cur.ttl:
                    st.pending[it.ip] = it
            st.event.set()
        await asyncio.sleep(0.5)

# ---------------- Existing single-shot functions ----------------
