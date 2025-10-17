import asyncio, shlex, time, ipaddress
from .nodes import NodeSpec, _ssh_base

SET_V4 = "m1m_guardian"
SET_V6 = "m1m_guardian6"
_RULE_ENSURED: set[str] = set()

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

async def ensure_rule(spec: NodeSpec, force: bool = False):
    """
    Idempotently ensure drop-rules and timed sets exist.
    Supports both iptables(+ipset) and nftables-native.
    """
    key = f"{spec.host}:{spec.ssh_port}"
    if not force and key in _RULE_ENSURED:
        return

    inner = f'''SUDO=""; if [ "$(id -u)" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi; fi

# --- detect backend ---
{_remote_detect_backend()}

# shell var BACKEND now contains IPTABLES or NFT
BACKEND=$({_remote_detect_backend()})

case "$BACKEND" in
  "IPTABLES")
    # ensure ipset available
    ( command -v ipset >/dev/null 2>&1 ) || \
      ( $SUDO apt-get update -y >/dev/null 2>&1 && $SUDO apt-get install -y ipset >/dev/null 2>&1 ) || \
      ( $SUDO apk add --no-cache ipset >/dev/null 2>&1 ) || \
      ( $SUDO yum install -y ipset >/dev/null 2>&1 ) || true

    IPT=$(command -v iptables-nft || command -v iptables || command -v iptables-legacy || true)
    [ -z "$IPT" ] && exit 0

    # create timed sets (timeout 0 => عنصرها تایم‌دار می‌شوند)
    $SUDO ipset create {SET_V4} hash:ip timeout 0 -exist
    $SUDO ipset create {SET_V6} hash:ip family inet6 timeout 0 -exist

    # prefer DOCKER-USER if exists; otherwise INPUT/FORWARD
    if $IPT -S DOCKER-USER >/dev/null 2>&1; then
      $IPT -C DOCKER-USER -m set --match-set {SET_V4} src -j DROP 2>/dev/null || $SUDO $IPT -I DOCKER-USER 1 -m set --match-set {SET_V4} src -j DROP
      $IPT -C DOCKER-USER -m set --match-set {SET_V6} src -j DROP 2>/dev/null || $SUDO $IPT -I DOCKER-USER 1 -m set --match-set {SET_V6} src -j DROP
    else
      $IPT -C INPUT   -m set --match-set {SET_V4} src -j DROP 2>/dev/null || $SUDO $IPT -I INPUT   1 -m set --match-set {SET_V4} src -j DROP
      $IPT -C FORWARD -m set --match-set {SET_V4} src -j DROP 2>/dev/null || $SUDO $IPT -I FORWARD 1 -m set --match-set {SET_V4} src -j DROP
      $IPT -C INPUT   -m set --match-set {SET_V6} src -j DROP 2>/dev/null || $SUDO $IPT -I INPUT   1 -m set --match-set {SET_V6} src -j DROP
      $IPT -C FORWARD -m set --match-set {SET_V6} src -j DROP 2>/dev/null || $SUDO $IPT -I FORWARD 1 -m set --match-set {SET_V6} src -j DROP
    fi
  ;;
  "NFT")
    # ensure table/chain/sets (timed)
    $SUDO nft list table inet filter >/dev/null 2>&1 || $SUDO nft add table inet filter
    # DOCKER-USER اگر وجود ندارد، به‌صورت hook input می‌سازیم (safe priority 0)
    if ! $SUDO nft list chain inet filter DOCKER-USER >/dev/null 2>&1; then
      if ! $SUDO nft list chain inet filter INPUT >/dev/null 2>&1; then
        $SUDO nft add chain inet filter INPUT { type filter hook input priority 0 \\; }
      fi
      # داشتن DOCKER-USER مزیت دارد؛ اگر نبود، از INPUT استفاده می‌کنیم
      $SUDO nft add chain inet filter DOCKER-USER { type filter hook input priority 0 \\; } 2>/dev/null || true
    fi
    # sets با قابلیت timeout
    $SUDO nft list set inet filter {SET_V4}   >/dev/null 2>&1 || $SUDO nft add set inet filter {SET_V4}   {{ type ipv4_addr; timeout 0s; flags timeout; }}
    $SUDO nft list set inet filter {SET_V6}   >/dev/null 2>&1 || $SUDO nft add set inet filter {SET_V6}   {{ type ipv6_addr; timeout 0s; flags timeout; }}

    # ruleها را اگر وجود ندارد اضافه کن (اول DOCKER-USER، بعد INPUT)
    if $SUDO nft list chain inet filter DOCKER-USER >/dev/null 2>&1; then
      $SUDO nft list ruleset | grep -q 'chain DOCKER-USER' && $SUDO nft list ruleset | grep -q '@{SET_V4}.*drop' || $SUDO nft add rule inet filter DOCKER-USER ip saddr @{SET_V4} drop
      $SUDO nft list ruleset | grep -q 'chain DOCKER-USER' && $SUDO nft list ruleset | grep -q '@{SET_V6}.*drop' || $SUDO nft add rule inet filter DOCKER-USER ip6 saddr @{SET_V6} drop
    else
      $SUDO nft list ruleset | grep -q 'chain INPUT' && $SUDO nft list ruleset | grep -q '@{SET_V4}.*drop' || $SUDO nft add rule inet filter INPUT ip saddr @{SET_V4} drop
      $SUDO nft list ruleset | grep -q 'chain INPUT' && $SUDO nft list ruleset | grep -q '@{SET_V6}.*drop' || $SUDO nft add rule inet filter INPUT ip6 saddr @{SET_V6} drop
    fi
  ;;
  *)
    # هیچ بک‌اندی در دسترس نیست
    exit 0
  ;;
esac
true'''.strip()

    cmd = _ssh_base(spec) + [inner]
    p = await asyncio.create_subprocess_exec(*cmd)
    await p.wait()
    _RULE_ENSURED.add(key)

async def ban_ip(spec: NodeSpec, ip: str, seconds: int) -> bool:
    """Add IP (v4/v6) with TTL to the appropriate set and flush conntrack. Returns True if membership confirmed."""
    is_v6 = _is_ipv6(ip)
    set_name = SET_V6 if is_v6 else SET_V4
    conntrack_block = _cmd_flush_all(ip)

    add_cmd = f'''SUDO=""; if [ "$(id -u)" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi; fi
BACKEND=$({_remote_detect_backend()})

case "$BACKEND" in
  "IPTABLES")
    ( command -v ipset >/dev/null 2>&1 ) || exit 1
    # ensure set exists (timed)
    if [ {1 if is_v6 else 0} -eq 1 ]; then
      $SUDO ipset create {SET_V6} hash:ip family inet6 timeout 0 -exist
      $SUDO ipset add {SET_V6} {_q(ip)} timeout {int(seconds)} -exist
    else
      $SUDO ipset create {SET_V4} hash:ip timeout 0 -exist
      $SUDO ipset add {SET_V4} {_q(ip)} timeout {int(seconds)} -exist
    fi
  ;;
  "NFT")
    # ensure table/sets exist
    $SUDO nft list table inet filter >/dev/null 2>&1 || $SUDO nft add table inet filter
    if [ {1 if is_v6 else 0} -eq 1 ]; then
      $SUDO nft list set inet filter {SET_V6} >/dev/null 2>&1 || $SUDO nft add set inet filter {SET_V6} {{ type ipv6_addr; timeout 0s; flags timeout; }}
      $SUDO nft add element inet filter {SET_V6} {{ {_q(ip)} timeout {int(seconds)}s }}
    else
      $SUDO nft list set inet filter {SET_V4} >/dev/null 2>&1 || $SUDO nft add set inet filter {SET_V4} {{ type ipv4_addr; timeout 0s; flags timeout; }}
      $SUDO nft add element inet filter {SET_V4} {{ {_q(ip)} timeout {int(seconds)}s }}
    fi
  ;;
  *)
    exit 1
  ;;
esac

{conntrack_block}
# membership test
if [ {1 if is_v6 else 0} -eq 1 ]; then
  ipset test {SET_V6} {_q(ip)} >/dev/null 2>&1 || echo '__TEST_FAIL__'
else
  ipset test {SET_V4} {_q(ip)} >/dev/null 2>&1 || echo '__TEST_FAIL__'
fi
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
    set_name = SET_V6 if _is_ipv6(ip) else SET_V4
    test_cmd = f"ipset test {set_name} {_q(ip)} >/dev/null 2>&1"
    cmd = _ssh_base(spec) + [test_cmd]
    p = await asyncio.create_subprocess_exec(*cmd)
    rc = await p.wait()
    return rc == 0

async def unban_ip(spec: NodeSpec, ip: str) -> bool:
    """Remove IP from set (if present) and flush conntrack."""
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
    $SUDO nft list set inet filter {set_name} >/dev/null 2>&1 && $SUDO nft delete element inet filter {set_name} {{ {_q(ip)} }} 2>/dev/null || true
  ;;
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
