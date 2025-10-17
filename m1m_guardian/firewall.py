import asyncio, shlex, ipaddress
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

    # create timed sets with large capacity (timeout 0 => elements themselves have TTL)
    $SUDO ipset create {SET_V4} hash:ip timeout 0 hashsize 16384 maxelem 1048576 -exist
    $SUDO ipset create {SET_V6} hash:ip family inet6 timeout 0 hashsize 16384 maxelem 1048576 -exist

    # IPv4 rules (prefer DOCKER-USER if exists)
    if [ -n "$IPT" ]; then
      if $IPT -S DOCKER-USER >/dev/null 2>&1; then
        $IPT -C DOCKER-USER -m set --match-set {SET_V4} src -j DROP 2>/dev/null || $SUDO $IPT -I DOCKER-USER 1 -m set --match-set {SET_V4} src -j DROP
      else
        $IPT -C INPUT   -m set --match-set {SET_V4} src -j DROP 2>/dev/null || $SUDO $IPT -I INPUT   1 -m set --match-set {SET_V4} src -j DROP
        $IPT -C FORWARD -m set --match-set {SET_V4} src -j DROP 2>/dev/null || $SUDO $IPT -I FORWARD 1 -m set --match-set {SET_V4} src -j DROP
      fi
    fi

    # IPv6 rules using ip6tables (prefer DOCKER-USER if exists)
    if [ -n "$IPT6" ]; then
      if $IPT6 -S DOCKER-USER >/dev/null 2>&1; then
        $IPT6 -C DOCKER-USER -m set --match-set {SET_V6} src -j DROP 2>/dev/null || $SUDO $IPT6 -I DOCKER-USER 1 -m set --match-set {SET_V6} src -j DROP
      else
        $IPT6 -C INPUT   -m set --match-set {SET_V6} src -j DROP 2>/dev/null || $SUDO $IPT6 -I INPUT   1 -m set --match-set {SET_V6} src -j DROP
        $IPT6 -C FORWARD -m set --match-set {SET_V6} src -j DROP 2>/dev/null || $SUDO $IPT6 -I FORWARD 1 -m set --match-set {SET_V6} src -j DROP
      fi
    fi
  ;;
  "NFT")
    # ensure table/chain/sets (timed)
    $SUDO nft list table inet filter >/dev/null 2>&1 || $SUDO nft add table inet filter
    # DOCKER-USER اگر وجود ندارد، به‌صورت hook input می‌سازیم (safe priority 0)
    if ! $SUDO nft list chain inet filter DOCKER-USER >/dev/null 2>&1; then
      if ! $SUDO nft list chain inet filter INPUT >/dev/null 2>&1; then
        $SUDO nft add chain inet filter INPUT '{{ type filter hook input priority 0 ; }}'
      fi
      # داشتن DOCKER-USER مزیت دارد؛ اگر نبود، از INPUT استفاده می‌کنیم
      $SUDO nft add chain inet filter DOCKER-USER '{{ type filter hook input priority 0 ; }}' 2>/dev/null || true
    fi
    # sets با قابلیت timeout و ظرفیت بالا
    $SUDO nft list set inet filter {SET_V4}   >/dev/null 2>&1 || $SUDO nft add set inet filter {SET_V4}   '{{ type ipv4_addr; timeout 0s; flags timeout; size 1048576; }}'
    $SUDO nft list set inet filter {SET_V6}   >/dev/null 2>&1 || $SUDO nft add set inet filter {SET_V6}   '{{ type ipv6_addr; timeout 0s; flags timeout; size 1048576; }}'

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
    await ensure_rule(spec)
    st = await _ensure_worker(spec)
    async with st.lock:
        # de-duplicate and keep max TTL (extend if needed)
        cur = st.pending.get(ip)
        if cur is None or seconds > cur.ttl:
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
            # use print to avoid import logging here
            print(f"[guardian.batch] worker error node={spec.name} err={e}")
            await asyncio.sleep(0.5)

async def _apply_batch(spec: NodeSpec, items: list[_BanItem], st: _WorkerState):
    if not items:
        return
    # split by ip family
    v4 = [it for it in items if ipaddress.ip_address(it.ip).version == 4]
    v6 = [it for it in items if ipaddress.ip_address(it.ip).version == 6]

    # build remote script once (backend auto-detect inside)
    # For iptables backend: use ipset restore -exist to add elements in batch
    # For nft backend: use nft -f with batched add/delete to update TTLs
    def _ipset_restore_payload():
        lines = []
        # big capacity to avoid maxelem/hashsize issues
        lines.append(f"create {SET_V4} hash:ip timeout 0 hashsize 16384 maxelem 1048576 -exist")
        if v4:
            for it in v4:
                lines.append(f"add {SET_V4} {it.ip} timeout {it.ttl} -exist")
        lines.append(f"create {SET_V6} hash:ip family inet6 timeout 0 hashsize 16384 maxelem 1048576 -exist")
        if v6:
            for it in v6:
                lines.append(f"add {SET_V6} {it.ip} timeout {it.ttl} -exist")
        return "\n".join(lines)

    def _nft_batch_script():
        parts = []
        # ensure table/sets
        parts.append("$SUDO nft list table inet filter >/dev/null 2>&1 || $SUDO nft add table inet filter")
        parts.append(f"$SUDO nft list set inet filter {SET_V4} >/dev/null 2>&1 || $SUDO nft add set inet filter {SET_V4} '{{ type ipv4_addr; timeout 0s; flags timeout; }}'")
        parts.append(f"$SUDO nft list set inet filter {SET_V6} >/dev/null 2>&1 || $SUDO nft add set inet filter {SET_V6} '{{ type ipv6_addr; timeout 0s; flags timeout; }}'")
        if v4:
            # delete to ensure TTL refresh, ignore errors
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
# ensure DOCKER-USER/INPUT rules exist (once)
true  # assumed ensured by ensure_rule earlier
case "$BACKEND" in
  "IPTABLES")
    if ! command -v ipset >/dev/null 2>&1; then exit 1; fi
    PAYLOAD=$(cat <<'__EOF__'
{_ipset_restore_payload()}
__EOF__
)
    echo "$PAYLOAD" | $SUDO ipset restore -exist
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
        print(f"[guardian.batch] node={spec.name} size={len(items)} pending={len(st.pending)} p95={p95:.3f}s last_latency={latency:.3f}s")
    if proc.returncode != 0:
        text = (out or b'').decode(errors='ignore')
        print(f"[guardian.batch] node={spec.name} rc={proc.returncode} out={text.strip()[:400]}")
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
