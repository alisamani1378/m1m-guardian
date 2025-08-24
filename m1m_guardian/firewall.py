import asyncio, shlex, time
from .nodes import NodeSpec, _ssh_base

SET_NAME="m1m_guardian"

def _cmd_flush_all(ip:str):
    qip=shlex.quote(ip)
    return f'''if command -v conntrack >/dev/null 2>&1; then
conntrack -D -s {qip} >/dev/null 2>&1 || true
fi'''

async def ensure_rule(spec:NodeSpec, force:bool=False):
    """Idempotently ensure ipset + iptables rules (INPUT/FORWARD/DOCKER-USER)."""
    inner = f'''SUDO=""; if [ "$(id -u)" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi; fi
(command -v ipset >/dev/null 2>&1) || ( $SUDO apt-get update -y >/dev/null 2>&1 && $SUDO apt-get install -y ipset >/dev/null 2>&1 ) || ( $SUDO apk add --no-cache ipset >/dev/null 2>&1 ) || ( $SUDO yum install -y ipset >/dev/null 2>&1 ) || true
IPT=$(command -v iptables-legacy || command -v iptables || true)
[ -z "$IPT" ] && exit 0
$SUDO ipset create {SET_NAME} hash:ip timeout 0 -exist
$IPT -C INPUT   -m set --match-set {SET_NAME} src -j DROP 2>/dev/null || $SUDO $IPT -I INPUT 1   -m set --match-set {SET_NAME} src -j DROP
$IPT -C FORWARD -m set --match-set {SET_NAME} src -j DROP 2>/dev/null || $SUDO $IPT -I FORWARD 1 -m set --match-set {SET_NAME} src -j DROP
if $IPT -S DOCKER-USER >/dev/null 2>&1; then
  $IPT -C DOCKER-USER -m set --match-set {SET_NAME} src -j DROP 2>/dev/null || $SUDO $IPT -I DOCKER-USER 1 -m set --match-set {SET_NAME} src -j DROP
fi
true'''.strip()
    cmd = _ssh_base(spec) + [inner]
    p = await asyncio.create_subprocess_exec(*cmd)
    await p.wait()

async def ban_ip(spec:NodeSpec, ip:str, seconds:int)->bool:
    """Add IP to set & flush conntrack. Returns True if ipset membership confirmed."""
    conntrack_block = _cmd_flush_all(ip)
    add_cmd = f'''SUDO=""; if [ "$(id -u)" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi; fi
IPT=$(command -v iptables-legacy || command -v iptables || true)
[ -z "$IPT" ] && exit 0
( $SUDO ipset add {SET_NAME} {shlex.quote(ip)} timeout {int(seconds)} -exist 2>/dev/null || ( $SUDO ipset create {SET_NAME} hash:ip timeout 0 -exist 2>/dev/null && $SUDO ipset add {SET_NAME} {shlex.quote(ip)} timeout {int(seconds)} -exist 2>/dev/null ) ) || true
{conntrack_block}
$SUDO ipset test {SET_NAME} {shlex.quote(ip)} >/dev/null 2>&1 || echo '__TEST_FAIL__'
true'''
    cmd = _ssh_base(spec) + [add_cmd]
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    out_bytes,_ = await proc.communicate()
    ok = b'__TEST_FAIL__' not in out_bytes
    return ok

async def is_banned(spec:NodeSpec, ip:str)->bool:
    test_cmd = f"ipset test {SET_NAME} {shlex.quote(ip)} >/dev/null 2>&1"
    cmd = _ssh_base(spec)+[test_cmd]
    p = await asyncio.create_subprocess_exec(*cmd)
    rc = await p.wait()
    return rc==0

async def unban_ip(spec:NodeSpec, ip:str)->bool:
    """Remove IP from ipset (if present) and flush its conntrack entries. Returns True if deletion attempted."""
    del_cmd = f'''SUDO=""; if [ "$(id -u)" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi; fi
(command -v ipset >/dev/null 2>&1) || exit 0
$SUDO ipset del {SET_NAME} {shlex.quote(ip)} 2>/dev/null || true
{_cmd_flush_all(ip)}
true'''
    cmd = _ssh_base(spec)+[del_cmd]
    try:
        p=await asyncio.create_subprocess_exec(*cmd)
        await p.wait()
        return True
    except Exception:
        return False
