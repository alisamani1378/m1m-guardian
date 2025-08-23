import asyncio, shlex
from .nodes import NodeSpec, _ssh_base

SET_NAME="m1m_guardian"
_ENSURED_CACHE = set()

def _cmd_flush_all(ip:str):
    qip=shlex.quote(ip)
    return f'''if command -v conntrack >/dev/null 2>&1; then
conntrack -D -s {qip} >/dev/null 2>&1 || true
fi'''

async def ensure_rule(spec:NodeSpec):
    # جلوگیری از اجرای تکراری روی یک نود
    if getattr(spec, "_fw_ensured", False):
        return
    inner = f'''set -e
SUDO=""; if [ "$(id -u)" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi; fi
(command -v ipset >/dev/null 2>&1) || ( $SUDO apt-get update -y >/dev/null 2>&1 && $SUDO apt-get install -y ipset >/dev/null 2>&1 ) || ( $SUDO apk add --no-cache ipset >/dev/null 2>&1 ) || ( $SUDO yum install -y ipset >/dev/null 2>&1 ) || true
IPT=$(command -v iptables-legacy || command -v iptables || true)
[ -z "$IPT" ] && exit 0
$SUDO ipset create {SET_NAME} hash:ip timeout 0 -exist
$IPT -C INPUT -m set --match-set {SET_NAME} src -j DROP 2>/dev/null || $SUDO $IPT -I INPUT 1 -m set --match-set {SET_NAME} src -j DROP
true
'''.strip()
    cmd = _ssh_base(spec) + [inner]
    p = await asyncio.create_subprocess_exec(*cmd)
    await p.wait()
    if p.returncode == 0:
        setattr(spec, "_fw_ensured", True)

async def ban_ip(spec:NodeSpec, ip:str, seconds:int):
    conntrack_block = _cmd_flush_all(ip)
    inner = f'''set -e
SUDO=""; if [ "$(id -u)" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi; fi
(command -v ipset >/dev/null 2>&1) || true
IPT=$(command -v iptables-legacy || command -v iptables || true)
[ -z "$IPT" ] && exit 0
# Try add; if set missing recreate then retry once
$SUDO ipset add {SET_NAME} {shlex.quote(ip)} timeout {int(seconds)} -exist 2>/dev/null || {{ $SUDO ipset create {SET_NAME} hash:ip timeout 0 -exist 2>/dev/null || true; $SUDO ipset add {SET_NAME} {shlex.quote(ip)} timeout {int(seconds)} -exist || true; }}
{conntrack_block}
true'''
    cmd = _ssh_base(spec) + [inner]
    p = await asyncio.create_subprocess_exec(*cmd)
    await p.wait()
