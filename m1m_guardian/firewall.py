import asyncio, shlex
from .nodes import NodeSpec, _ssh_base

SET_NAME="m1m_guardian"

def _cmd_ensure_ports(ports):
    # حذف سشن‌های conntrack برای IP
    parts=[]
    parts.append('if command -v conntrack >/dev/null 2>&1; then')
    parts.append('IP="$1"; shift || true')
    if ports and any(str(p).strip()=='*' for p in ports):
        # Wildcard: حذف همه کانکشن‌ها (همه پروت‌ها/پورت‌ها) برای IP
        parts.append('conntrack -D -s "$IP" >/dev/null 2>&1 || true')
    else:
        for p in ports:
            parts.append(f'conntrack -D -p tcp --dport {p} --src "$IP" >/dev/null 2>&1 || true')
            parts.append(f'conntrack -D -p udp --dport {p} --src "$IP" >/dev/null 2>&1 || true')
    parts.append('fi')
    return " ; ".join(parts)

async def ensure_rule(spec:NodeSpec):
    inner = f'''
SUDO=""; if [ "$(id -u)" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi; fi
# ensure ipset installed
(command -v ipset >/dev/null 2>&1) || ( $SUDO apt-get update -y >/dev/null 2>&1 && $SUDO apt-get install -y ipset >/dev/null 2>&1 ) || ( $SUDO apk add --no-cache ipset >/dev/null 2>&1 ) || ( $SUDO yum install -y ipset >/dev/null 2>&1 ) || true
IPT=$(command -v iptables-legacy || command -v iptables)
[ -n "$IPT" ] || exit 0
ipset list {SET_NAME} >/dev/null 2>&1 || $SUDO ipset create {SET_NAME} hash:ip timeout 0
$IPT -C INPUT -m set --match-set {SET_NAME} src -j DROP 2>/dev/null || $SUDO $IPT -I INPUT 1 -m set --match-set {SET_NAME} src -j DROP
true
'''.strip()
    cmd = _ssh_base(spec) + [inner]
    p = await asyncio.create_subprocess_exec(*cmd)
    await p.wait()

async def ban_ip(spec:NodeSpec, ip:str, seconds:int, ports:list[int]):
    inner = f'''
SUDO=""; if [ "$(id -u)" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi; fi
(command -v ipset >/dev/null 2>&1) || true
IPT=$(command -v iptables-legacy || command -v iptables)
[ -n "$IPT" ] || exit 0
$SUDO ipset add {SET_NAME} {shlex.quote(ip)} timeout {int(seconds)} -exist
{_cmd_ensure_ports(ports)} {shlex.quote(ip)}
true
'''.strip()
    cmd = _ssh_base(spec) + [inner]
    p = await asyncio.create_subprocess_exec(*cmd)
    await p.wait()
