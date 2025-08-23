import asyncio, shlex
from .nodes import NodeSpec, _ssh_base

SET_NAME="m1m_guardian"

def _cmd_ensure_ports(ports):
    # حذف سشن‌های conntrack برای IP
    parts=[]
    parts.append('if command -v conntrack >/dev/null 2>&1; then')
    parts.append('IP="$1"; shift || true')
    for p in ports:
        parts.append(f'conntrack -D -p tcp --dport {p} --src "$IP" >/dev/null 2>&1 || true')
        parts.append(f'conntrack -D -p udp --dport {p} --src "$IP" >/dev/null 2>&1 || true')
    parts.append('fi')
    return " ; ".join(parts)

async def ensure_rule(spec:NodeSpec):
    # یکبار در هر نود
    inner = f'''
ipset list {SET_NAME} >/dev/null 2>&1 || ipset create {SET_NAME} hash:ip timeout 0
iptables -C INPUT -m set --match-set {SET_NAME} src -j DROP 2>/dev/null || iptables -I INPUT 1 -m set --match-set {SET_NAME} src -j DROP
true
'''.strip()
    cmd = _ssh_base(spec) + [inner]
    p = await asyncio.create_subprocess_exec(*cmd)
    await p.wait()

async def ban_ip(spec:NodeSpec, ip:str, seconds:int, ports:list[int]):
    inner = f'''
ipset add {SET_NAME} {shlex.quote(ip)} timeout {int(seconds)} -exist
{_cmd_ensure_ports(ports)} {shlex.quote(ip)}
true
'''.strip()
    cmd = _ssh_base(spec) + [inner]
    p = await asyncio.create_subprocess_exec(*cmd)
    await p.wait()
