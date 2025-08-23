import asyncio, shlex
from typing import Optional, List, AsyncIterator, Dict

class NodeSpec:
    def __init__(self, name, host, ssh_user, ssh_port, docker_container, ssh_key=None, ssh_pass=None):
        self.name=name; self.host=host; self.ssh_user=ssh_user; self.ssh_port=ssh_port
        self.docker_container=docker_container; self.ssh_key=ssh_key; self.ssh_pass=ssh_pass

    def __repr__(self): return f"<Node {self.name}@{self.host}:{self.ssh_port}>"

def _ssh_base(spec:NodeSpec)->List[str]:
    common = [
        "ssh","-o","BatchMode=yes","-o","StrictHostKeyChecking=no",
        "-o","ServerAliveInterval=30","-o","ServerAliveCountMax=3",
        "-p", str(spec.ssh_port),
        f"{spec.ssh_user}@{spec.host}",
    ]
    if spec.ssh_key: common = ["ssh","-i",spec.ssh_key] + common[1:]
    if spec.ssh_pass: common = ["sshpass","-p",spec.ssh_pass] + common
    return common

async def run_ssh(spec:NodeSpec, remote_cmd:str) -> int:
    cmd = _ssh_base(spec) + [remote_cmd]
    proc = await asyncio.create_subprocess_exec(*cmd)
    return await proc.wait()

async def stream_logs(spec:NodeSpec) -> AsyncIterator[str]:
    # داخل کانتینر، لاگ استریم stdout/err:
    inner = r'''
apk add --no-cache procps >/dev/null 2>&1 || (apt-get update -y >/dev/null 2>&1 && apt-get install -y procps >/dev/null 2>&1) || true
pid=$(pgrep -xo xray || ps -o pid,comm | awk "/[x]ray/{print $1; exit}")
exec stdbuf -oL cat /proc/$pid/fd/1 /proc/$pid/fd/2 2>/dev/null
'''.strip()

    remote = f"docker exec -i {shlex.quote(spec.docker_container)} sh -lc {shlex.quote(inner)}"
    cmd = _ssh_base(spec) + [remote]
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    try:
        assert proc.stdout is not None
        while True:
            line = await proc.stdout.readline()
            if not line: break
            yield line.decode("utf-8","ignore").rstrip("\n")
    finally:
        with contextlib.suppress(ProcessLookupError, AttributeError):
            proc.kill(); await proc.wait()
