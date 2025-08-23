import asyncio, shlex
import contextlib
from typing import List, AsyncIterator
import logging

log = logging.getLogger("guardian.nodes")

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
    # Wrapper script: verify docker + container before exec
    container = shlex.quote(spec.docker_container)
    inner = r'''set -e
if ! command -v docker >/dev/null 2>&1; then echo "[guardian-stream] no_docker"; exit 41; fi
if ! docker inspect {container} >/dev/null 2>&1; then echo "[guardian-stream] no_container"; exit 42; fi
if ! command -v pgrep >/dev/null 2>&1; then (apk add --no-cache procps >/dev/null 2>&1 || (apt-get update -y >/dev/null 2>&1 && apt-get install -y procps >/dev/null 2>&1) || (yum install -y procps-ng >/dev/null 2>&1) || true); fi
pid=$(docker exec {container} pgrep -xo xray || docker exec {container} ps -o pid,comm | awk '/[x]ray/{print $1; exit}')
if [ -z "$pid" ]; then echo "[guardian-stream] no_xray_process"; exit 44; fi
echo "[guardian-stream] attach pid=$pid"
# Stream stdout/err of xray process inside container via cat on its fds
exec docker exec -i {container} sh -lc "exec stdbuf -oL cat /proc/$pid/fd/1 /proc/$pid/fd/2 2>/dev/null"
'''.format(container=container).strip()

    remote = f"sh -lc {shlex.quote(inner)}"
    cmd = _ssh_base(spec) + [remote]
    log.debug("starting remote log stream: node=%s cmd=%s", spec.name, ' '.join(cmd))
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    try:
        assert proc.stdout is not None
        while True:
            line = await proc.stdout.readline()
            if not line: break
            text=line.decode("utf-8","ignore").rstrip("\n")
            if text.startswith("[guardian-stream]"):
                log.info("node=%s %s", spec.name, text.replace('[guardian-stream] ','').strip())
            else:
                log.debug("node=%s raw-log: %s", spec.name, text)
            yield text
    finally:
        rc = getattr(proc,'returncode',None)
        with contextlib.suppress(ProcessLookupError, AttributeError):
            proc.kill(); await proc.wait()
        log.debug("remote log stream ended: node=%s rc=%s", spec.name, rc)
        # Emit sentinel so watcher can log reason centrally
        yield f"[guardian-stream-exit rc={rc}]"
