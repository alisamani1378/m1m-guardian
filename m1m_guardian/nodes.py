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
    container = shlex.quote(spec.docker_container)
    inner = r'''set -e


SUDO=""; if [ "$(id -u)" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi; fi
if ! command -v docker >/dev/null 2>&1; then echo "[guardian-stream] no_docker"; exit 41; fi
# Check container; if missing try auto-discover one containing xray
if ! $SUDO docker inspect {container} >/dev/null 2>&1; then
  found=""; amb=""; cands=$($SUDO docker ps --format '{{{{.Names}}}}' 2>/dev/null || true)
  for c in $cands; do
    if $SUDO docker exec "$c" pgrep -xo xray >/dev/null 2>&1; then
      if [ -z "$found" ]; then found="$c"; else amb="1"; fi
    fi
  done
  if [ -n "$found" ]; then
    if [ -n "$amb" ]; then echo "[guardian-stream] auto_container_ambiguous using=$found"; else echo "[guardian-stream] auto_container=$found"; fi
    target="$found"
  else
    echo "[guardian-stream] no_container"; exit 42
  fi
else
  target={container}
fi
if ! command -v pgrep >/dev/null 2>&1; then (apk add --no-cache procps >/dev/null 2>&1 || (apt-get update -y >/dev/null 2>&1 && apt-get install -y procps >/dev/null 2>&1) || (yum install -y procps-ng >/dev/null 2>&1) || true); fi
pid=$($SUDO docker exec "$target" pgrep -xo xray || $SUDO docker exec "$target" ps -o pid,comm | awk '/[x]ray/{{print $1; exit}}')
if [ -z "$pid" ]; then echo "[guardian-stream] no_xray_process"; exit 44; fi
echo "[guardian-stream] attach pid=$pid container=$target"
exec $SUDO docker exec -i "$target" sh -lc "exec stdbuf -oL cat /proc/$pid/fd/1 /proc/$pid/fd/2 2>/dev/null"
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
        yield f"[guardian-stream-exit rc={rc}]"
