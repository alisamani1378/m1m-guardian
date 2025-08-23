import asyncio, shlex
import contextlib
from typing import List, AsyncIterator
import logging, time

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
    """Stream xray stdout/stderr directly via /proc/$pid/fd inside container.
    Uses a persistent loop inside the container to auto re-attach when xray restarts.
    Falls back to autodiscovering a container if the configured one is missing.
    """
    while True:
        container = shlex.quote(spec.docker_container)
        remote_script = r'''SUDO=""; if [ "$(id -u)" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi; fi
if ! command -v docker >/dev/null 2>&1; then echo "[guardian-stream] no_docker"; exit 41; fi
TARGET={container}
if ! $SUDO docker inspect "$TARGET" >/dev/null 2>&1; then
  for c in $($SUDO docker ps --format '{{{{.Names}}}}' 2>/dev/null); do
    if $SUDO docker exec "$c" sh -lc 'pgrep -xo xray >/dev/null 2>&1 || ps -o comm | grep -i xray >/dev/null 2>&1'; then TARGET="$c"; break; fi
  done
fi
if ! $SUDO docker inspect "$TARGET" >/dev/null 2>&1; then echo "[guardian-stream] no_container"; exit 42; fi
echo "[guardian-stream] attach container=$TARGET"
# Loop re-attaching to xray pid
exec $SUDO docker exec -i "$TARGET" sh -lc 'while true; do \
  pid=$(pgrep -xo xray || ps -o pid,comm | awk "/[x]ray/{print $1; exit}"); \
  if [ -z "$pid" ]; then echo "[guardian-stream] no_xray_process"; sleep 2; continue; fi; \
  echo "[guardian-stream] follow pid=$pid"; \
  stdbuf -oL cat /proc/$pid/fd/1 /proc/$pid/fd/2 2>/dev/null || true; \
  sleep 1; \
 done'
'''.format(container=container).strip()
        cmd = _ssh_base(spec) + ["sh","-lc", remote_script]
        log.debug("starting direct xray stream: node=%s cmd=%s", spec.name, ' '.join(cmd))
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        start=time.time()
        try:
            assert proc.stdout is not None
            while True:
                line = await proc.stdout.readline()
                if not line: break
                text=line.decode('utf-8','ignore').rstrip('\n')
                if text.startswith('[guardian-stream]'):
                    log.info("node=%s %s", spec.name, text.replace('[guardian-stream] ','').strip())
                else:
                    log.debug("node=%s raw-log: %s", spec.name, text)
                yield text
        finally:
            rc=getattr(proc,'returncode',None)
            with contextlib.suppress(Exception):
                proc.kill(); await proc.wait()
            log.warning("log stream wrapper ended node=%s rc=%s uptime=%.1fs (restarting in 3s)", spec.name, rc, time.time()-start)
            yield f"[guardian-stream-exit rc={rc}]"
            await asyncio.sleep(3)
