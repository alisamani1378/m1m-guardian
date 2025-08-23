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
    container = shlex.quote(spec.docker_container)
    consecutive_fail=0
    while True:
        start=time.time()
        inner = r'''set -e
SUDO=""; if [ "$(id -u)" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi; fi
if ! command -v docker >/dev/null 2>&1; then echo "[guardian-stream] no_docker"; exit 41; fi
if ! $SUDO docker inspect {container} >/dev/null 2>&1; then echo "[guardian-stream] no_container"; exit 42; fi
if ! command -v pgrep >/dev/null 2>&1; then (apk add --no-cache procps >/dev/null 2>&1 || (apt-get update -y >/dev/null 2>&1 && apt-get install -y procps >/dev/null 2>&1) || (yum install -y procps-ng >/dev/null 2>&1) || true); fi
pid=$($SUDO docker exec {container} pgrep -xo xray || $SUDO docker exec {container} ps -o pid,comm | awk '/[x]ray/{{print $1; exit}}')
if [ -z "$pid" ]; then echo "[guardian-stream] no_xray_process"; exit 44; fi
echo "[guardian-stream] attach pid=$pid container={container}"
exec $SUDO docker exec -i {container} sh -lc "exec stdbuf -oL cat /proc/$pid/fd/1 /proc/$pid/fd/2 2>/dev/null"'''.format(container=container).strip()
        remote = f"sh -lc {shlex.quote(inner)}"
        cmd = _ssh_base(spec) + [remote]
        log.debug("starting primary log stream: node=%s cmd=%s", spec.name, ' '.join(cmd))
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        premature=False
        try:
            assert proc.stdout is not None
            async for line in _iter_stream(proc, spec):
                yield line
        finally:
            rc=getattr(proc,'returncode',None)
            duration=time.time()-start
            premature = duration < 8  # ended too quickly
            if premature or rc in (41,42,44):
                consecutive_fail+=1
            else:
                consecutive_fail=0
            log.debug("primary stream ended node=%s rc=%s duration=%.1fs fail_count=%d", spec.name, rc, duration, consecutive_fail)
            with contextlib.suppress(Exception):
                proc.kill(); await proc.wait()
        # Decide fallback
        if consecutive_fail>=3:
            log.warning("node=%s switching to docker logs fallback", spec.name)
            fallback = f"sh -lc {shlex.quote(f'SUDO=; if [ \"$(id -u)\" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO=\"sudo\"; fi; fi; $SUDO docker logs -f --tail=50 {container}')}"
            fcmd=_ssh_base(spec)+[fallback]
            fproc=await asyncio.create_subprocess_exec(*fcmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            try:
                assert fproc.stdout is not None
                while True:
                    line=await fproc.stdout.readline()
                    if not line: break
                    text=line.decode('utf-8','ignore').rstrip('\n')
                    yield text
            finally:
                with contextlib.suppress(Exception):
                    fproc.kill(); await fproc.wait()
            consecutive_fail=0
        # small delay before retry primary
        await asyncio.sleep(2)

async def _iter_stream(proc, spec:NodeSpec):
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
