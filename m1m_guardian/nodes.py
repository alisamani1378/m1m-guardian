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

async def _ssh_run_capture(cmd:list[str], timeout:float=15.0):
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    except Exception as e:
        return 997, f"spawn_error: {e}".encode()
    try:
        out,_= await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        with contextlib.suppress(Exception): proc.kill()
        return 998, b'timeout'
    return proc.returncode, out or b''

async def run_ssh(spec:NodeSpec, remote_cmd:str) -> int:
    cmd = _ssh_base(spec) + [remote_cmd]
    proc = await asyncio.create_subprocess_exec(*cmd)
    return await proc.wait()

async def _diagnose_connectivity(spec:NodeSpec)->bool:
    """Return True if basic SSH works; logs detailed error otherwise."""
    sentinel="__M1M_OK__"
    cmd=_ssh_base(spec)+[f"echo {sentinel}"]
    rc,out= await _ssh_run_capture(cmd, timeout=10)
    if rc==0 and sentinel.encode() in out:
        return True
    # log condensed diagnostics
    snippet=out.decode(errors='ignore').strip().splitlines()[-5:]
    log.error("ssh basic check failed node=%s rc=%s lines=%s", spec.name, rc, '; '.join(snippet) or '<empty>')
    return False

async def _diagnose_docker(spec:NodeSpec):
    cmd=_ssh_base(spec)+["sh","-lc","command -v docker >/dev/null 2>&1 || echo __NO_DOCKER__; docker ps --format '{{.Names}}' 2>/dev/null | head -20"]
    rc,out= await _ssh_run_capture(cmd, timeout=20)
    text=out.decode(errors='ignore').strip()
    if rc!=0:
        log.error("docker check failed node=%s rc=%s out=%s", spec.name, rc, text)
    else:
        if "__NO_DOCKER__" in text:
            log.error("node=%s docker not installed", spec.name)
        else:
            log.debug("node=%s docker containers: %s", spec.name, ' '.join(text.split()))

async def stream_logs(spec:NodeSpec) -> AsyncIterator[str]:
    """Stream xray stdout/stderr via /proc/$pid/fd inside container with auto reattach.
    Adds: SSH connectivity & docker diagnostics when repeated failures occur.
    """
    failure_streak=0
    while True:
        # Pre-check SSH connectivity if prior failures
        if failure_streak>0:
            ok = await _diagnose_connectivity(spec)
            if not ok:
                failure_streak+=1
                await asyncio.sleep(min(30, 2*failure_streak))
                continue
            # If SSH ok, optionally check docker environment
            await _diagnose_docker(spec)
        container = shlex.quote(spec.docker_container)
        remote_script = (
            "SUDO=\"\"; if [ \"$(id -u)\" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO=\"sudo\"; fi; fi\n"
            "if ! command -v docker >/dev/null 2>&1; then echo '[guardian-stream] no_docker'; exit 41; fi\n"
            f"TARGET={container}\n"
            "if ! $SUDO docker inspect \"$TARGET\" >/dev/null 2>&1; then\n"
            "  for c in $($SUDO docker ps --format '{{.Names}}' 2>/dev/null); do\n"
            "    if $SUDO docker exec \"$c\" sh -lc 'command -v pgrep >/dev/null 2>&1 && pgrep -xo xray >/dev/null 2>&1 || ps | grep -i \\bxray\\b | grep -v grep >/dev/null 2>&1'; then TARGET=\"$c\"; break; fi\n"
            "  done\n"
            "fi\n"
            "if ! $SUDO docker inspect \"$TARGET\" >/dev/null 2>&1; then echo '[guardian-stream] no_container'; exit 42; fi\n"
            "echo '[guardian-stream] attach container='$TARGET\n"
            "exec $SUDO docker exec -i \"$TARGET\" sh -c '"
            "if ! command -v pgrep >/dev/null 2>&1; then (apk add --no-cache procps 2>/dev/null || (apt-get update -y >/dev/null 2>&1 && apt-get install -y procps >/dev/null 2>&1) || yum install -y procps-ng >/dev/null 2>&1 || true); fi; "
            "no_cnt=0; while true; do "
            "if command -v pgrep >/dev/null 2>&1; then pid=$(pgrep -xo xray); else pid=$(ps | grep -i \\bxray\\b | grep -v grep | awk \"{print $1; exit}\"); fi; "
            "if [ -z \"$pid\" ]; then echo \"[guardian-stream] no_xray_process\"; sleep 2; continue; fi; "
            "[ -r /proc/$pid/fd/1 ] || { echo \"[guardian-stream] fd_unreadable pid=$pid\"; sleep 2; continue; }; "
            "echo \"[guardian-stream] follow pid=$pid\"; "
            "cat /proc/$pid/fd/1 /proc/$pid/fd/2 2>/dev/null || true; "
            "sleep 1; done'"
        )
        cmd = _ssh_base(spec) + ["sh","-lc", remote_script]
        log.debug("starting direct xray stream: node=%s cmd=%s", spec.name, ' '.join(cmd))
        try:
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        except Exception as e:
            failure_streak+=1
            log.error("spawn ssh failed node=%s err=%s", spec.name, e)
            await asyncio.sleep(min(30, 2*failure_streak))
            continue
        start=time.time()
        had_output=False
        try:
            assert proc.stdout is not None
            while True:
                line = await proc.stdout.readline()
                if not line: break
                had_output=True
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
            uptime=time.time()-start
            if rc not in (0, None):
                failure_streak = failure_streak+1 if uptime < 10 else 0
                if rc==255:
                    log.error("ssh session ended rc=255 node=%s uptime=%.1fs (auth/network).", spec.name, uptime)
                else:
                    log.warning("log stream wrapper ended node=%s rc=%s uptime=%.1fs", spec.name, rc, uptime)
                if not had_output and uptime < 2:
                    # immediate failure, run quick docker diag once
                    await _diagnose_docker(spec)
            else:
                failure_streak=0
            yield f"[guardian-stream-exit rc={rc}]"
            await asyncio.sleep(4)
