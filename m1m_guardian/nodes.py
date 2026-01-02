import asyncio, shlex
import contextlib
from typing import List, AsyncIterator
import logging, time
import os
import re

log = logging.getLogger("guardian.nodes")
# Track hosts whose host key mismatch we already auto-cleared (avoid loops)
_hostkey_cleared:set[str] = set()

class NodeSpec:
    def __init__(self, name, host, ssh_user, ssh_port, docker_container, ssh_key=None, ssh_pass=None):
        self.name=name; self.host=host; self.ssh_user=ssh_user; self.ssh_port=ssh_port
        self.docker_container=docker_container; self.ssh_key=ssh_key; self.ssh_pass=ssh_pass

    def __repr__(self): return f"<Node {self.name}@{self.host}:{self.ssh_port}>"

def _ssh_base(spec:NodeSpec)->List[str]:
    # Rebuild to drop BatchMode when password auth is used (sshpass needs prompts allowed)
    opts=[
        "-o","StrictHostKeyChecking=no",
        "-o","ServerAliveInterval=30",
        "-o","ServerAliveCountMax=3",
        "-o","ControlMaster=auto",
        "-o","ControlPersist=60s",
        "-o","ControlPath=~/.ssh/cm-%r@%h:%p",
        "-o","ConnectTimeout=8",
    ]
    if not spec.ssh_pass:  # only safe for key auth
        opts=["-o","BatchMode=yes"]+opts
    common=["ssh", *opts, "-p", str(spec.ssh_port), f"{spec.ssh_user}@{spec.host}"]
    if spec.ssh_key:
        common=["ssh","-i",spec.ssh_key]+common[1:]
    if spec.ssh_pass:
        common=["sshpass","-p",spec.ssh_pass]+common
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

async def _remove_known_host(host:str):
    """Remove host key entry so new key is accepted. Returns True if removal ran."""
    try:
        # ssh-keygen -R handles hashed/normal entries
        proc = await asyncio.create_subprocess_exec('ssh-keygen','-R',host, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        await proc.communicate()
        # Also remove possible duplicated entries with sed (best-effort)
        known = '/root/.ssh/known_hosts'
        if host and os.path.isfile(known):
            try:
                lines=[]
                pattern=re.compile(rf"(^|,){re.escape(host)}(,|\s)")
                with open(known,'r',encoding='utf-8',errors='ignore') as f: # type: ignore
                    for line in f:
                        if pattern.search(line):
                            continue
                        lines.append(line)
                with open(known,'w',encoding='utf-8') as f:
                    f.writelines(lines)
            except Exception:
                pass
        return True
    except Exception:
        return False

async def run_ssh(spec:NodeSpec, remote_cmd:str) -> int:
    cmd = _ssh_base(spec) + [remote_cmd]
    proc = await asyncio.create_subprocess_exec(*cmd)
    return await proc.wait()

async def _diagnose_connectivity(spec:NodeSpec)->bool:
    """Return True if basic SSH works; logs detailed error otherwise.
    Auto handles host key change by clearing known_hosts once.
    """
    sentinel="__M1M_OK__"
    cmd=_ssh_base(spec)+[f"echo {sentinel}"]
    rc,out= await _ssh_run_capture(cmd, timeout=10)
    if rc==0 and sentinel.encode() in out:
        return True
    text = out.decode(errors='ignore')
    # Extract fingerprint if present
    fp_match=re.search(r"SHA256:[A-Za-z0-9+/=]+", text)
    fingerprint=fp_match.group(0) if fp_match else 'unknown'
    mismatch = 'REMOTE HOST IDENTIFICATION HAS CHANGED' in text or 'IDENTIFICATION HAS CHANGED' in text
    if mismatch:
        if spec.host not in _hostkey_cleared:
            log.warning("hostkey rotated node=%s host=%s fingerprint=%s action=detected", spec.name, spec.host, fingerprint)
            ok = await _remove_known_host(spec.host)
            _hostkey_cleared.add(spec.host)
            if ok:
                rc2,out2 = await _ssh_run_capture(cmd, timeout=10)
                if rc2==0 and sentinel.encode() in out2:
                    log.info("hostkey rotated node=%s host=%s fingerprint=%s action=auto-cleared status=accepted", spec.name, spec.host, fingerprint)
                    return True
                else:
                    log.error("hostkey rotated node=%s host=%s fingerprint=%s action=auto-cleared status=retry_failed rc=%s", spec.name, spec.host, fingerprint, rc2)
            else:
                log.error("hostkey rotated node=%s host=%s fingerprint=%s action=remove_failed", spec.name, spec.host, fingerprint)
            # do not proceed further; return False to allow backoff
            return False
    # log condensed diagnostics
    snippet=text.strip().splitlines()[-8:]
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
    Retains SSH/docker diagnostics; removes docker logs fallback (همیشه روش قبلی).
    On repeated fd_unreadable prints periodic diagnostics instead of switching.
    """
    failure_streak=0
    fd_unreadable_count=0
    last_diag_time=0.0
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
            "while true; do "
            "if command -v pgrep >/dev/null 2>&1; then pid=$(pgrep -xo xray); else pid=$(ps | grep -i \\bxray\\b | grep -v grep | awk \"{print $1; exit}\"); fi; "
            "if [ -z \"$pid\" ]; then echo \"[guardian-stream] no_xray_process\"; sleep 2; continue; fi; "
            "if [ ! -r /proc/$pid/fd/1 ]; then echo \"[guardian-stream] fd_unreadable pid=$pid\"; sleep 2; continue; fi; "
            "echo \"[guardian-stream] follow pid=$pid\"; "
            "cat /proc/$pid/fd/1 /proc/$pid/fd/2 2>/dev/null || true; "
            "sleep 1; done'"
        )
        cmd = _ssh_base(spec) + ["sh","-lc", remote_script]
        log.debug("starting direct stream (no-fallback) node=%s cmd=%s", spec.name, ' '.join(cmd))
        try:
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        except Exception as e:
            failure_streak+=1
            log.error("spawn ssh failed node=%s err=%s", spec.name, e)
            await asyncio.sleep(min(30, 2*failure_streak))
            continue
        start=time.time(); had_output=False
        raw_count=0  # sampling counter for raw logs
        try:
            assert proc.stdout is not None
            while True:
                line=await proc.stdout.readline()
                if not line: break
                had_output=True
                text=line.decode('utf-8','ignore').rstrip('\n')
                if text.startswith('[guardian-stream]'):
                    msg=text.replace('[guardian-stream]','').strip()
                    if 'fd_unreadable' in msg:
                        fd_unreadable_count+=1
                        # هر چند بار، دیاگ مختصر
                        if fd_unreadable_count in (5,15,30) and (time.time()-last_diag_time>10):
                            last_diag_time=time.time()
                            # یک فرمان تشخیصی جدا برای گزارش سطح دسترسی FD
                            diag_cmd=_ssh_base(spec)+["sh","-lc", "pid=$(pgrep -xo xray || ps | grep -i \\bxray\\b | grep -v grep | awk '{print $1;exit}'); if [ -n \"$pid\" ]; then echo '[guardian-diag] ls_fd:'; ls -l /proc/$pid/fd 2>/dev/null | head -20; echo '[guardian-diag] stat_fd1:'; stat /proc/$pid/fd/1 2>/dev/null || true; fi"]
                            rc,out=await _ssh_run_capture(diag_cmd, timeout=8)
                            log.warning("node=%s fd_unreadable diagnostics rc=%s out=%s", spec.name, rc, out.decode(errors='ignore').strip())
                    elif 'follow pid=' in msg:
                        fd_unreadable_count=0
                    log.info("node=%s %s", spec.name, msg)
                    yield text
                else:
                    # Detect host key mismatch in raw ssh output (before our diagnostics)
                    if 'REMOTE HOST IDENTIFICATION HAS CHANGED' in text and spec.host not in _hostkey_cleared:
                        fp_match=re.search(r"SHA256:[A-Za-z0-9+/=]+", text)
                        fingerprint=fp_match.group(0) if fp_match else 'unknown'
                        log.warning("hostkey rotated node=%s host=%s fingerprint=%s action=detected(stream)", spec.name, spec.host, fingerprint)
                        ok = await _remove_known_host(spec.host)
                        _hostkey_cleared.add(spec.host)
                        if ok:
                            log.info("hostkey rotated node=%s host=%s fingerprint=%s action=auto-cleared(stream) status=will-retry", spec.name, spec.host, fingerprint)
                            break  # break current stream to retry quickly
                        else:
                            log.error("hostkey rotated node=%s host=%s fingerprint=%s action=remove_failed(stream)", spec.name, spec.host, fingerprint)
                    raw_count+=1
                    if raw_count % 20 == 0:  # sample every 20th raw line
                        log.debug("node=%s raw-log(sampled): %s", spec.name, text)
                    yield text
        finally:
            rc=getattr(proc,'returncode',None)
            with contextlib.suppress(Exception): proc.kill(); await proc.wait()
            uptime=time.time()-start
            if rc not in (0,None):
                failure_streak = failure_streak+1 if uptime < 10 else 0
                if rc==255:
                    log.error("ssh session ended rc=255 node=%s uptime=%.1fs (auth/network).", spec.name, uptime)
                else:
                    log.warning("log stream wrapper ended node=%s rc=%s uptime=%.1fs", spec.name, rc, uptime)
            else:
                failure_streak=0
            # Do not yield inside finally to avoid GeneratorExit issues.
            await asyncio.sleep(4)
