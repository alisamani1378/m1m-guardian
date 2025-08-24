import asyncio, logging, time
from .nodes import NodeSpec, stream_logs
from .parser import parse_line
from .firewall import ensure_rule, ban_ip
from .notify import TelegramNotifier

log = logging.getLogger("guardian.watcher")

class NodeWatcher:
    def __init__(self, spec:NodeSpec, store, limits:dict, ban_minutes:int, all_nodes:list[NodeSpec], notifier:TelegramNotifier|None=None):
        self.spec=spec; self.store=store; self.limits=limits; self.ban_minutes=ban_minutes
        self.all_nodes=all_nodes; self.notifier=notifier
        self._ensured=False
        # node state
        self._up_notified=False
        self._last_down_notice=0.0
        self._last_no_proc_count=0

    async def _notify(self, text:str):
        if self.notifier:
            try:
                await self.notifier.send(text)
            except Exception:
                pass

    async def run(self):
        if not self._ensured:
            await ensure_rule(self.spec); self._ensured=True
            log.info("ensured firewall on %s", self.spec.name)

        backoff=1
        while True:
            try:
                async for line in stream_logs(self.spec):
                    # handle guardian-stream control lines
                    if line.startswith('[guardian-stream]'):
                        low=line.lower()
                        if 'follow pid=' in low and not self._up_notified:
                            self._up_notified=True; self._last_no_proc_count=0
                            await self._notify(f"Node {self.spec.name} attached and streaming logs.")
                        elif 'no_xray_process' in low:
                            self._last_no_proc_count+=1
                            if self._last_no_proc_count in (3,10,30) and (time.time()-self._last_down_notice>30):
                                self._last_down_notice=time.time()
                                await self._notify(f"WARNING: Node {self.spec.name} no xray process (count={self._last_no_proc_count}).")
                        elif 'no_container' in low and (time.time()-self._last_down_notice>30):
                            self._last_down_notice=time.time(); self._up_notified=False
                            await self._notify(f"ERROR: Node {self.spec.name} container not found.")
                        elif 'switching_container' in low:
                            await self._notify(f"Node {self.spec.name} switching container.")
                        elif 'log stream wrapper ended' in low:
                            if time.time()-self._last_down_notice>30:
                                self._last_down_notice=time.time(); self._up_notified=False
                                await self._notify(f"Node {self.spec.name} log stream ended; reconnecting.")
                        continue
                    email, ip, inbound = parse_line(line)
                    if not email or not ip: continue
                    limit = self.limits.get(inbound)
                    if limit is None: continue
                    evicted, _ = await self.store.add_ip(inbound,email,ip,int(limit))
                    for old_ip in evicted:
                        if old_ip == ip: continue
                        if await self.store.is_banned_recently(old_ip): continue
                        success_nodes=[]; failed_nodes=[]
                        for node in self.all_nodes:
                            try:
                                await ensure_rule(node)
                                ok = await ban_ip(node, old_ip, self.ban_minutes*60)
                                (success_nodes if ok else failed_nodes).append(node.name)
                            except Exception as e:
                                failed_nodes.append(node.name)
                                log.debug("ban exception node=%s ip=%s err=%s", node.name, old_ip, e)
                        # summary log (single)
                        log.warning(
                            "banned ip=%s user=%s inbound=%s nodes=%s%s for %dm",
                            old_ip, email, inbound, ','.join(success_nodes) or '-',
                            (f" failed={','.join(failed_nodes)}" if failed_nodes else ''),
                            self.ban_minutes)
                        await self.store.mark_banned(old_ip, self.ban_minutes*60)
                        # single notifier message
                        if success_nodes:
                            msg = (f"IP {old_ip} banned on {', '.join(success_nodes)} for {self.ban_minutes}m\n"
                                   f"user: {email}\n"
                                   f"inbound: {inbound}")
                            if failed_nodes:
                                msg += f"\nFailed nodes: {', '.join(failed_nodes)}"
                            await self._notify(msg)
                log.warning("log stream ended for %s, reconnecting...", self.spec.name)
            except Exception as e:
                log.error("watcher error on %s: %s", self.spec.name, e)
            await asyncio.sleep(min(backoff, 30))
            backoff = min(backoff*2, 30)
