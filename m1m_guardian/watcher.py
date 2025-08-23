import asyncio, logging
from .nodes import NodeSpec, stream_logs
from .parser import parse_line
from .firewall import ensure_rule, ban_ip

log = logging.getLogger("guardian.watcher")

class NodeWatcher:
    def __init__(self, spec:NodeSpec, store, limits:dict, ban_minutes:int, all_nodes:list[NodeSpec], cross_node_ban:bool):
        self.spec=spec; self.store=store; self.limits=limits; self.ban_minutes=ban_minutes
        self.all_nodes=all_nodes; self.cross=cross_node_ban
        self._ensured=False

    def limit_for(self, inbound:str):
        return self.limits.get(inbound)

    async def run(self):
        if not self._ensured:
            await ensure_rule(self.spec); self._ensured=True
            log.info("ensured firewall on %s", self.spec.name)

        backoff=1
        while True:
            try:
                async for line in stream_logs(self.spec):
                    email, ip, inbound = parse_line(line)
                    if not email or not ip: continue
                    limit = self.limit_for(inbound)
                    if limit is None:
                        continue
                    evicted, _ = await self.store.add_ip(inbound,email,ip,int(limit))
                    for old_ip in evicted:
                        if old_ip == ip: continue
                        if await self.store.is_banned_recently(old_ip): continue
                        targets = self.all_nodes if self.cross else [self.spec]
                        for node in targets:
                            await ensure_rule(node)
                            await ban_ip(node, old_ip, self.ban_minutes*60)
                            log.warning("banned old ip=%s (user=%s inbound=%s) on node=%s for %dm",
                                old_ip, email, inbound, node.name, self.ban_minutes)
                        await self.store.mark_banned(old_ip, self.ban_minutes*60)
                log.warning("log stream ended for %s, reconnecting...", self.spec.name)
            except Exception as e:
                log.error("watcher error on %s: %s", self.spec.name, e)
            await asyncio.sleep(min(backoff, 30))
            backoff = min(backoff*2, 30)
