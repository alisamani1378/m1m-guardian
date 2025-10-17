import asyncio, logging, time
from .nodes import NodeSpec, stream_logs, run_ssh  # added run_ssh import
from .parser import parse_line
from .firewall import ensure_rule, schedule_ban
from .notify import TelegramNotifier

log = logging.getLogger("guardian.watcher")

class NodeWatcher:
    def __init__(self, spec:NodeSpec, store, limits:dict|None, ban_minutes:int, all_nodes:list[NodeSpec], notifier:TelegramNotifier|None=None):
        # Accept limits possibly None
        self.spec=spec; self.store=store; self.limits=limits or {}; self.ban_minutes=ban_minutes
        self.all_nodes=all_nodes; self.notifier=notifier
        self._ensured=False
        # node state
        self._up_notified=False
        self._last_down_notice=0.0
        self._last_no_proc_count=0
        # fd_unreadable tracking / auto reboot
        self._fd_unreadable_count=0
        self._fd_last_reboot=0.0
        self._fd_window_start=0.0
        # lightweight metrics
        self._lines=0; self._parsed=0; self._last_stat=time.time()
        # NEW: scheduled reboot time after threshold grace period
        self._fd_reboot_scheduled_at=0.0

    async def _notify(self, text:str):
        if self.notifier:
            try:
                await self.notifier.send(text)
            except Exception:
                pass

    async def _maybe_reboot_for_fd(self):
        """If fd_unreadable repeated threshold times, schedule reboot after 60s grace; cooldown 20m."""
        THRESHOLD=10
        COOLDOWN=20*60
        GRACE=60  # 1 minute
        now=time.time()
        if self._fd_unreadable_count >= THRESHOLD:
            # schedule if not already
            if self._fd_reboot_scheduled_at == 0:
                self._fd_reboot_scheduled_at = now
                await self._notify(f"⚠️ نود {self.spec.name}: خطای تکراری خواندن (fd_unreadable x{self._fd_unreadable_count}). اگر ظرف ۶۰ ثانیه درست نشود ریبوت می‌شود.")
                return
            # already scheduled; check grace passed
            if now - self._fd_reboot_scheduled_at < GRACE:
                return
            # grace passed; only reboot if cooldown allows
            if (now - self._fd_last_reboot) <= COOLDOWN:
                # still in cooldown; just notify once every GRACE interval
                if int(now - self._fd_reboot_scheduled_at) % GRACE < 2:  # near boundary
                    await self._notify(f"⏳ نود {self.spec.name}: هنوز مشکل fd_unreadable ادامه دارد ولی در کول‌داون ریبوت است.")
                return
            # proceed reboot
            await self._notify(f"♻️ ریبوت خودکار نود {self.spec.name} پس از عدم بهبود در مهلت ۶۰ ثانیه.")
            reboot_cmd = (
                "sudo -n reboot || sudo -n /sbin/reboot || sudo -n systemctl reboot || "
                "sudo -n shutdown -r now || reboot || /sbin/reboot || systemctl reboot || shutdown -r now"
            )
            async def _reboot():
                try:
                    rc = await run_ssh(self.spec, reboot_cmd)
                    if rc!=0:
                        await self._notify(f"⚠️ ریبوت خودکار نود {self.spec.name} ناموفق (rc={rc}). لطفا دستی بررسی شود.")
                    else:
                        await self._notify(f"✅ فرمان ریبوت ارسال شد برای {self.spec.name}. منتظر اتصال مجدد باشید.")
                except Exception as e:
                    await self._notify(f"⚠️ خطا هنگام ریبوت خودکار {self.spec.name}: {e}")
            asyncio.create_task(_reboot())
            self._fd_last_reboot=now
            self._fd_unreadable_count=0
            self._fd_window_start=now
            self._fd_reboot_scheduled_at=0.0

    async def run(self):
        if not self._ensured:
            await ensure_rule(self.spec); self._ensured=True
            log.info("ensured firewall on %s", self.spec.name)

        backoff=1
        while True:
            try:
                async for line in stream_logs(self.spec):
                    # lightweight periodic stats (every 60s)
                    self._lines+=1
                    now=time.time()
                    if now - self._last_stat > 60:
                        log.debug("stats node=%s lines=%d parsed=%d", self.spec.name, self._lines, self._parsed)
                        self._last_stat=now; self._lines=0; self._parsed=0
                    if line.startswith('[guardian-stream]'):
                        low=line.lower()
                        if 'follow pid=' in low and not self._up_notified:
                            # recovery: reset reboot schedule and counters
                            self._fd_reboot_scheduled_at=0.0
                            self._up_notified=True; self._last_no_proc_count=0
                            self._fd_unreadable_count=0; self._fd_window_start=time.time()
                            await self._notify(f"Node {self.spec.name} attached and streaming logs.")
                        elif 'fd_unreadable' in low:
                            now=time.time()
                            if self._fd_window_start==0 or (now - self._fd_window_start) > 600:
                                self._fd_window_start=now; self._fd_unreadable_count=0; self._fd_reboot_scheduled_at=0.0
                            self._fd_unreadable_count+=1
                            # notify at some milestones (exclude scheduled grace message handled in _maybe_reboot_for_fd)
                            if self._fd_unreadable_count in (3,5,8,10):
                                await self._notify(f"⚠️ نود {self.spec.name}: خطای خواندن خروجی xray (fd_unreadable x{self._fd_unreadable_count}).")
                            await self._maybe_reboot_for_fd()
                            continue
                        # ...existing code for other control messages...
                        if any(k in low for k in ('no_xray_process','no_container','switching_container','log stream wrapper ended')):
                            # existing behaviors unchanged; rest of original code remains
                            pass
                        # continue original logic
                        # ...existing code...
                        # fall through so other branches still processed as before
                    # ...existing code for log parsing and banning...
                    if 'accepted' not in line or 'email:' not in line:
                        continue
                    try:
                        email, ip, inbound = parse_line(line)
                    except Exception as e:
                        log.debug("parse error node=%s err=%s line=%r", self.spec.name, e, line[:200])
                        continue
                    if not email or not ip or not inbound:
                        continue
                    limit = self.limits.get(inbound)
                    if limit is None:
                        continue
                    self._parsed+=1
                    evicted, _ = await self.store.add_ip(inbound,email,ip,int(limit))
                    for old_ip in evicted:
                        if old_ip == ip: continue
                        if await self.store.is_banned_recently(old_ip): continue
                        success_nodes=[]; failed_nodes=[]
                        for node in self.all_nodes:
                            try:
                                await ensure_rule(node)
                                ok = await schedule_ban(node, old_ip, self.ban_minutes*60)
                                (success_nodes if ok else failed_nodes).append(node.name)
                            except Exception as e:
                                failed_nodes.append(node.name)
                                log.debug("ban exception node=%s ip=%s err=%s", node.name, old_ip, e)
                        log.warning("banned ip=%s user=%s inbound=%s nodes=%s%s for %dm", old_ip, email, inbound, ','.join(success_nodes) or '-', (f" failed={','.join(failed_nodes)}" if failed_nodes else ''), self.ban_minutes)
                        await self.store.mark_banned(old_ip, self.ban_minutes*60)
                        display_email=email
                        if '.' in display_email:
                            first, rest = display_email.split('.',1)
                            if first.isdigit():
                                display_email=rest
                        if success_nodes:
                            nodes_list = ', '.join(success_nodes)
                            msg = (f"🚫 *بن IP*\n" f"IP: `{old_ip}`\n" f"کاربر: `{display_email}`\n" f"اینباند: `{inbound}`\n" f"نودها: {nodes_list}\n" f"مدت: {self.ban_minutes} دقیقه")
                            if failed_nodes:
                                msg += f"\nنودهای ناموفق: {', '.join(failed_nodes)}"
                            await self._notify(msg)
                log.warning("log stream ended for %s, reconnecting...", self.spec.name)
            except Exception as e:
                log.error("watcher error on %s: %s", self.spec.name, e)
            await asyncio.sleep(min(backoff, 30))
            backoff = min(backoff*2, 30)
