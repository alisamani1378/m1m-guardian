import logging, time, asyncio
from typing import Set
from .notify import TelegramNotifier

KEY_LOGGERS = {"guardian.nodes", "guardian.watcher", "guardian.start"}
KEYWORDS = (
    "ssh basic check failed",
    "no_xray_process",
    "no_container",
    "docker not installed",
    "spawn ssh failed",
    "log stream wrapper ended",
    "attach container",
    "follow pid=",
    "attached and streaming logs",
    "ensured firewall",
    "banned old ip="
)

class TelegramLogHandler(logging.Handler):
    def __init__(self, notifier:TelegramNotifier, min_interval:float=15.0):
        super().__init__()
        self.notifier=notifier
        self.min_interval=min_interval
        self._last:dict[str,float]={}
        self._loop = None

    def emit(self, record:logging.LogRecord):
        if record.name not in KEY_LOGGERS:
            return
        if record.levelno < logging.WARNING and not any(kw in record.getMessage().lower() for kw in KEYWORDS):
            # forward only warnings/errors or important keywords
            return
        msg=record.getMessage()
        low=msg.lower()
        if not any(kw in low for kw in KEYWORDS) and record.levelno < logging.ERROR:
            return
        now=time.time()
        key=record.name+":"+msg
        lt=self._last.get(key,0)
        if now-lt < self.min_interval:
            return
        self._last[key]=now
        # schedule async send
        try:
            loop=asyncio.get_running_loop()
            loop.create_task(self.notifier.send(f"{record.name}: {msg}"))
        except RuntimeError:
            # no running loop, ignore
            pass

def install_telegram_log_forward(notifier:TelegramNotifier, min_interval:float=15.0):
    if not notifier or not notifier.enabled:
        return None
    h=TelegramLogHandler(notifier, min_interval=min_interval)
    logging.getLogger().addHandler(h)
    return h
