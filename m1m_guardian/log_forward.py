import logging, time, asyncio
from typing import Set
from .notify import TelegramNotifier
import re

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
    "banned old ip=",
    "fd_unreadable",
    "switching to docker logs fallback"
)
# خطوط info غیر بحرانی که نمی خواهیم ارسال کنیم (کاهش نویز)
SKIP_KEYWORDS = {"ensured firewall", "attached and streaming logs", "follow pid="}

_node_re = re.compile(r"node=([A-Za-z0-9_-]+)")

class TelegramLogHandler(logging.Handler):
    def __init__(self, notifier:TelegramNotifier, min_interval:float=15.0):
        super().__init__()
        self.notifier=notifier
        self.min_interval=min_interval
        self._last:dict[str,float]={}
        self._loop = None

    def _extract_node(self, msg:str):
        m=_node_re.search(msg)
        return m.group(1) if m else "?"

    def _format(self, record:logging.LogRecord)->str|None:
        raw=record.getMessage()
        low=raw.lower()
        node=self._extract_node(raw)
        # Skip purely informational lines
        if any(k in low for k in SKIP_KEYWORDS) and record.levelno < logging.WARNING:
            return None
        # Patterns
        if "ssh basic check failed" in low:
            # example: ssh basic check failed node=fl rc=255 lines=...;
            rc=re.search(r"rc=(\d+)", raw)
            lines=raw.split('lines=',1)[1] if 'lines=' in raw else ''
            return f"❌ نود {node}: خطای SSH (rc={rc.group(1) if rc else '?'}).\nجزئیات: {lines}\nلطفاً تنظیمات کلید/پسورد و دسترسی پورت را بررسی کنید."
        if "spawn ssh failed" in low:
            return f"❌ نود {node}: برقراری جلسه SSH ناموفق. شبکه یا احراز هویت را بررسی کنید.\nخام: {raw}"
        if "no_container" in low:
            return f"❌ نود {node}: کانتینر تعریف‌شده پیدا نشد. نام کانتینر یا اجرای docker را بررسی کنید."
        if "docker not installed" in low or "no_docker" in low:
            return f"⚠️ نود {node}: docker نصب یا در PATH نیست."
        if "no_xray_process" in low:
            return f"⚠️ نود {node}: فرآیند xray یافت نشد. احتمالاً سرویس داخل کانتینر متوقف است یا هنوز بالا نیامده."
        if "fd_unreadable" in low:
            return f"⚠️ نود {node}: خروجی استاندارد xray قابل خواندن نیست (fd_unreadable). احتمال ریدایرکت به فایل یا محدودیت دسترسی."
        if "switching to docker logs fallback" in low:
            return f"ℹ️ نود {node}: تلاش برای fallback به docker logs (تشخیصی)."
        if "log stream wrapper ended" in low:
            rc=re.search(r"rc=(\d+)", raw)
            return f"⚠️ نود {node}: استریم لاگ قطع شد (rc={rc.group(1) if rc else '?'}). تلاش برای اتصال مجدد..."
        if "banned old ip=" in low:
            # keep concise ban notice
            return raw  # already شامل ip و user است
        # default for warnings/errors
        if record.levelno >= logging.WARNING:
            return f"⚠️ نود {node}: {raw}"
        # ignore residual infos
        return None

    def emit(self, record:logging.LogRecord):
        if record.name not in KEY_LOGGERS:
            return
        raw_msg=record.getMessage()
        low=raw_msg.lower()
        if record.levelno < logging.WARNING and not any(kw in low for kw in KEYWORDS):
            return
        formatted=self._format(record)
        if not formatted:
            return
        now=time.time()
        key=formatted  # use formatted text for rate limiting
        lt=self._last.get(key,0)
        if now-lt < self.min_interval:
            return
        self._last[key]=now
        try:
            loop=asyncio.get_running_loop()
            loop.create_task(self.notifier.send(formatted))
        except RuntimeError:
            pass

def install_telegram_log_forward(notifier:TelegramNotifier, min_interval:float=15.0):
    if not notifier or not notifier.enabled:
        return None
    h=TelegramLogHandler(notifier, min_interval=min_interval)
    logging.getLogger().addHandler(h)
    return h
