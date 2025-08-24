import asyncio, json, logging, urllib.request, urllib.parse

log = logging.getLogger("guardian.notify")

class TelegramNotifier:
    def __init__(self, bot_token:str|None, chat_id:str|None, enabled:bool=True):
        self.bot_token = (bot_token or '').strip()
        self.chat_id = (chat_id or '').strip()
        self.enabled = enabled and bool(self.bot_token and self.chat_id)
        if not self.enabled:
            log.debug("Telegram notifier disabled (missing token/chat_id)")

    async def send(self, text:str):
        if not self.enabled: return
        # run blocking HTTP in thread
        await asyncio.to_thread(self._post, text[:4000])  # limit length

    def _post(self, text:str):
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        data = urllib.parse.urlencode({
            'chat_id': self.chat_id,
            'text': text,
            'disable_web_page_preview': 'true'
        }).encode()
        req = urllib.request.Request(url, data=data)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status != 200:
                    log.warning("telegram send non-200 status=%s", resp.status)
        except Exception as e:
            log.warning("telegram send failed: %s", e)

