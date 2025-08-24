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
        await asyncio.to_thread(self._post, { 'chat_id': self.chat_id, 'text': text[:4000], 'disable_web_page_preview':'true'})

    async def send_with_inline(self, text:str, buttons:list[list[tuple[str,str]]]):
        """buttons: list of rows; each row list of (label, callback_data)."""
        if not self.enabled: return
        markup={"inline_keyboard": [[{"text": b[0], "callback_data": b[1]} for b in row] for row in buttons]}
        await asyncio.to_thread(self._post, { 'chat_id': self.chat_id, 'text': text[:4000], 'reply_markup': json.dumps(markup), 'disable_web_page_preview':'true'})

    def _post(self, fields:dict):
        if not self.enabled: return
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        data = urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(url, data=data)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status != 200:
                    log.warning("telegram send non-200 status=%s", resp.status)
        except Exception as e:
            log.warning("telegram send failed: %s", e)

    async def delete_webhook(self):
        if not self.enabled: return
        await asyncio.to_thread(self._call_delete_webhook)

    def _call_delete_webhook(self):
        url = f"https://api.telegram.org/bot{self.bot_token}/deleteWebhook"
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                if resp.status!=200:
                    log.debug("deleteWebhook status=%s", resp.status)
        except Exception as e:
            log.debug("deleteWebhook failed: %s", e)

class TelegramBotPoller:
    """Simple long-polling command handler (admin-only). Supports:
    /status, /limits, /nodes, /setlimit name value, /dellimit name
    Button callbacks: lim:<name>, node:<name>, addlim, dellim
    Writes directly to config file; requires service restart for runtime changes.
    """
    def __init__(self, bot_token:str, admin_chat_id:str, config_path:str, load_fn, save_fn):
        self.token=bot_token; self.admin=str(admin_chat_id); self.cfg_path=config_path
        self.load=load_fn; self.save=save_fn; self.offset=0; self.running=True

    async def start(self):
        log.info("telegram poller started")
        while self.running:
            try:
                updates = await asyncio.to_thread(self._get_updates)
                if updates:
                    for u in updates:
                        self.offset = max(self.offset, u.get('update_id',0)+1)
                        await self._handle(u)
            except Exception as e:
                log.debug("poll error: %s", e)
            await asyncio.sleep(2)

    def _api_get(self, method:str, params:dict=None):
        params = params or {}
        params['timeout']=10
        url = f"https://api.telegram.org/bot{self.token}/{method}?"+urllib.parse.urlencode(params)
        with urllib.request.urlopen(url, timeout=20) as resp:
            import json as _j
            return _j.loads(resp.read().decode())

    def _api_post(self, method:str, data:dict):
        url = f"https://api.telegram.org/bot{self.token}/{method}"
        body=urllib.parse.urlencode(data).encode()
        with urllib.request.urlopen(urllib.request.Request(url, data=body), timeout=20) as resp:
            import json as _j
            return _j.loads(resp.read().decode())

    def _get_updates(self):
        res = self._api_get('getUpdates', {'offset': self.offset, 'timeout': 10})
        if not res.get('ok'): return []
        return res.get('result', [])

    async def _handle(self, upd:dict):
        msg = upd.get('message') or upd.get('callback_query',{}).get('message')
        if not msg: return
        chat_id = str(msg['chat']['id'])
        if chat_id != self.admin:  # ignore others
            return
        if 'callback_query' in upd:
            data = upd['callback_query'].get('data','')
            await self._handle_callback(data)
            return
        text = (upd.get('message',{}).get('text') or '').strip()
        if not text: return
        if text.startswith('/'):
            parts=text.split()
            cmd=parts[0].lower()
            args=parts[1:]
            if cmd=='/status': await self._cmd_status()
            elif cmd=='/limits': await self._cmd_limits()
            elif cmd=='/nodes': await self._cmd_nodes()
            elif cmd=='/setlimit' and len(args)==2: await self._cmd_setlimit(args[0], args[1])
            elif cmd=='/dellimit' and len(args)==1: await self._cmd_dellimit(args[0])
            else:
                await self._send(f"Unknown or bad usage. Commands: /status /nodes /limits /setlimit name value /dellimit name")

    async def _handle_callback(self, data:str):
        if data.startswith('lim:'):
            name=data[4:]
            cfg=self.load(self.cfg_path)
            v=cfg.get('inbounds_limit',{}).get(name)
            await self._send(f"Inbound {name} = {v}")
        elif data=='addlim':
            await self._send("Use /setlimit name value")
        elif data.startswith('node:'):
            name=data[5:]
            cfg=self.load(self.cfg_path)
            node=next((n for n in cfg.get('nodes',[]) if n.get('name')==name),None)
            await self._send(f"Node {name}: host={node.get('host') if node else '?'} container={node.get('docker_container') if node else '?'}")
        elif data=='dellim':
            await self._send("Use /dellimit name")

    async def _cmd_status(self):
        cfg=self.load(self.cfg_path)
        nodes=cfg.get('nodes',[])
        txt='Nodes:\n'
        for n in nodes:
            txt+=f" - {n.get('name')} {n.get('host')}:{n.get('ssh_port')} container={n.get('docker_container')}\n"
        await self._send(txt or 'No nodes')

    async def _cmd_limits(self):
        cfg=self.load(self.cfg_path)
        lim=cfg.get('inbounds_limit',{})
        if not lim:
            await self._send('No limits defined')
            return
        buttons=[[ (k, f'lim:{k}') ] for k in lim.keys()]
        buttons.append([('Add','addlim'),('Del','dellim')])
        await self._send_inline('Inbound limits:', buttons)

    async def _cmd_nodes(self):
        cfg=self.load(self.cfg_path)
        nodes=cfg.get('nodes',[])
        if not nodes:
            await self._send('No nodes')
            return
        buttons=[[ (n.get('name'), f'node:{n.get("name")}') ] for n in nodes]
        await self._send_inline('Nodes:', buttons)

    async def _cmd_setlimit(self, name:str, value:str):
        try: v=int(value)
        except: await self._send('Value must be int'); return
        cfg=self.load(self.cfg_path); cfg.setdefault('inbounds_limit',{})[name]=v; self.save(self.cfg_path,cfg)
        await self._send(f'Set {name}={v} (restart service to apply).')

    async def _cmd_dellimit(self, name:str):
        cfg=self.load(self.cfg_path)
        if name in cfg.get('inbounds_limit',{}):
            cfg['inbounds_limit'].pop(name,None); self.save(self.cfg_path,cfg)
            await self._send(f'Removed {name} (restart service).')
        else:
            await self._send('Not found.')

    async def _send(self, text:str):
        await asyncio.to_thread(self._api_post,'sendMessage', {'chat_id': self.admin, 'text': text[:4000], 'disable_web_page_preview':'true'})

    async def _send_inline(self, text:str, buttons:list[list[tuple[str,str]]]):
        markup={"inline_keyboard": [[{"text": b[0], "callback_data": b[1]} for b in row] for row in buttons]}
        await asyncio.to_thread(self._api_post,'sendMessage', {'chat_id': self.admin, 'text': text[:4000], 'reply_markup': json.dumps(markup), 'disable_web_page_preview':'true'})
