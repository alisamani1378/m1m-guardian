import asyncio, json, logging, urllib.request, urllib.parse
import os, time
from typing import List, Dict, Tuple
from .firewall import unban_ip, ensure_rule
from .nodes import NodeSpec

log = logging.getLogger("guardian.notify")

class TelegramNotifier:
    def __init__(self, bot_token:str|None, chat_id:str|None, enabled:bool=True):
        self.bot_token = (bot_token or '').strip()
        self.chat_id = (chat_id or '').strip()
        self.enabled = enabled and bool(self.bot_token and self.chat_id)
        if not self.enabled:
            log.debug("Telegram notifier disabled (missing token/chat_id)")

    async def send(self, text:str, parse_mode:str|None='Markdown'):
        if not self.enabled: return
        payload={ 'chat_id': self.chat_id, 'text': text[:4000], 'disable_web_page_preview':'true'}
        if parse_mode: payload['parse_mode']=parse_mode
        await asyncio.to_thread(self._post, payload)

    async def send_with_inline(self, text:str, buttons:list[list[tuple[str,str]]], parse_mode:str|None='Markdown'):
        """buttons: list of rows; each row list of (label, callback_data)."""
        if not self.enabled: return
        markup={"inline_keyboard": [[{"text": b[0], "callback_data": b[1]} for b in row] for row in buttons]}
        payload={ 'chat_id': self.chat_id, 'text': text[:4000], 'reply_markup': json.dumps(markup), 'disable_web_page_preview':'true'}
        if parse_mode: payload['parse_mode']=parse_mode
        await asyncio.to_thread(self._post, payload)

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
    """Telegram management bot (simplified)."""
    def __init__(self, bot_token:str, admin_chat_id:str|None, config_path:str, load_fn, save_fn, store=None, nodes:List[NodeSpec]|None=None, extra_admins:List[str]|None=None):
        self.token=bot_token; self.cfg_path=config_path
        self.load=load_fn; self.save=save_fn; self.offset=0; self.running=True
        admins=set()
        if admin_chat_id: admins.add(str(admin_chat_id))
        if extra_admins:
            for a in extra_admins:
                if a: admins.add(str(a))
        self.admins=admins or set()
        self.state:dict[str,dict]={}
        self.store=store
        self.nodes=nodes or []
        self.session_cache:Dict[str,Tuple[str,str,List[str]]]={}
        self.banned_cache:Dict[str,int]={}
        self._last_restart_ts=0.0
        cfg_dir=os.path.dirname(self.cfg_path) or '/etc/m1m-guardian'
        os.makedirs(cfg_dir, exist_ok=True)
        self.offset_file=os.path.join(cfg_dir, 'telegram.offset')
        self._load_offset()
        self._pending_post_add:dict[str,float]={}

    # ---------------- core polling ----------------
    async def start(self):
        log.info("telegram poller started")
        while self.running:
            try:
                updates = await asyncio.to_thread(self._get_updates)
                if updates:
                    for u in updates:
                        self.offset = max(self.offset, u.get('update_id',0)+1)
                        # persist offset after each processed update to avoid replay after restart
                        self._save_offset()
                        await self._handle(u)
            except Exception as e:
                log.debug("poll error: %s", e)
            await asyncio.sleep(2)

    # ---------------- HTTP helpers ----------------
    def _api_get(self, method:str, params:dict=None):
        params = params or {}; params['timeout']=10
        url = f"https://api.telegram.org/bot{self.token}/{method}?"+urllib.parse.urlencode(params)
        with urllib.request.urlopen(url, timeout=20) as resp:
            import json as _j; return _j.loads(resp.read().decode())

    def _api_post(self, method:str, data:dict):
        url = f"https://api.telegram.org/bot{self.token}/{method}"; body=urllib.parse.urlencode(data).encode()
        with urllib.request.urlopen(urllib.request.Request(url, data=body), timeout=20) as resp:
            import json as _j; return _j.loads(resp.read().decode())

    def _get_updates(self):
        res = self._api_get('getUpdates', {'offset': self.offset, 'timeout': 10})
        if not res.get('ok'): return []
        return res.get('result', [])

    # ---------------- sending helpers ----------------
    async def _send(self, text:str, markup:dict|None=None, chat_id:str|None=None, parse_mode:str|None='Markdown'):
        chat_id = chat_id or (next(iter(self.admins)) if self.admins else None)
        if not chat_id: return
        data={'chat_id': chat_id, 'text': text[:4000], 'disable_web_page_preview':'true'}
        if markup: data['reply_markup']=json.dumps(markup)
        if parse_mode: data['parse_mode']=parse_mode
        await asyncio.to_thread(self._api_post,'sendMessage', data)

    def _kb(self, rows:list[list[tuple[str,str]]]):
        return {"inline_keyboard": [[{"text":t,"callback_data":d} for (t,d) in row] for row in rows]}

    async def _menu_main(self, chat_id:str):
        cfg=self.load(self.cfg_path)
        nodes=cfg.get('nodes',[])
        header=(f"*🛡 Guardian*")
        rows=[
            [("📊 وضعیت","mn_status"),("👥 سشن‌ها","mn_sessions")],
            [("🧩 نودها","mn_nodes"),("📡 این‌باندها","mn_inb")],
            [("🚫 IP بن","mn_banned"),("⚙️ تنظیمات","mn_settings")],
            [("🔁 ریفرش","mn_refresh"),("♻️ ریست","set_restart")]
        ]
        await self._send(header, self._kb(rows), chat_id=chat_id, parse_mode='Markdown')

    # ---------------- update handler ----------------
    async def _handle(self, upd:dict):
        cb = upd.get('callback_query')
        if cb:
            chat_id=str(cb['message']['chat']['id'])
            if chat_id not in self.admins: return
            data=cb.get('data','')
            await self._handle_callback(chat_id, data)
            return
        msg=upd.get('message')
        if not msg: return
        chat_id=str(msg['chat']['id'])
        if chat_id not in self.admins: return
        text=(msg.get('text') or '').strip()
        st=self.state.get(chat_id)
        if st:
            await self._handle_state_input(chat_id, text)
            return
        await self._menu_main(chat_id)

    # ---------------- state input ----------------
    async def _handle_state_input(self, chat_id:str, text:str):
        st=self.state.get(chat_id)
        if not st: return
        kind=st.get('kind')
        cfg=self.load(self.cfg_path)
        try:
            if kind=='edit_node_field':
                node_name=st['node']; field=st['field']
                node=self._find_node(cfg,node_name)
                if not node:
                    await self._send("نود یافت نشد", chat_id=chat_id)
                else:
                    if field=='ssh_port':
                        try: node[field]=int(text)
                        except: await self._send("پورت نامعتبر", chat_id=chat_id); self.state.pop(chat_id,None); return
                    else:
                        node[field]=text
                    self.save(self.cfg_path,cfg)
                    await self._send(f"بروزرسانی شد: {node_name}.{field}", chat_id=chat_id)
                self.state.pop(chat_id,None)
                await self._show_node(node_name, chat_id)
            elif kind=='set_inbound_limit':
                name=st['inbound']
                try: v=int(text)
                except: await self._send("عدد نامعتبر", chat_id=chat_id); return
                cfg.setdefault('inbounds_limit',{})[name]=v; self.save(self.cfg_path,cfg)
                await self._send(f"حد {name} = {v} ذخیره شد (ریست برای اعمال)", chat_id=chat_id)
                self.state.pop(chat_id,None)
                await self._menu_inbounds(chat_id)
            elif kind=='add_inbound_name':
                if not text:
                    await self._send("نام خالی است.", chat_id=chat_id)
                    return
                st['new_name']=text
                st['kind']='add_inbound_value'
                await self._send("عدد حد مجاز را وارد کن:", chat_id=chat_id)
            elif kind=='add_inbound_value':
                try: v=int(text)
                except: await self._send("عدد نامعتبر", chat_id=chat_id); return
                name=st.get('new_name')
                cfg.setdefault('inbounds_limit',{})[name]=v; self.save(self.cfg_path,cfg)
                await self._send(f"این‌باند {name} با حد {v} افزوده شد.", chat_id=chat_id)
                self.state.pop(chat_id,None)
                await self._menu_inbounds(chat_id)
            elif kind=='add_node_step':
                step=st.get('step',0)
                collecting=st.setdefault('data',{})
                if step==0:
                    collecting['name']=text or 'node'
                    st['step']=1; await self._send("هاست / IP را وارد کن:", chat_id=chat_id)
                elif step==1:
                    collecting['host']=text; st['step']=2; await self._send("کاربر SSH (مثلا ubuntu):", chat_id=chat_id)
                elif step==2:
                    collecting['ssh_user']=text or 'root'; st['step']=3; await self._send("پورت SSH (مثلا 22):", chat_id=chat_id)
                elif step==3:
                    try: collecting['ssh_port']=int(text)
                    except: collecting['ssh_port']=22
                    st['step']=4; await self._send("نام کانتینر (مثلا marzban-node):", chat_id=chat_id)
                elif step==4:
                    collecting['docker_container']=text or 'marzban-node'
                    st['step']=5; await self._send("نوع احراز: 1=مسیر کلید 2=پسورد 3=متن کلید", chat_id=chat_id)
                elif step==5:
                    if text=='2':
                        st['auth']='pass'; st['step']=6; await self._send("پسورد SSH را بفرست:", chat_id=chat_id)
                    elif text=='3':
                        st['auth']='keytext'; st['step']=6; await self._send("متن کامل کلید خصوصی را ارسال کن (با -----BEGIN شروع می شود):", chat_id=chat_id)
                    else:
                        st['auth']='key'; st['step']=6; await self._send("مسیر کلید خصوصی (مثلا /root/.ssh/id_rsa):", chat_id=chat_id)
                elif step==6:
                    if st.get('auth')=='pass':
                        collecting['ssh_pass']=text
                    elif st.get('auth')=='key':
                        collecting['ssh_key']=text
                    elif st.get('auth')=='keytext':
                        # ذخیره متن کلید در فایل امن
                        try:
                            import os, stat
                            keys_dir='/etc/m1m-guardian/keys'
                            os.makedirs(keys_dir, exist_ok=True)
                            safe_name=collecting.get('name','node')
                            fname=os.path.join(keys_dir, f"{safe_name}.key")
                            with open(fname,'w',encoding='utf-8') as f:
                                f.write(text.strip()+('\n' if not text.endswith('\n') else ''))
                            try:
                                os.chmod(fname, 0o600)
                            except Exception:
                                pass
                            collecting['ssh_key']=fname
                        except Exception as e:
                            await self._send(f"خطا در ذخیره کلید: {e}", chat_id=chat_id)
                    cfg.setdefault('nodes',[]).append(collecting)
                    self.save(self.cfg_path,cfg)
                    await self._send(f"نود {collecting['name']} اضافه شد. در حال ریست و تست اتصال...", chat_id=chat_id)
                    # زمان ذخیره برای جلوگیری از چند تست همزمان اگر اسپم شود
                    self._pending_post_add[collecting['name']]=time.time()
                    asyncio.create_task(self._post_add_node(collecting['name'], chat_id))
                    self.state.pop(chat_id,None)
                    await self._menu_nodes(chat_id)
            elif kind=='edit_setting_banmin':
                try: v=int(text)
                except: await self._send("عدد نامعتبر", chat_id=chat_id); return
                cfg['ban_minutes']=v; self.save(self.cfg_path,cfg)
                await self._send(f"ban_minutes = {v} ذخیره شد.", chat_id=chat_id)
                self.state.pop(chat_id,None)
                await self._menu_settings(chat_id)
            else:
                await self._send("وضعیت ناشناخته پاک شد.", chat_id=chat_id)
                self.state.pop(chat_id,None)
        except Exception as e:
            log.debug("state input error: %s", e)
            self.state.pop(chat_id,None)
            await self._send("خطا در پردازش ورودی.", chat_id=chat_id)

    # ---------------- callback handlers ----------------
    async def _handle_callback(self, chat_id:str, data:str):
        if data=='mn_status':
            await self._menu_status(chat_id); return
        if data=='mn_refresh':
            await self._menu_main(chat_id); return
        if data=='mn_nodes':
            await self._menu_nodes(chat_id); return
        if data=='mn_inb':
            await self._menu_inbounds(chat_id); return
        if data=='mn_settings':
            await self._menu_settings(chat_id); return
        if data=='mn_sessions':
            await self._menu_sessions(chat_id); return
        if data=='mn_banned':
            await self._menu_banned(chat_id); return
        # node menu
        if data=='nodes_add':
            self.state[chat_id]={'kind':'add_node_step','step':0}
            await self._send("نام نود جدید را وارد کن:", chat_id=chat_id)
            return
        if data.startswith('node:'):
            name=data.split(':',1)[1]
            await self._show_node(name, chat_id); return
        if data.startswith('nodedelete:'):
            name=data.split(':',1)[1]
            cfg=self.load(self.cfg_path); before=len(cfg.get('nodes',[]))
            cfg['nodes']=[n for n in cfg.get('nodes',[]) if n.get('name')!=name]; self.save(self.cfg_path,cfg)
            await self._send(f"نود {name} حذف شد (ریست برای اعمال).", chat_id=chat_id)
            await self._menu_nodes(chat_id); return
        if data.startswith('nodeedit:'):
            _parts=data.split(':')  # nodeedit:NAME:FIELD
            if len(_parts)==3:
                name,field=_parts[1],_parts[2]
                self.state[chat_id]={'kind':'edit_node_field','node':name,'field':field}
                await self._send(f"مقدار جدید برای {name}.{field} را ارسال کن:", chat_id=chat_id)
            return
        if data.startswith('nodeauthpass:'):
            name=data.split(':',1)[1]
            self.state[chat_id]={'kind':'edit_node_field','node':name,'field':'ssh_pass'}
            await self._send(f"پسورد جدید SSH برای {name}:", chat_id=chat_id)
            return
        if data.startswith('nodeauthkey:'):
            name=data.split(':',1)[1]
            self.state[chat_id]={'kind':'edit_node_field','node':name,'field':'ssh_key'}
            await self._send(f"مسیر کلید خصوصی برای {name}:", chat_id=chat_id)
            return
        # inbound limits
        if data=='inb_add':
            self.state[chat_id]={'kind':'add_inbound_name'}
            await self._send("نام این‌باند جدید را بفرست:", chat_id=chat_id)
            return
        if data.startswith('inb:'):
            name=data.split(':',1)[1]
            await self._show_inbound(name, chat_id); return
        if data.startswith('inbdel:'):
            name=data.split(':',1)[1]
            cfg=self.load(self.cfg_path)
            if name in cfg.get('inbounds_limit',{}):
                cfg['inbounds_limit'].pop(name,None); self.save(self.cfg_path,cfg)
                await self._send(f"این‌باند {name} حذف شد (ریست برای اعمال).", chat_id=chat_id)
            await self._menu_inbounds(chat_id); return
        if data.startswith('inbedit:'):
            name=data.split(':',1)[1]
            self.state[chat_id]={'kind':'set_inbound_limit','inbound':name}
            await self._send(f"عدد جدید حد برای {name}:", chat_id=chat_id)
            return
        # sessions
        if data.startswith('sess:'):
            sid=data.split(':',1)[1]
            rec=self.session_cache.get(sid)
            if not rec:
                await self._send("سشن یافت نشد.", chat_id=chat_id); return
            inbound,email,ips=rec
            txt=f"سشن\nاینباند: {inbound}\nیوزر: {email}\nIP ها:\n"+'\n'.join(ips[:50])
            await self._send(txt, self._kb([[("↩️","mn_sessions")]]), chat_id=chat_id); return
        # banned
        if data.startswith('unbanconfirm:'):
            ip=data.split(':',1)[1]
            await self._perform_unban(ip, chat_id)
            return
        if data.startswith('unban:'):
            ip=data.split(':',1)[1]
            await self._send(f"آنبن IP {ip}?", self._kb([[('✅ بله','unbanconfirm:'+ip),("❌ خیر","mn_banned")]]), chat_id=chat_id)
            return
        # settings
        if data=='set_edit_banmin':
            self.state[chat_id]={'kind':'edit_setting_banmin'}
            await self._send("عدد جدید ban_minutes را بفرست:", chat_id=chat_id)
            return
        if data=='set_restart':
            await self._restart_service(chat_id); return

    async def _perform_unban(self, ip:str, chat_id:str):
        if not self.store:
            await self._send("Store در دسترس نیست.", chat_id=chat_id); return
        # Attempt unban across all nodes (safe if not present)
        tasks=[]
        for n in self.nodes:
            tasks.append(unban_ip(n, ip))
        if tasks:
            try:
                await asyncio.gather(*tasks)
            except Exception:
                pass
        await self.store.unmark_banned(ip)
        await self._send(f"IP {ip} آنبن شد.", chat_id=chat_id)
        await self._menu_banned(chat_id)

    async def _restart_service(self, chat_id:str):
        now=time.time()
        if now - self._last_restart_ts < 60:  # 60s cooldown
            await self._send("⏳ ریست اخیر انجام شد؛ چند ثانیه دیگر دوباره تلاش کن.", chat_id=chat_id)
            return
        self._last_restart_ts=now
        await self._send("درحال ریست سرویس...", chat_id=chat_id)
        try:
            asyncio.create_task(self._run_restart())
        except Exception:
            await self._send("خطای ریست", chat_id=chat_id)

    async def _run_restart(self):
        try:
            proc=await asyncio.create_subprocess_exec('sh','-lc','sleep 1; systemctl restart m1m-guardian')
            await proc.wait()
        except Exception as e:
            log.debug("restart error: %s", e)
    # ---------------- offset persistence ----------------
    def _load_offset(self):
        try:
            if os.path.isfile(self.offset_file):
                with open(self.offset_file,'r',encoding='utf-8') as f:
                    val=f.read().strip()
                    if val.isdigit():
                        self.offset=int(val)
                        log.debug("loaded telegram offset=%s", self.offset)
        except Exception as e:
            log.debug("load offset failed: %s", e)

    def _save_offset(self):
        try:
            with open(self.offset_file,'w',encoding='utf-8') as f:
                f.write(str(self.offset))
        except Exception as e:
            log.debug("save offset failed: %s", e)

    # ---------------- submenus ----------------
    def _find_node(self,cfg,name):
        return next((n for n in cfg.get('nodes',[]) if n.get('name')==name), None)

    async def _menu_nodes(self, chat_id:str):
        cfg=self.load(self.cfg_path)
        nodes=cfg.get('nodes',[])
        if not nodes:
            await self._send("هیچ نودی تعریف نشده.", self._kb([[('افزودن نود','nodes_add')],[('بازگشت','mn_refresh')]]), chat_id=chat_id)
            return
        rows=[[ (n.get('name'), f'node:{n.get("name")}') ] for n in nodes]
        rows.append([('➕ افزودن','nodes_add'),('↩️ برگشت','mn_refresh')])
        await self._send("لیست نودها:", self._kb(rows), chat_id=chat_id)

    async def _show_node(self, name:str, chat_id:str):
        cfg=self.load(self.cfg_path); node=self._find_node(cfg,name)
        if not node:
            await self._send("نود پیدا نشد.", chat_id=chat_id); return
        txt=(f"نود: {name}\nHost: {node.get('host')}\nUser: {node.get('ssh_user')}\nPort: {node.get('ssh_port')}\nContainer: {node.get('docker_container')}\nAuth: {'key' if node.get('ssh_key') else 'pass' if node.get('ssh_pass') else 'unknown'}\n")
        rows=[
            [('Host','nodeedit:'+name+':host'),('User','nodeedit:'+name+':ssh_user')],
            [('Port','nodeedit:'+name+':ssh_port'),('Container','nodeedit:'+name+':docker_container')],
            [('AuthPass','nodeauthpass:'+name),('AuthKey','nodeauthkey:'+name)],
            [('❌ حذف','nodedelete:'+name),('⬅️ برگشت','mn_nodes')]
        ]
        await self._send(txt, self._kb(rows), chat_id=chat_id)

    async def _menu_inbounds(self, chat_id:str):
        cfg=self.load(self.cfg_path); lim=cfg.get('inbounds_limit',{})
        if not lim:
            await self._send("هیچ این‌باندی تنظیم نشده.", self._kb([[('➕ افزودن','inb_add'),('↩️ برگشت','mn_refresh')]]), chat_id=chat_id); return
        rows=[[ (f"{k}:{v}", f'inb:{k}') ] for k,v in lim.items()]
        rows.append([('➕','inb_add'),('↩️','mn_refresh')])
        await self._send("لیست این‌باندها:", self._kb(rows), chat_id=chat_id)

    async def _show_inbound(self,name:str, chat_id:str):
        cfg=self.load(self.cfg_path); v=cfg.get('inbounds_limit',{}).get(name)
        if v is None:
            await self._send("یافت نشد.", chat_id=chat_id); return
        rows=[[('ویرایش','inbedit:'+name),('حذف','inbdel:'+name)],[('↩️ برگشت','mn_inb')]]
        await self._send(f"این‌باند {name}\nحد فعلی: {v}", self._kb(rows), chat_id=chat_id)

    async def _menu_settings(self, chat_id:str):
        cfg=self.load(self.cfg_path)
        banm=cfg.get('ban_minutes')
        rows=[[('ویرایش ban_minutes','set_edit_banmin'),('ریست سرویس','set_restart')],[('↩️ برگشت','mn_refresh')]]
        await self._send(f"تنظیمات:\nban_minutes: {banm}", self._kb(rows), chat_id=chat_id)

    async def _menu_sessions(self, chat_id:str):
        if not self.store:
            await self._send("Store در دسترس نیست.", chat_id=chat_id); return
        items = await self.store.list_active()
        self.session_cache.clear()
        rows=[]; idx=1
        for inbound,email,ips in items[:40]:
            sid=f's{idx}'; self.session_cache[sid]=(inbound,email,ips); idx+=1
            label=f"{inbound}:{email[:20]} ({len(ips)})"[:60]
            rows.append([(label, 'sess:'+sid)])
        rows.append([('↩️ برگشت','mn_refresh')])
        if not items:
            await self._send("هیچ سشنی.", self._kb([[('↩️','mn_refresh')]]), chat_id=chat_id)
        else:
            await self._send("سشن‌های فعال:", self._kb(rows), chat_id=chat_id)

    async def _menu_banned(self, chat_id:str):
        if not self.store:
            await self._send("Store در دسترس نیست.", chat_id=chat_id); return
        banned = await self.store.list_banned()
        self.banned_cache={ip:ttl for ip,ttl in banned}
        rows=[]
        for ip,ttl in banned[:40]:
            mins=max(0,int(ttl/60)) if ttl else 0
            rows.append([(f"{ip} ({mins}m)", 'unban:'+ip)])
        rows.append([('↩️ برگشت','mn_refresh')])
        if not banned:
            await self._send("لیست بن خالی است.", self._kb([[('↩️','mn_refresh')]]), chat_id=chat_id)
        else:
            await self._send("IP های بن شده (برای آنبن بزن):", self._kb(rows), chat_id=chat_id)

    async def _menu_status(self, chat_id:str):
        cfg=self.load(self.cfg_path)
        nodes=cfg.get('nodes', [])
        lines=["*وضعیت فعلی*", f"ban_minutes: *{cfg.get('ban_minutes')}*"]
        for n in nodes:
            lines.append(f"• `{n.get('name')}` → {n.get('host')}:{n.get('ssh_port')} cnt={n.get('docker_container')}")
        await self._send("\n".join(lines), self._kb([[('↩️ برگشت','mn_refresh')]]), chat_id=chat_id, parse_mode='Markdown')

    async def _post_add_node(self, node_name:str, chat_id:str):
        """Restart service then run quick SSH+container+xray checks and report Persian status."""
        try:
            # restart service (not subject to cooldown)
            await self._send("♻️ ریست سرویس برای اعمال نود جدید...", chat_id=chat_id)
            proc=await asyncio.create_subprocess_exec('sh','-lc','systemctl restart m1m-guardian || true')
            await proc.wait()
            await asyncio.sleep(5)
            cfg=self.load(self.cfg_path)
            node=self._find_node(cfg,node_name)
            if not node:
                await self._send(f"❌ نود {node_name}: پس از ریست در پیکربندی یافت نشد.", chat_id=chat_id); return
            # Basic SSH
            from .nodes import NodeSpec as _NS, _ssh_run_capture as _cap, _ssh_base as _base  # type: ignore
            spec=_NS(node.get('name'), node.get('host'), node.get('ssh_user'), node.get('ssh_port'), node.get('docker_container'), node.get('ssh_key'), node.get('ssh_pass'))
            sentinel='__M1M_OK__'
            rc,out=await _cap(_base(spec)+[f'echo {sentinel}'], timeout=10)
            if rc!=0 or sentinel.encode() not in out:
                await self._send(f"❌ نود {node_name}: SSH برقرار نشد (rc={rc}).\n{out.decode(errors='ignore')[-200:]}", chat_id=chat_id)
                return
            # Check docker container + xray process
            check_script=(
                "SUDO=; if [ \"$(id -u)\" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO=sudo; fi; fi; "
                "if ! command -v docker >/dev/null 2>&1; then echo NO_DOCKER; exit 1; fi; "
                f"C={node.get('docker_container')}; "
                "if ! $SUDO docker inspect $C >/dev/null 2>&1; then echo NO_CONTAINER; exit 2; fi; "
                "pid=$($SUDO docker exec $C sh -lc 'pgrep -xo xray || ps | grep -i \\bxray\\b | grep -v grep | awk {\"{print $1;exit}\"}'); "
                "if [ -z \"$pid\" ]; then echo NO_XRAY; exit 3; fi; echo OK:$pid;"
            )
            rc2,out2=await _cap(_base(spec)+["sh","-lc",check_script], timeout=20)
            text=out2.decode(errors='ignore').strip()
            if rc2!=0 or not text.startswith('OK:'):
                msg_map={'NO_DOCKER':'docker نصب نیست','NO_CONTAINER':'کانتینر پیدا نشد','NO_XRAY':'فرایند xray یافت نشد'}
                human=msg_map.get(text.split('\n')[0],'نامشخص')
                await self._send(f"⚠️ نود {node_name}: اتصال SSH برقرار شد اما مشکل: {human}\nجزئیات: {text[:180]}", chat_id=chat_id)
                return
            pid=text.split(':',1)[1]
            await self._send(f"✅ نود {node_name}: متصل و در حال استریم (PID={pid}).", chat_id=chat_id)
        except Exception as e:
            await self._send(f"❌ نود {node_name}: خطای داخلی تست اتصال: {e}", chat_id=chat_id)
