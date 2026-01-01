import asyncio, json, logging, urllib.request, urllib.parse
import os, time
from typing import List, Dict, Tuple
from .firewall import unban_ip, ensure_rule  # added ensure_rule for fix firewall
from .nodes import NodeSpec, run_ssh
from .config import ensure_defaults  # added

log = logging.getLogger("guardian.notify")

class TelegramNotifier:
    def __init__(self, bot_token:str|None, chat_id:str|None, enabled:bool=True):
        self.bot_token = (bot_token or '').strip()
        self.chat_id = (chat_id or '').strip()
        self.enabled = enabled and bool(self.bot_token and self.chat_id)
        if not self.enabled:
            log.debug("Telegram notifier disabled (missing token/chat_id)")

    def _needs_plain(self, text:str)->bool:
        """Return True if we should disable Markdown to avoid 400 Bad Request.
        Heuristic: if text contains markdown special chars but no backticks and no asterisks balanced.
        """
        if not text: return False
        # If already using code fences/backticks assume safe.
        if '`' in text: return False
        # Raw guardian / system lines often contain underscores / square brackets.
        specials = ['_', '*', '[', ']', '(', ')']
        if any(s in text for s in specials):
            return True
        return False

    def _prepare(self, text:str, parse_mode:str|None):
        # If parse_mode requested but heuristic says plain, drop parse_mode
        if parse_mode and self._needs_plain(text):
            return None
        return parse_mode

    async def send(self, text:str, parse_mode:str|None='Markdown'):
        if not self.enabled: return
        pm = self._prepare(text, parse_mode)
        payload={ 'chat_id': self.chat_id, 'text': text[:4000], 'disable_web_page_preview':'true'}
        if pm: payload['parse_mode']=pm
        await asyncio.to_thread(self._post, payload)

    async def send_with_inline(self, text:str, buttons:list[list[tuple[str,str]]], parse_mode:str|None='Markdown'):
        """buttons: list of rows; each row list of (label, callback_data)."""
        if not self.enabled: return
        pm = self._prepare(text, parse_mode)
        markup={"inline_keyboard": [[{"text": b[0], "callback_data": b[1]} for b in row] for row in buttons]}
        payload={ 'chat_id': self.chat_id, 'text': text[:4000], 'reply_markup': json.dumps(markup), 'disable_web_page_preview':'true'}
        if pm: payload['parse_mode']=pm
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
        self._last_update_ts=0.0  # cooldown for update
        # NEW: per-node reboot cooldown tracking
        self._last_node_reboot:dict[str,float]={}
        # pagination state (optional)
        self._banned_page:Dict[str,int]={}

    # NEW: offset persistence helpers
    def _load_offset(self):
        try:
            if self.offset_file and os.path.exists(self.offset_file):
                with open(self.offset_file, 'r', encoding='utf-8') as f:
                    content = (f.read() or '').strip()
                    if content:
                        try:
                            self.offset = int(content)
                        except Exception:
                            # corrupt file; reset
                            self.offset = 0
        except Exception as e:
            log.debug("load offset failed: %s", e)
            # keep default offset=0

    def _save_offset(self):
        try:
            # best-effort; avoid raising inside polling loop
            with open(self.offset_file, 'w', encoding='utf-8') as f:
                f.write(str(int(self.offset)))
        except Exception as e:
            log.debug("save offset failed: %s", e)

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
        try:
            await asyncio.to_thread(self._api_post,'sendMessage', data)
        except Exception as e:
            # Downgrade to plain text and retry once (Markdown errors etc.)
            try:
                if parse_mode:
                    data.pop('parse_mode', None)
                    await asyncio.to_thread(self._api_post,'sendMessage', data)
                else:
                    logging.getLogger('guardian.notify').debug("telegram send fail final: %s", e)
            except Exception:
                logging.getLogger('guardian.notify').debug("telegram send retry failed: %s", e)

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
            [("🆕 آپدیت","set_update")],
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
        ensure_defaults(cfg)  # ensure structure
        try:
            if kind=='edit_node_field':
                node_name=st['node']; field=st['field']
                node=self._find_node(cfg,node_name)
                if not node:
                    await self._send("نود یافت نشد", chat_id=chat_id)
                else:
                    if field=='ssh_port':
                        try: node[field]=int(text)
                        except:
                            await self._send("پورت نامعتبر", chat_id=chat_id); self.state.pop(chat_id,None); return
                    else:
                        # auth field logic: ensure only one of ssh_pass / ssh_key kept
                        if field=='ssh_pass':
                            node.pop('ssh_key', None)
                        if field=='ssh_key':
                            node.pop('ssh_pass', None)
                        node[field]=text
                    self.save(self.cfg_path,cfg)
                    await self._send(f"بروزرسانی شد: {node_name}.{field}", chat_id=chat_id)
                self.state.pop(chat_id,None)
                await self._show_node(node_name, chat_id)
            elif kind=='edit_node_keytext':
                node_name=st['node']
                node=self._find_node(cfg,node_name)
                if not node:
                    await self._send("نود یافت نشد", chat_id=chat_id)
                else:
                    try:
                        keys_dir='/etc/m1m-guardian/keys'
                        os.makedirs(keys_dir, exist_ok=True)
                        fname=os.path.join(keys_dir, f"{node_name}.key")
                        with open(fname,'w',encoding='utf-8') as f:
                            f.write(text.strip()+('\n' if not text.endswith('\n') else ''))
                        try: os.chmod(fname,0o600)
                        except Exception: pass
                        node.pop('ssh_pass', None)
                        node['ssh_key']=fname
                        self.save(self.cfg_path,cfg)
                        await self._send(f"کلید جدید برای {node_name} ذخیره شد.", chat_id=chat_id)
                    except Exception as e:
                        await self._send(f"خطا در ذخیره کلید: {e}", chat_id=chat_id)
                self.state.pop(chat_id,None)
                await self._show_node(node_name, chat_id)
            elif kind=='set_inbound_limit':
                name=st['inbound']
                try: v=int(text)
                except: await self._send("عدد نامعتبر", chat_id=chat_id); return
                if not isinstance(cfg.get('inbounds_limit'), dict):
                    cfg['inbounds_limit']={}
                cfg['inbounds_limit'][name]=v; self.save(self.cfg_path,cfg)
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
                if not isinstance(cfg.get('inbounds_limit'), dict):
                    cfg['inbounds_limit']={}
                cfg['inbounds_limit'][name]=v; self.save(self.cfg_path,cfg)
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
                            # removed inner 'import os, stat' to avoid overshadowing global os
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
            logging.getLogger('guardian.notify').debug("state input error: %s", e)
            self.state.pop(chat_id,None)
            # show short error to user (avoid leaking long traces)
            await self._send(f"خطا در پردازش ورودی: {type(e).__name__}", chat_id=chat_id)

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
            self._banned_page[chat_id]=0
            await self._menu_banned(chat_id, page=0); return
        if data=='set_update':
            await self._update_service(chat_id); return
        # pagination for banned
        if data.startswith('bannedpage:'):
            try:
                page=int(data.split(':',1)[1])
            except Exception:
                page=0
            self._banned_page[chat_id]=max(0,page)
            await self._menu_banned(chat_id, page=self._banned_page[chat_id]); return
        if data=='unbanall':
            await self._send("آیا همه IP های بن شده آن‌بن شوند؟", self._kb([[('✅ بله','unbanallconfirm'),('↩️ برگشت','mn_banned')]]), chat_id=chat_id)
            return
        if data=='unbanallconfirm':
            await self._perform_unban_all(chat_id); return
        # node menu
        if data=='nodes_add':
            self.state[chat_id]={'kind':'add_node_step','step':0}
            await self._send("نام نود جدید را وارد کن:", chat_id=chat_id)
            return
        if data.startswith('node:'):
            name=data.split(':',1)[1]
            await self._show_node(name, chat_id); return
        # NEW: fix firewall callbacks
        if data.startswith('nodefixfw:'):
            name=data.split(':',1)[1]
            await self._perform_fix_firewall(name, chat_id); return
        # NEW: node reboot callbacks
        if data.startswith('noderebootconfirm:'):
            name=data.split(':',1)[1]
            await self._perform_node_reboot(name, chat_id); return
        if data.startswith('nodereboot:'):
            name=data.split(':',1)[1]
            await self._send(f"ریبوت نود {name} انجام شود؟", self._kb([[('✅ بله','noderebootconfirm:'+name),('↩️ برگشت','node:'+name)]]), chat_id=chat_id)
            return
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
        if data.startswith('nodeauthkeytext:'):
            name=data.split(':',1)[1]
            self.state[chat_id]={'kind':'edit_node_keytext','node':name}
            await self._send(f"متن کامل کلید خصوصی جدید برای {name} را بفرست (با -----BEGIN شروع):", chat_id=chat_id)
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
        # NEW: immediate unban without confirmation (used by inline button under ban report)
        if data.startswith('unban_now:'):
            ip=data.split(':',1)[1]
            await self._perform_unban(ip, chat_id)
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

    async def _perform_unban_all(self, chat_id:str):
        if not self.store:
            await self._send("Store در دسترس نیست.", chat_id=chat_id); return
        await self._send("🧹 درحال آن‌بن همه IP ها و پاکسازی ست‌ها...", chat_id=chat_id)
        deleted=0
        try:
            deleted = await self.store.unmark_all_banned()
        except Exception as e:
            log.debug("unmark_all_banned error: %s", e)
        # flush sets on all nodes (best-effort)
        async def _flush_node(n:NodeSpec):
            try:
                script=(
                    "SUDO=; if [ \"$(id -u)\" != 0 ]; then if command -v sudo >/dev/null 2>&1; then SUDO=sudo; fi; fi; "
                    "$SUDO ipset flush m1m_guardian 2>/dev/null || true; "
                    "$SUDO ipset flush m1m_guardian6 2>/dev/null || true; "
                    "$SUDO nft list set inet filter m1m_guardian >/dev/null 2>&1 && $SUDO nft flush set inet filter m1m_guardian || true; "
                    "$SUDO nft list set inet filter m1m_guardian6 >/dev/null 2>&1 && $SUDO nft flush set inet filter m1m_guardian6 || true; "
                    "true"
                )
                await run_ssh(n, script)
            except Exception as e:
                log.debug("flush node error %s: %s", n.name, e)
        if self.nodes:
            await asyncio.gather(*[_flush_node(n) for n in self.nodes])
        # clear cache and show page 0
        self.banned_cache.clear(); self._banned_page[chat_id]=0
        await self._send(f"✅ {deleted} کلید از Redis حذف شد و ست‌ها پاکسازی شدند.", chat_id=chat_id)
        await self._menu_banned(chat_id, page=0)

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
            [('AuthKeyText','nodeauthkeytext:'+name)],
            [('🔥 فیکس فایروال','nodefixfw:'+name)],  # NEW fix firewall button
            [('♻️ ریبوت','nodereboot:'+name)],  # NEW reboot button
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

    async def _menu_banned(self, chat_id:str, page:int=0):
        if not self.store:
            await self._send("Store در دسترس نیست.", chat_id=chat_id); return
        banned = await self.store.list_banned(limit=1000)
        total=len(banned); page_size=20
        max_page = (total-1)//page_size if total>0 else 0
        page = min(max(0,page), max_page)
        start=page*page_size; end=min(total, start+page_size)
        self.banned_cache={ip:ttl for ip,ttl in banned[start:end]}
        rows=[]
        for ip,ttl in banned[start:end]:
            mins=max(0,int((ttl or 0)/60))
            rows.append([(f"{ip} ({mins}m)", 'unban:'+ip)])
        nav=[]
        if page>0:
            nav.append(('⬅️ قبلی', f'bannedpage:{page-1}'))
        if end<total:
            nav.append(('بعدی ➡️', f'bannedpage:{page+1}'))
        if nav:
            rows.append(nav)
        rows.append([('🧹 آن‌بن همه','unbanall'),('↩️ برگشت','mn_refresh')])
        title=f"IP های بن شده (صفحه {page+1}/{max_page+1}, کل {total})"
        if total==0:
            await self._send("لیست بن خالی است.", self._kb([[('↩️','mn_refresh')]]), chat_id=chat_id)
        else:
            await self._send(title, self._kb(rows), chat_id=chat_id)

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

    async def _update_service(self, chat_id:str):
        """Git pull + pip install editable + restart service, with cooldown."""
        now=time.time()
        if now - self._last_update_ts < 120:  # 2 min cooldown
            await self._send("⏳ اخیراً آپدیت اجرا شده؛ کمی بعد دوباره تلاش کن.", chat_id=chat_id)
            return
        self._last_update_ts=now
        await self._send("🆕 درحال آپدیت پروژه...", chat_id=chat_id)
        script=(
            "set -e; cd /opt/m1m-guardian; "
            "echo '[1/5] git fetch' ; git fetch --all --prune >/dev/null 2>&1 || echo 'git fetch failed'; "
            "echo '[2/5] git reset' ; git reset --hard origin/main 2>&1; "
            "echo '[3/5] pip install' ; /opt/m1m-guardian/.venv/bin/pip install -U -e . 2>&1 || true; "
            "echo '[4/5] restart service' ; systemctl restart m1m-guardian 2>&1 || true; "
            "echo '[5/5] current commit:'; git rev-parse --short HEAD || true"
        )
        try:
            proc=await asyncio.create_subprocess_exec('bash','-lc',script, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            out, _=await proc.communicate()
            text=out.decode(errors='ignore')
            import re
            m=re.findall(r"[0-9a-f]{7,10}", text)
            commit=m[-1] if m else 'unknown'
            status = '✅ آپدیت شد' if proc.returncode==0 else f"⚠️ کد خروج {proc.returncode}"
            trimmed='\n'.join([l for l in text.strip().split('\n') if l][:25])
            msg = f"{status}\nCommit: `{commit}`\n```\n{trimmed}\n```"
            await self._send(msg, chat_id=chat_id, parse_mode='Markdown')
        except Exception as e:
            await self._send(f"❌ خطا در آپدیت: {e}", chat_id=chat_id)

    # NEW: simple service restart handler used by menu
    async def _restart_service(self, chat_id:str):
        try:
            await self._send("♻️ ریست سرویس در حال انجام...", chat_id=chat_id)
            # Using sh -lc for portability with the rest of the file
            proc = await asyncio.create_subprocess_exec('sh','-lc','systemctl restart m1m-guardian || true')
            await proc.wait()
            # After restart the current process may be terminated by systemd; message may not be delivered.
        except Exception as e:
            await self._send(f"❌ خطا در ریست سرویس: {e}", chat_id=chat_id)

    async def _perform_node_reboot(self, name:str, chat_id:str):
        """Perform a reboot on a specific node via SSH with cooldown."""
        COOLDOWN=300  # 5 minutes
        now=time.time()
        last=self._last_node_reboot.get(name,0)
        if now - last < COOLDOWN:
            remain=int(COOLDOWN-(now-last))
            await self._send(f"⏳ ریبوت اخیر انجام شده. {remain}s دیگر دوباره تلاش کن.", chat_id=chat_id)
            return
        cfg=self.load(self.cfg_path)
        node=self._find_node(cfg,name)
        if not node:
            await self._send("نود یافت نشد.", chat_id=chat_id); return
        self._last_node_reboot[name]=now
        await self._send(f"ارسال فرمان ریبوت به {name}...", chat_id=chat_id)
        async def _do():
            try:
                spec=NodeSpec(node.get('name'), node.get('host'), node.get('ssh_user'), node.get('ssh_port'), node.get('docker_container'), node.get('ssh_key'), node.get('ssh_pass'))
                # Use a broad command list; SSH will likely drop connection, so rc may be non-zero.
                cmd="sudo -n reboot || sudo -n /sbin/reboot || sudo -n systemctl reboot || sudo -n shutdown -r now || reboot || /sbin/reboot || systemctl reboot || shutdown -r now"
                rc=await run_ssh(spec, cmd)
                if rc==0:
                    await self._send(f"✅ فرمان ریبوت ارسال شد به {name}.", chat_id=chat_id)
                else:
                    # Even non-zero could mean connection dropped due to reboot; treat rc>0 as uncertain
                    await self._send(f"⚠️ نتیجه نامشخص (rc={rc}) شاید در حال ریبوت باشد {name}.", chat_id=chat_id)
            except Exception as e:
                await self._send(f"❌ خطا در ریبوت {name}: {e}", chat_id=chat_id)
        asyncio.create_task(_do())

    async def _perform_fix_firewall(self, name:str, chat_id:str):
        """Fix firewall rules on a specific node - creates ipset and iptables rules."""
        cfg=self.load(self.cfg_path)
        node=self._find_node(cfg,name)
        if not node:
            await self._send("نود یافت نشد.", chat_id=chat_id); return
        
        await self._send(f"🔧 در حال فیکس فایروال روی {name}...", chat_id=chat_id)
        
        async def _do():
            try:
                spec=NodeSpec(node.get('name'), node.get('host'), node.get('ssh_user'), node.get('ssh_port'), node.get('docker_container'), node.get('ssh_key'), node.get('ssh_pass'))
                
                # Clear cache to force re-run
                from .firewall import _RULE_ENSURED
                key = f"{spec.host}:{spec.ssh_port}"
                _RULE_ENSURED.discard(key)
                
                # Run ensure_rule with force=True
                await ensure_rule(spec, force=True)
                
                # Check if it was added to cache (meaning success)
                if key in _RULE_ENSURED:
                    await self._send(f"✅ فایروال نود {name} با موفقیت فیکس شد!\n\n"
                                    f"• ipset ساخته شد\n"
                                    f"• قوانین iptables اضافه شد", chat_id=chat_id)
                else:
                    await self._send(f"⚠️ فیکس فایروال {name} ناموفق بود.\n"
                                    f"لاگ رو چک کن:\n"
                                    f"`journalctl -u m1m-guardian | tail -50`", chat_id=chat_id)
            except Exception as e:
                await self._send(f"❌ خطا در فیکس فایروال {name}: {e}", chat_id=chat_id)
        
        asyncio.create_task(_do())

