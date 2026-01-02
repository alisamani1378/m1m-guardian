import argparse, asyncio, logging, sys, os
from .config import load, ensure_defaults, save
from .store import Store
from .nodes import NodeSpec
from .watcher import NodeWatcher
from .notify import TelegramNotifier, TelegramBotPoller
from .log_forward import install_telegram_log_forward
from .firewall import check_firewall_status, ensure_rule

log = logging.getLogger("guardian.main")

def setup_logging(level:str="INFO"):
    h = logging.StreamHandler(sys.stdout)
    fmt = logging.Formatter("[%(levelname)s] %(asctime)s %(name)s: %(message)s")
    h.setFormatter(fmt)
    root=logging.getLogger()
    root.handlers.clear()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.addHandler(h)

def make_nodes(cfg):
    nodes=[]
    for n in cfg.get("nodes",[]):
        nodes.append(NodeSpec(
            name=n["name"], host=n["host"], ssh_user=n.get("ssh_user","root"),
            ssh_port=int(n.get("ssh_port",22)),
            docker_container=n.get("docker_container","marzban-node"),
            ssh_key=n.get("ssh_key"), ssh_pass=n.get("ssh_pass")
        ))
    return nodes

async def amain(config_path:str, log_level:str):
    setup_logging(log_level)
    cfg = load(config_path); ensure_defaults(cfg)
    log.info(
        "config loaded: nodes=%d ban_minutes=%s",
        len(cfg.get("nodes",[])), cfg.get("ban_minutes")
    )
    store = Store(cfg["redis"]["url"])

    # Test Redis connection at startup
    try:
        await store.ping()
        log.info("redis connection: OK")
    except Exception as e:
        log.error("redis connection FAILED: %s - banning will not work!", e)

    nodes = make_nodes(cfg)
    limits = cfg.get("inbounds_limit", {})
    ban_minutes = int(cfg.get("ban_minutes",10))

    notifier = None
    tcfg = cfg.get("telegram", {})
    poller_task=None
    if tcfg.get("bot_token") and (tcfg.get("chat_id") or tcfg.get("admins")):
        # support multiple admins: union of chat_id + admins list
        extra_admins = []
        if isinstance(tcfg.get("admins"), list):
            extra_admins = [str(a) for a in tcfg.get("admins") if a]
        main_chat = tcfg.get("chat_id") or (extra_admins[0] if extra_admins else None)
        notifier = TelegramNotifier(tcfg.get("bot_token"), main_chat)
        await notifier.delete_webhook()
        try:
            await notifier.send("m1m-guardian شروع شد ✅")
        except Exception:
            pass
        poller=TelegramBotPoller(tcfg.get("bot_token"), main_chat, config_path, load, save, store=store, nodes=nodes, extra_admins=extra_admins)
        poller_task=asyncio.create_task(poller.start())
        # نصب فورواردر لاگ برای ارسال خطاهای نود به تلگرام
        install_telegram_log_forward(notifier, min_interval=20.0)

    if not nodes:
        log.error("No nodes configured. Use auto.sh -> option 2 (Config menu) to add a node.")
        return

    # Auto check and fix firewall on all nodes at startup
    log.info("Checking firewall status on %d nodes...", len(nodes))
    firewall_results = []
    for spec in nodes:
        try:
            status = await check_firewall_status(spec)
            if status['ok']:
                log.info("firewall OK node=%s backend=%s", spec.name, status['backend'])
                firewall_results.append((spec.name, True, None))
            else:
                log.warning("firewall NOT OK node=%s, attempting auto-fix...", spec.name)
                try:
                    await ensure_rule(spec, force=True)
                    # Re-check after fix
                    status2 = await check_firewall_status(spec)
                    if status2['ok']:
                        log.info("firewall FIXED node=%s", spec.name)
                        firewall_results.append((spec.name, True, "auto-fixed"))
                    else:
                        log.error("firewall FIX FAILED node=%s", spec.name)
                        firewall_results.append((spec.name, False, "fix failed"))
                except Exception as e:
                    log.error("firewall fix error node=%s err=%s", spec.name, e)
                    firewall_results.append((spec.name, False, str(e)))
        except Exception as e:
            log.error("firewall check error node=%s err=%s", spec.name, e)
            firewall_results.append((spec.name, False, str(e)))

    # Send firewall status summary to Telegram
    if notifier:
        ok_count = sum(1 for _, ok, _ in firewall_results if ok)
        fail_count = len(firewall_results) - ok_count
        if fail_count > 0:
            lines = ["⚠️ *وضعیت فایروال:*"]
            for name, ok, note in firewall_results:
                status_icon = "✅" if ok else "❌"
                line = f"{status_icon} {name}"
                if note:
                    line += f" ({note})"
                lines.append(line)
            try:
                await notifier.send("\n".join(lines))
            except Exception:
                pass
        else:
            log.info("All %d nodes have firewall OK", ok_count)

    watchers=[]
    for spec in nodes:
        log.debug("starting watcher for node=%s host=%s", spec.name, spec.host)
        watchers.append(NodeWatcher(spec, store, limits, ban_minutes, nodes, notifier).run())

    log.info("Starting %d node watchers...", len(watchers))
    await asyncio.gather(*watchers, *( [poller_task] if poller_task else [] ))

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--config", required=True)
    p.add_argument("--log-level", default=os.environ.get("M1M_GUARDIAN_LOG_LEVEL","INFO"), help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    args=p.parse_args()
    asyncio.run(amain(args.config, args.log_level))

if __name__=="__main__":
    main()
