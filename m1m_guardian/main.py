import argparse, asyncio, logging, sys, yaml, os
from .config import load, ensure_defaults, save
from .store import Store
from .nodes import NodeSpec
from .watcher import NodeWatcher
from .notify import TelegramNotifier, TelegramBotPoller
from .log_forward import install_telegram_log_forward

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
    logging.getLogger("guardian.start").info(
        "config loaded: nodes=%d ban_minutes=%s cross_node_ban=%s",
        len(cfg.get("nodes",[])), cfg.get("ban_minutes"), cfg.get("cross_node_ban")
    )
    store = Store(cfg["redis"]["url"])
    nodes = make_nodes(cfg)
    limits = cfg.get("inbounds_limit", {})
    ban_minutes = int(cfg.get("ban_minutes",10))
    cross = bool(cfg.get("cross_node_ban", True))

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
        poller=TelegramBotPoller(tcfg.get("bot_token"), main_chat, config_path, load, save, store=store, nodes=nodes, cross_node_ban=cross, extra_admins=extra_admins)
        poller_task=asyncio.create_task(poller.start())
        # نصب فورواردر لاگ برای ارسال خطاهای نود به تلگرام
        install_telegram_log_forward(notifier, min_interval=20.0)

    if not nodes:
        logging.error("No nodes configured. Use auto.sh -> option 2 (Config menu) to add a node.")
        return

    watchers=[]
    for spec in nodes:
        logging.getLogger("guardian.start").debug("starting watcher for node=%s host=%s", spec.name, spec.host)
        watchers.append(NodeWatcher(spec, store, limits, ban_minutes, nodes, cross, notifier).run())

    logging.info("Starting %d node watchers...", len(watchers))
    await asyncio.gather(*watchers, *( [poller_task] if poller_task else [] ))

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--config", required=True)
    p.add_argument("--log-level", default=os.environ.get("M1M_GUARDIAN_LOG_LEVEL","INFO"), help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    args=p.parse_args()
    asyncio.run(amain(args.config, args.log_level))

if __name__=="__main__":
    main()
