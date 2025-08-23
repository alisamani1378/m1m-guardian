import argparse, asyncio, logging, sys, yaml, os
from .config import load, ensure_defaults
from .store import Store
from .nodes import NodeSpec
from .watcher import NodeWatcher

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
        "config loaded: nodes=%d ports=%s fallback_limit=%s cross_node_ban=%s ban_minutes=%s",
        len(cfg.get("nodes",[])), cfg.get("ports"), cfg.get("fallback_limit"), cfg.get("cross_node_ban"), cfg.get("ban_minutes")
    )
    store = Store(cfg["redis"]["url"])
    nodes = make_nodes(cfg)
    limits = cfg["inbounds_limit"]
    fallback = int(cfg.get("fallback_limit", 1))
    ban_minutes = int(cfg.get("ban_minutes",10))
    ports = list(cfg.get("ports",[8080,5540,2222]))
    cross = bool(cfg.get("cross_node_ban", True))

    if not nodes:
        logging.error("No nodes configured. Use auto.sh -> option 2 (Config menu) to add a node.")
        return

    watchers=[]
    for spec in nodes:
        logging.getLogger("guardian.start").debug("starting watcher for node=%s host=%s ports=%s", spec.name, spec.host, ports)
        watchers.append(NodeWatcher(spec, store, limits, ban_minutes, ports, nodes, cross, fallback).run())

    logging.info("Starting %d node watchers...", len(watchers))
    await asyncio.gather(*watchers)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--config", required=True)
    p.add_argument("--log-level", default=os.environ.get("M1M_GUARDIAN_LOG_LEVEL","INFO"), help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    args=p.parse_args()
    asyncio.run(amain(args.config, args.log_level))

if __name__=="__main__":
    main()
