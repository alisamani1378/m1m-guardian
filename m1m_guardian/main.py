import argparse, asyncio, logging, sys, yaml
from .config import load, ensure_defaults
from .store import Store
from .nodes import NodeSpec
from .watcher import NodeWatcher

def setup_logging():
    h = logging.StreamHandler(sys.stdout)
    fmt = logging.Formatter("[%(levelname)s] %(asctime)s %(name)s: %(message)s")
    h.setFormatter(fmt)
    root=logging.getLogger()
    root.setLevel(logging.INFO)
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

async def amain(config_path:str):
    cfg = load(config_path); ensure_defaults(cfg)
    store = Store(cfg["redis"]["url"])
    nodes = make_nodes(cfg)
    limits = cfg["inbounds_limit"]
    ban_minutes = int(cfg.get("ban_minutes",10))
    ports = list(cfg.get("ports",[8080,5540,2222]))
    cross = bool(cfg.get("cross_node_ban", True))

    if not nodes:
        logging.error("No nodes configured. Use auto.sh -> Add node.")
        return

    watchers=[]
    for spec in nodes:
        watchers.append(NodeWatcher(spec, store, limits, ban_minutes, ports, nodes, cross).run())

    logging.info("Starting %d node watchers...", len(watchers))
    await asyncio.gather(*watchers)

def main():
    setup_logging()
    p=argparse.ArgumentParser()
    p.add_argument("--config", required=True)
    args=p.parse_args()
    asyncio.run(amain(args.config))

if __name__=="__main__":
    main()
