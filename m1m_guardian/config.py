import argparse, os, sys, yaml

def load(path:str)->dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def save(path:str, data:dict):
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False)

def ensure_defaults(cfg:dict):
    cfg.setdefault("redis", {"url":"redis://127.0.0.1:6379/0"})
    cfg.setdefault("ban_minutes", 10)
    cfg.setdefault("cross_node_ban", True)
    cfg.setdefault("ports", [8080,5540,2222])
    cfg.setdefault("inbounds_limit", {"default":1})
    cfg.setdefault("nodes", [])

def show(path):
    cfg=load(path); ensure_defaults(cfg)
    print("=== Config ===")
    print(yaml.safe_dump(cfg, sort_keys=False))

def prompt(inp:str, default=None):
    s=input(f"{inp}{f' [{default}]' if default is not None else ''}: ").strip()
    return s or (default if default is not None else "")

def add_node(path):
    cfg=load(path); ensure_defaults(cfg)
    node={
        "name": prompt("Node name"),
        "host": prompt("Host/IP"),
        "ssh_user": prompt("SSH user", "root"),
        "ssh_port": int(prompt("SSH port", "22")),
        "docker_container": prompt("Docker container name", "marzban-node")
    }
    mode=prompt("Auth mode (key/pass)", "key")
    if mode.lower().startswith("k"):
        node["ssh_key"]=prompt("Path to private key", "/root/.ssh/id_rsa")
    else:
        node["ssh_pass"]=prompt("SSH password")
    cfg["nodes"].append(node)
    save(path,cfg)
    print(f"[ok] added: {node['name']}")

def remove_node(path):
    cfg=load(path); ensure_defaults(cfg)
    if not cfg["nodes"]:
        print("No nodes configured."); return
    for i,n in enumerate(cfg["nodes"],1):
        print(f"{i}) {n['name']} ({n['host']})")
    idx=int(prompt("Which index to remove"))-1
    if 0<=idx<len(cfg["nodes"]):
        n=cfg["nodes"].pop(idx)
        save(path,cfg)
        print(f"[ok] removed: {n['name']}")
    else:
        print("Bad index")

def edit_limits(path):
    cfg=load(path); ensure_defaults(cfg)
    print("Current inbound limits:", cfg["inbounds_limit"])
    while True:
        k=prompt("Inbound name (or 'done' to finish)","done")
        if k.lower()=="done": break
        v=int(prompt(f"Max concurrent IPs for '{k}'", "1"))
        cfg["inbounds_limit"][k]=v
    save(path,cfg)
    print("[ok] saved limits")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--show", nargs="?", const="/etc/m1m-guardian/config.yaml")
    p.add_argument("--add-node", nargs="?", const="/etc/m1m-guardian/config.yaml")
    p.add_argument("--remove-node", nargs="?", const="/etc/m1m-guardian/config.yaml")
    p.add_argument("--edit-limits", nargs="?", const="/etc/m1m-guardian/config.yaml")
    args=p.parse_args()
    path = (args.show or args.add_node or args.remove_node or args.edit_limits)
    if not path: p.error("need command")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if args.show: show(path)
    elif args.add_node: add_node(path)
    elif args.remove_node: remove_node(path)
    elif args.edit_limits: edit_limits(path)

if __name__=="__main__":
    main()
