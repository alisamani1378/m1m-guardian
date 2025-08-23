import argparse, os, yaml

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
    print("Instructions: enter inbound name to set/update limit; prefix with '-' to delete (except 'default'); enter 'done' to finish.")
    while True:
        k=prompt("Inbound name (or 'done' to finish)","done").strip()
        if k.lower()=="done": break
        if not k: continue
        if k.startswith('-'):
            target=k[1:].strip()
            if target=="default":
                print("Cannot delete 'default'.")
            elif target in cfg["inbounds_limit"]:
                del cfg["inbounds_limit"][target]
                print(f"[ok] deleted inbound limit '{target}'")
            else:
                print(f"No such inbound '{target}'")
            continue
        try:
            v_input=prompt(f"Max concurrent IPs for '{k}'", "1").strip()
            v=int(v_input)
        except ValueError:
            print("Enter an integer."); continue
        cfg["inbounds_limit"][k]=v
        print(f"[ok] set {k}={v}")
    save(path,cfg)
    print("[ok] saved limits")

def edit_node(path):
    cfg=load(path); ensure_defaults(cfg)
    if not cfg["nodes"]:
        print("No nodes."); return
    for i,n in enumerate(cfg["nodes"],1):
        print(f"{i}) {n['name']} ({n['host']})")
    try:
        idx=int(prompt("Which index to edit"))-1
    except ValueError:
        print("Bad index"); return
    if not (0<=idx<len(cfg["nodes"])): print("Bad index"); return
    node=cfg["nodes"][idx]
    def upd(key, title, cast=str):
        cur=node.get(key,"")
        val=prompt(f"{title}", cur).strip()
        if val:
            try:
                node[key]=cast(val)
            except Exception:
                print(f"Invalid value for {title}")
    upd("name","Name")
    upd("host","Host/IP")
    upd("ssh_user","SSH user")
    upd("ssh_port","SSH port", int)
    upd("docker_container","Docker container")
    if "ssh_key" in node or ("ssh_pass" not in node):
        k=prompt("SSH key path (leave blank to keep / type 'pass' to switch to password)", node.get("ssh_key",""))
        if k=="pass":
            node.pop("ssh_key", None)
            node["ssh_pass"]=prompt("SSH password")
        elif k:
            node["ssh_key"]=k; node.pop("ssh_pass", None)
    else:
        k=prompt("SSH password (leave blank to keep / type 'key' to switch to key)", "***")
        if k=="key":
            node.pop("ssh_pass", None)
            node["ssh_key"]=prompt("SSH key path","/root/.ssh/id_rsa")
        elif k and k!="***":
            node["ssh_pass"]=k
    save(path,cfg); print("[ok] node updated")


def manage_nodes(path):
    while True:
        cfg=load(path); ensure_defaults(cfg)
        print("\n=== Nodes ===")
        if not cfg["nodes"]:
            print("(none)")
        else:
            for i,n in enumerate(cfg["nodes"],1):
                auth = 'key' if 'ssh_key' in n else 'pass'
                print(f"{i}) {n['name']} {n['host']}:{n.get('ssh_port',22)} [{auth}] container={n.get('docker_container')}")
        print("n) Add  e) Edit  r) Remove  b) Back")
        c=input("> ").strip().lower()
        if c=='b': break
        elif c=='n': add_node(path)
        elif c=='e': edit_node(path)
        elif c=='r': remove_node(path)
        else: print("Bad choice")


def manage_limits(path):
    while True:
        cfg=load(path); ensure_defaults(cfg)
        print("\n=== Inbound Limits ===")
        for k,v in cfg["inbounds_limit"].items():
            print(f" - {k}: {v}")
        print("a) Add/Update  d) Delete  b) Back")
        c=input("> ").strip().lower()
        if c=='b': break
        elif c=='a':
            name=prompt("Inbound name (default if blank)", "default").strip() or "default"
            try:
                v=int(prompt("Max concurrent IPs", str(cfg["inbounds_limit"].get(name,1))).strip())
            except ValueError:
                print("Enter integer"); continue
            cfg["inbounds_limit"][name]=v; save(path,cfg); print("[ok] saved")
        elif c=='d':
            name=prompt("Inbound to delete (cannot delete default)").strip()
            if name=='default': print("Cannot delete default"); continue
            cfg["inbounds_limit"].pop(name, None); save(path,cfg); print("[ok] deleted (if existed)")
        else:
            print("Bad choice")


def interactive_menu(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    ensure_defaults(cfg:=load(path))
    save(path,cfg)
    while True:
        cfg=load(path); ensure_defaults(cfg)
        print("\n=== m1m-guardian Config Menu ===")
        print("1) Show config")
        print("2) Manage nodes")
        print("3) Manage inbound limits")
        print("0) Exit")
        c=input("> ").strip()
        if c=='0': break
        elif c=='1': show(path)
        elif c=='2': manage_nodes(path)
        elif c=='3': manage_limits(path)
        else: print("Bad choice")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--show", nargs="?", const="/etc/m1m-guardian/config.yaml")
    p.add_argument("--add-node", nargs="?", const="/etc/m1m-guardian/config.yaml")
    p.add_argument("--remove-node", nargs="?", const="/etc/m1m-guardian/config.yaml")
    p.add_argument("--edit-limits", nargs="?", const="/etc/m1m-guardian/config.yaml")
    p.add_argument("--menu", nargs="?", const="/etc/m1m-guardian/config.yaml", help="Interactive menu mode")
    args=p.parse_args()
    path = (args.show or args.add_node or args.remove_node or args.edit_limits or args.menu)
    if not path: p.error("need command")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if args.show: show(path)
    elif args.add_node: add_node(path)
    elif args.remove_node: remove_node(path)
    elif args.edit_limits: edit_limits(path)
    elif args.menu: interactive_menu(path)

if __name__=="__main__":
    main()
