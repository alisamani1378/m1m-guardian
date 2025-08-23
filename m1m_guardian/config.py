import argparse, os, yaml, sys

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
    cfg.setdefault("rejected_threshold", 8)  # new: how many rejected/invalid before ban
    if "ports" not in cfg or cfg["ports"] in (None, ""):
        cfg["ports"] = []  # empty list means no conntrack flush
    if isinstance(cfg.get("ports"), int):
        cfg["ports"]=[cfg["ports"]]
    cfg.setdefault("inbounds_limit", {})
    if not isinstance(cfg.get("nodes"), list):
        cfg["nodes"]=[]
    cfg.setdefault("nodes", [])

def show(path):
    cfg=load(path); ensure_defaults(cfg)
    print("=== Config ===")
    print(yaml.safe_dump(cfg, sort_keys=False))

def prompt(inp:str, default=None):
    s=input(f"{inp}{f' [{default}]' if default is not None else ''}: ").strip()
    return s or (default if default is not None else "")

def _safe_filename(name:str)->str:
    import re
    return re.sub(r"[^A-Za-z0-9_.-]","_", name)[:60] or "node"

def _read_multiline_key()->str:
    print("Paste private key (ends automatically after a line containing 'END PRIVATE KEY'). Ctrl+D (Linux) or Ctrl+Z Enter (Windows) to finish if needed.")
    lines=[]
    while True:
        try:
            line=sys.stdin.readline()
        except KeyboardInterrupt:
            print("\n[cancelled]"); return ""
        if not line: # EOF
            break
        lines.append(line.rstrip("\n"))
        if "END" in line and "PRIVATE KEY" in line:
            break
        # safety cap
        if len(lines) > 500:
            print("[warn] key too large, stopping read."); break
    key="\n".join(lines).strip()
    if not key:
        print("[warn] empty key input.")
    return key

def _store_key_content(base_dir:str, node_name:str, key_content:str)->str:
    os.makedirs(os.path.join(base_dir, "keys"), exist_ok=True)
    fname=_safe_filename(node_name)+".key"
    path=os.path.join(base_dir, "keys", fname)
    with open(path, "w", encoding="utf-8") as f:
        f.write(key_content+("\n" if not key_content.endswith("\n") else ""))
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    print(f"[ok] stored key at {path} (chmod 600)")
    return path

def add_node(path):
    cfg=load(path); ensure_defaults(cfg)
    node={
        "name": prompt("Node name"),
        "host": prompt("Host/IP"),
        "ssh_user": prompt("SSH user", "root"),
        "ssh_port": int(prompt("SSH port", "22")),
        "docker_container": prompt("Docker container name", "marzban-node")
    }
    # Auth selection menu
    while True:
        print("Auth method: 1) Key path  2) Paste key  3) Password")
        choice=prompt("Select (1/2/3)", "1").strip()
        if choice == '1':
            node["ssh_key"]=prompt("Path to private key", "/root/.ssh/id_rsa")
            break
        elif choice == '2':
            key_content=_read_multiline_key()
            if key_content:
                key_path=_store_key_content(os.path.dirname(path) or "/etc/m1m-guardian", node["name"], key_content)
                node["ssh_key"]=key_path
                break
            else:
                print("Empty key, try again.")
        elif choice == '3':
            node["ssh_pass"]=prompt("SSH password")
            break
        else:
            print("Bad choice")
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
    # Auto-migrate legacy default each call
    if "default" in cfg["inbounds_limit"]:
        cfg["fallback_limit"] = int(cfg["inbounds_limit"]["default"]) if "fallback_limit" not in cfg else cfg["fallback_limit"]
        del cfg["inbounds_limit"]["default"]
        save(path,cfg)
    print("Current inbound limits:", cfg["inbounds_limit"])
    print("Instructions: a) add/update inbound, d) delete inbound, done to finish.")
    while True:
        k=prompt("Action (a/d/done)","done").strip().lower()
        if k=="done": break
        if k=="a":
            name=prompt("Inbound name").strip()
            if not name: continue
            try:
                v=int(prompt(f"Max concurrent IPs for '{name}'", str(cfg["inbounds_limit"].get(name,1))))
            except ValueError:
                print("Enter integer"); continue
            cfg["inbounds_limit"][name]=v
            print(f"[ok] set {name}={v}")
        elif k=="d":
            name=prompt("Inbound to delete").strip()
            if not name: continue
            if name in cfg["inbounds_limit"]:
                del cfg["inbounds_limit"][name]; print(f"[ok] deleted {name}")
            else:
                print("No such inbound")
        else:
            print("Bad choice")
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
    print("Change auth? 1) keep  2) key path  3) paste key  4) password")
    choice=prompt("Select", "1")
    if choice=='2':
        node.pop("ssh_pass", None)
        node["ssh_key"]=prompt("Path to private key", node.get("ssh_key","/root/.ssh/id_rsa"))
    elif choice=='3':
        node.pop("ssh_pass", None)
        key_content=_read_multiline_key()
        if key_content:
            key_path=_store_key_content(os.path.dirname(path) or "/etc/m1m-guardian", node["name"], key_content)
            node["ssh_key"]=key_path
    elif choice=='4':
        node.pop("ssh_key", None)
        node["ssh_pass"]=prompt("SSH password")
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
        print("\n=== Inbound Limits (only these are enforced) ===")
        if not cfg["inbounds_limit"]:
            print("(none defined)")
        else:
            for k,v in cfg["inbounds_limit"].items():
                print(f" - {k}: {v}")
        print("a) Add/Update  d) Delete  b) Back")
        c=input("> ").strip().lower()
        if c=='b': break
        elif c=='a':
            name=prompt("Inbound name").strip()
            if not name: continue
            try:
                v=int(prompt("Max concurrent IPs", str(cfg["inbounds_limit"].get(name,1))))
            except ValueError:
                print("Enter integer"); continue
            cfg["inbounds_limit"][name]=v; save(path,cfg); print("[ok] saved")
        elif c=='d':
            name=prompt("Inbound to delete").strip()
            if name in cfg["inbounds_limit"]:
                cfg["inbounds_limit"].pop(name, None); save(path,cfg); print("[ok] deleted")
            else:
                print("No such inbound")
        else: print("Bad choice")


def manage_ports(path):
    while True:
        cfg=load(path); ensure_defaults(cfg)
        cur=cfg.get("ports", [])
        print("\n=== Conntrack Flush Ports ===")
        print("Current:", cur)
        print("Modes: 1) Flush ALL ('*')  2) Custom list  3) Disable flush  b) Back")
        c=input("> ").strip().lower()
        if c=='b': break
        elif c=='1':
            cfg['ports']=["*"]
            save(path,cfg); print("[ok] set to all ports (*).")
        elif c=='2':
            raw=prompt("Enter ports (comma/space separated)").replace(',', ' ')
            ports=[]
            for token in raw.split():
                if token.isdigit():
                    p=int(token)
                    if 1<=p<=65535: ports.append(p)
            if not ports:
                print("No valid ports parsed.")
            else:
                cfg['ports']=ports; save(path,cfg); print(f"[ok] set ports={ports}")
        elif c=='3':
            cfg['ports']=[]; save(path,cfg); print("[ok] disabled conntrack flush (existing connections linger).")
        else:
            print("Bad choice")


def interactive_menu(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    ensure_defaults(cfg:=load(path))
    save(path,cfg)
    while True:
        cfg=load(path); ensure_defaults(cfg)
        print("\n=== m1m-guardian Config Menu ===")
        print(f"Ports: {cfg.get('ports')}  (Only defined inbounds are enforced)  rejected_threshold={cfg.get('rejected_threshold')}")
        print("1) Show config")
        print("2) Manage nodes")
        print("3) Manage inbound limits")
        print("4) Manage ports (conntrack flush)")
        print("0) Exit")
        c=input("> ").strip()
        if c=='0': break
        elif c=='1': show(path)
        elif c=='2': manage_nodes(path)
        elif c=='3': manage_limits(path)
        elif c=='4': manage_ports(path)
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
