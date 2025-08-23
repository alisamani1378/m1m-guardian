# m1m-guardian

Xray multi-IP guardian: monitors Xray node logs (inside a docker container) and bans IPs that exceed configured per-inbound concurrent IP limits. Optionally performs cross-node bans.

## Features
- Tracks active IPs per (inbound, user email)
- Enforces configurable concurrent IP limits (per inbound + global fallback)
- Bans evicted (old) IPs for configurable minutes using ipset + iptables
- Optional cross-node ban propagation
- Interactive TUI-style config menu (nodes + limits)
- Supports SSH auth: key path, pasted private key (auto-saved 0600), or password
- Simple YAML config stored at `/etc/m1m-guardian/config.yaml`
- Redis for state

## Install (manual)
```bash
python -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -e .
```

## CLI Entrypoints
- `m1m-guardian --config /etc/m1m-guardian/config.yaml` : Run guardian watchers (systemd uses module form `python -m m1m_guardian.agent`).
- `m1m-guardian-config --menu /etc/m1m-guardian/config.yaml` : Interactive menu (manage nodes & limits, fallback limit).
- `m1m-guardian-config --show /etc/m1m-guardian/config.yaml` : Show config
- `m1m-guardian-config --add-node /etc/m1m-guardian/config.yaml` : Add node (non-interactive)
- `m1m-guardian-config --remove-node /etc/m1m-guardian/config.yaml` : Remove node
- `m1m-guardian-config --edit-limits /etc/m1m-guardian/config.yaml` : Legacy limits editor (still works)

## Systemd
`auto.sh` will:
1. Install OS deps (apt/yum)
2. Clone/update repo into `/opt/m1m-guardian`
3. Create venv & install requirements + editable package
4. Install systemd unit `m1m-guardian.service`
5. Show current config.

After install you can re-run `auto.sh` and choose option 2 to open the interactive config menu.

## Configuration
See `config.example.yaml` for defaults. Keys:
- `redis.url`: Redis connection URL
- `ban_minutes`: Ban duration (minutes)
- `cross_node_ban`: true/false for propagating bans
- `ports`: List of service ports whose conntrack entries are purged on ban
- `fallback_limit`: Global default max concurrent IPs when an inbound has no explicit entry
- `inbounds_limit`: (Optional) Map of inbound -> limit (can be empty)
- `nodes`: List of node objects:
  - `name`, `host`, `ssh_user`, `ssh_port`, `docker_container`
  - One of: `ssh_key` (path) OR `ssh_pass`
  - Pasted keys are stored under `/etc/m1m-guardian/keys/<node>.key` with chmod 600

## SSH Key Paste Mode
When adding/editing a node choose option 2 (Paste key). Paste until the line containing `END PRIVATE KEY` (auto-stop). Key is saved securely.

## License
MIT
