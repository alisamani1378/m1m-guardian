# m1m-guardian

Xray multi-IP guardian: monitors Xray node logs (inside a docker container) and bans IPs that exceed configured per-inbound concurrent IP limits. Optionally performs cross-node bans.

## Features
- Tracks active IPs per (inbound, user email)
- Enforces configurable concurrent IP limits (per inbound + default)
- Bans evicted (old) IPs for configurable minutes using ipset + iptables
- Optional cross-node ban propagation
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
- `m1m-guardian-config --show /etc/m1m-guardian/config.yaml` : Show config
- `m1m-guardian-config --add-node /etc/m1m-guardian/config.yaml` : Add node
- `m1m-guardian-config --remove-node /etc/m1m-guardian/config.yaml` : Remove node
- `m1m-guardian-config --edit-limits /etc/m1m-guardian/config.yaml` : Edit inbound limits

## Systemd
`auto.sh` will:
1. Install OS deps (apt/yum)
2. Clone/update repo into `/opt/m1m-guardian`
3. Create venv & install requirements + editable package
4. Install systemd unit `m1m-guardian.service`
5. Show current config.

## Configuration
See `config.example.yaml` for defaults. Keys:
- `redis.url`: Redis connection URL
- `ban_minutes`: Ban duration (minutes)
- `cross_node_ban`: true/false for propagating bans
- `ports`: List of service ports whose conntrack entries are purged on ban
- `inbounds_limit`: Map of inbound name -> max concurrent IPs (use `default` key for fallback)
- `nodes`: List of node objects with fields: name, host, ssh_user, ssh_port, docker_container, ssh_key OR ssh_pass

## License
MIT

