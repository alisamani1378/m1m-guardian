# m1m-guardian

Xray multi-IP guardian: monitors Xray node logs (inside a docker container) and bans IPs that exceed configured per-inbound concurrent IP limits.

## Features
- 📊 Tracks active IPs per (inbound, user email)
- 🚫 Enforces configurable concurrent IP limits per inbound
- 🔥 Bans IPs using ipset + iptables (supports Docker and non-Docker setups)
- 🤖 Telegram bot for management (nodes, inbounds, bans, firewall)
- ♻️ Auto-reconnect and node health monitoring
- 🔄 Cross-node ban propagation (ban IP on all nodes)
- 📱 Ban notification batching (reduces Telegram spam)
- 🛡️ Auto-fix SSH host key changes
- 💾 Redis for state persistence

## Telegram Bot Features
- View/manage nodes, inbounds, sessions, and banned IPs
- 🔥 Check firewall status on all nodes
- 🔧 Fix firewall rules remotely
- ♻️ Restart service or reboot nodes
- 🆕 One-click update from git

## Install (auto)
```bash
curl -fsSL https://raw.githubusercontent.com/yourrepo/m1m-guardian/main/auto.sh | bash
```

## Install (manual)
```bash
git clone https://github.com/yourrepo/m1m-guardian.git /opt/m1m-guardian
cd /opt/m1m-guardian
python -m venv .venv
. .venv/bin/activate
pip install -e .
cp config.example.yaml /etc/m1m-guardian/config.yaml
# Edit config.yaml with your settings
systemctl enable --now m1m-guardian
```

## CLI Entrypoints
- `m1m-guardian --config /etc/m1m-guardian/config.yaml` : Run guardian
- `m1m-guardian-config --menu /etc/m1m-guardian/config.yaml` : Interactive config menu
- `m1m-guardian-config --show /etc/m1m-guardian/config.yaml` : Show config

## Configuration (`/etc/m1m-guardian/config.yaml`)
```yaml
redis:
  url: redis://127.0.0.1:6379/0

ban_minutes: 10

telegram:
  bot_token: "YOUR_BOT_TOKEN"
  chat_id: "YOUR_CHAT_ID"
  admins: []  # Additional admin chat IDs

inbounds_limit:
  VIP: 2
  Free: 1

nodes:
  - name: node1
    host: 1.2.3.4
    ssh_user: root
    ssh_port: 22
    docker_container: marzban-node
    ssh_key: /root/.ssh/id_rsa  # or ssh_pass: "password"
```

## Firewall Setup
The guardian automatically creates:
- ipset sets: `m1m_guardian` (IPv4), `m1m_guardian6` (IPv6)
- iptables rules in `INPUT`, `FORWARD`, and `DOCKER-USER` (if Docker exists)

Use the Telegram bot's "🔥 چک فایروال" to verify and fix firewall rules.

## License
MIT
