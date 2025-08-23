#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/alisamani1378/m1m-guardian}"
INSTALL_DIR="/opt/m1m-guardian"
ETC_DIR="/etc/m1m-guardian"
CFG="$ETC_DIR/config.yaml"
VENV="$INSTALL_DIR/.venv"
SERVICE="/etc/systemd/system/m1m-guardian.service"

need_root() { [ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }; }
pkg_install() {
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y git curl jq python3-venv python3-pip redis-server openssh-client sshpass
    systemctl enable --now redis-server || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y git curl jq python3 python3-venv python3-pip redis openssh-clients sshpass
    systemctl enable --now redis || true
  else
    echo "Install deps manually: git curl jq python3-venv redis-server openssh-client sshpass"; exit 1
  fi
}

clone_or_update() {
  mkdir -p "$INSTALL_DIR" "$ETC_DIR"
  if [ -n "${GITHUB_TOKEN:-}" ]; then

    CLONE_URL="${REPO_URL/https:\/\/github.com\//https:\/\/${GITHUB_TOKEN}@github.com/}.git"
  else
    CLONE_URL="${REPO_URL}.git"
  fi

  if [ -d "$INSTALL_DIR/.git" ]; then
    git -C "$INSTALL_DIR" fetch --depth=1 origin main || git -C "$INSTALL_DIR" fetch --depth=1 origin master || true
    git -C "$INSTALL_DIR" reset --hard "$(git -C "$INSTALL_DIR" rev-parse --verify origin/main 2>/dev/null || git -C "$INSTALL_DIR" rev-parse --verify origin/master)"
  else
    git clone --depth=1 "$CLONE_URL" "$INSTALL_DIR"
  fi
}


make_venv() {
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install --upgrade pip
  "$VENV/bin/pip" install -r "$INSTALL_DIR/requirements.txt"
  if [ -f "$INSTALL_DIR/pyproject.toml" ] || [ -f "$INSTALL_DIR/setup.py" ]; then
    "$VENV/bin/pip" install -e "$INSTALL_DIR"
  else
    echo "[warn] No pyproject/setup.py found. Using PYTHONPATH at runtime."
  fi
}

install_service() {
  cp "$INSTALL_DIR/m1m-guardian.service" "$SERVICE"
  sed -i "s|/opt/m1m-guardian|$INSTALL_DIR|g" "$SERVICE"
  sed -i "s|/etc/m1m-guardian/config.yaml|$CFG|g" "$SERVICE"
  systemctl daemon-reload
  systemctl enable --now m1m-guardian
}

init_cfg() {
  if [ ! -f "$CFG" ]; then
    cp "$INSTALL_DIR/config.example.yaml" "$CFG"
    echo "[init] Wrote $CFG (defaults)."
  fi
}

menu() {
  clear
  echo "m1m-guardian installer"
  echo "1) Install/Update & Start"
  echo "2) Add node"
  echo "3) Remove node"
  echo "4) Edit inbound limits"
  echo "5) Uninstall (wipe)"
  echo "0) Exit"
  read -rp "> " c
  case "$c" in
    1)
      need_root; pkg_install; clone_or_update; make_venv; init_cfg; install_service
      "$VENV/bin/python" -m m1m_guardian.config --show "$CFG"
      echo "Service is running: systemctl status m1m-guardian"
      ;;
    2)
      need_root; clone_or_update; make_venv; init_cfg
      "$VENV/bin/python" -m m1m_guardian.config --add-node "$CFG"
      systemctl restart m1m-guardian || true
      ;;
    3)
      need_root; clone_or_update; make_venv; init_cfg
      "$VENV/bin/python" -m m1m_guardian.config --remove-node "$CFG"
      systemctl restart m1m-guardian || true
      ;;
    4)
      need_root; clone_or_update; make_venv; init_cfg
      "$VENV/bin/python" -m m1m_guardian.config --edit-limits "$CFG"
      systemctl restart m1m-guardian || true
      ;;
    5)
      need_root
      systemctl disable --now m1m-guardian || true
      rm -f "$SERVICE"; systemctl daemon-reload || true
      rm -rf "$INSTALL_DIR" "$ETC_DIR"
      echo "Wiped. (Redis DB kept)."
      ;;
    0) exit 0 ;;
    *) echo "Bad choice";;
  esac
}

# non-interactive quick mode
if [ "${1:-}" = "--quick-install" ]; then
  need_root; pkg_install; clone_or_update; make_venv; init_cfg; install_service; exit 0
fi

menu
