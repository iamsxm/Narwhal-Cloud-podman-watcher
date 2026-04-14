#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLIENT_ENV_FILE="/opt/narwhal-monitor/client.env"
CLIENT_INSTALL_ENV_FILE="/opt/narwhal-monitor/client-install.env"
CLIENT_APP_DIR="/opt/narwhal-monitor/client-agent"
CLIENT_VENV_DIR="$CLIENT_APP_DIR/.venv"
SYSTEMD_SERVICE_FILE="/etc/systemd/system/narwhal-monitor-client.service"
MODE="${1:-install}"

if [[ "$MODE" != "install" && "$MODE" != "update" ]]; then
  echo "[ERROR] 用法: bash scripts/install-client.sh [install|update]"
  exit 1
fi

generate_secret() {
  tr -d '-' </proc/sys/kernel/random/uuid | cut -c 1-25
}

ask_with_default() {
  local prompt="$1"
  local current="$2"
  local answer=""
  if [[ "$MODE" == "update" && -n "$current" ]]; then
    echo "$current"
    return
  fi
  read -rp "$prompt [$current]: " answer
  echo "${answer:-$current}"
}

load_kv_from_file() {
  local f="$1"
  local key="$2"
  [[ -f "$f" ]] || return 1
  awk -v k="$key" '
    {
      pos = index($0, "=")
      if (pos > 0) {
        current_key = substr($0, 1, pos - 1)
        if (current_key == k) {
          print substr($0, pos + 1)
          found = 1
          exit
        }
      }
    }
    END { exit(found ? 0 : 1) }
  ' "$f"
}

load_non_empty_or_default() {
  local f="$1"
  local key="$2"
  local fallback="$3"
  local value=""

  value="$(load_kv_from_file "$f" "$key" || true)"
  if [[ -n "$value" ]]; then
    echo "$value"
  else
    echo "$fallback"
  fi
}

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Please run as root: sudo bash scripts/install-client.sh ${MODE}"
  exit 1
fi

if ! command -v podman >/dev/null 2>&1; then
  echo "Installing podman..."
  apt-get update
  apt-get install -y podman
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Installing python3..."
  apt-get update
  apt-get install -y python3 python3-venv
fi

if ! python3 -m venv -h >/dev/null 2>&1; then
  echo "Installing python3-venv..."
  apt-get update
  apt-get install -y python3-venv
fi

ensure_python_venv_ready() {
  local tmp_venv
  tmp_venv="$(mktemp -d /tmp/narwhal-venv-check-XXXXXX)"

  if python3 -m venv "$tmp_venv" >/dev/null 2>&1; then
    rm -rf "$tmp_venv"
    return 0
  fi

  rm -rf "$tmp_venv"
  local py_minor
  py_minor="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"

  echo "Detected missing ensurepip for python${py_minor}, installing venv packages..."
  apt-get update
  apt-get install -y "python${py_minor}-venv" python3-venv
}

ensure_python_venv_ready

ensure_client_venv() {
  if [[ -d "$CLIENT_VENV_DIR" && -x "$CLIENT_VENV_DIR/bin/python" && -x "$CLIENT_VENV_DIR/bin/pip" ]]; then
    return 0
  fi

  if [[ -d "$CLIENT_VENV_DIR" ]]; then
    echo "Existing virtualenv is incomplete, recreating: $CLIENT_VENV_DIR"
    rm -rf "$CLIENT_VENV_DIR"
  fi

  python3 -m venv "$CLIENT_VENV_DIR"
}

default_server_url="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SERVER_URL "http://127.0.0.1:8080")"
default_secret="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SHARED_SECRET "$(generate_secret)")"
default_host_id="$(load_non_empty_or_default "$CLIENT_ENV_FILE" HOST_ID "$(hostname)")"
default_interval="$(load_non_empty_or_default "$CLIENT_ENV_FILE" REPORT_INTERVAL "300")"
default_monitored_patterns="$(load_non_empty_or_default "$CLIENT_ENV_FILE" MONITORED_IMAGE_PATTERNS "docker.io/narwhalcloud/debian,docker.io/library/alpine,alpine,sing-box,vpn")"

server_url="$(ask_with_default "Server URL (e.g. https://server.example.com or https://1.2.3.4)" "$default_server_url")"
secret="$(ask_with_default "Shared secret" "$default_secret")"
host_id="$(ask_with_default "Host ID" "$default_host_id")"
interval="$(ask_with_default "Collect interval seconds" "$default_interval")"
monitored_patterns="$(ask_with_default "Monitored image patterns (comma-separated substring match)" "$default_monitored_patterns")"

mkdir -p /opt/narwhal-monitor
cat >"$CLIENT_ENV_FILE" <<ENV
SERVER_URL=$server_url
SHARED_SECRET=$secret
HOST_ID=$host_id
REPORT_INTERVAL=$interval
WATCH_DISK_FILE=/xfs_disk.img
MONITORED_IMAGE_PATTERNS=$monitored_patterns
ENV

cat >"$CLIENT_INSTALL_ENV_FILE" <<ENV
RUNTIME=host-agent
AGENT_DIR=$CLIENT_APP_DIR
ENV

# 为兼容旧版本，先尝试删除原容器化 client。
podman rm -f narwhal-monitor-client >/dev/null 2>&1 || true

mkdir -p "$CLIENT_APP_DIR"
cp "$ROOT_DIR/client/agent.py" "$CLIENT_APP_DIR/agent.py"
cp "$ROOT_DIR/client/requirements.txt" "$CLIENT_APP_DIR/requirements.txt"

ensure_client_venv

"$CLIENT_VENV_DIR/bin/pip" install --upgrade pip >/dev/null
"$CLIENT_VENV_DIR/bin/pip" install -r "$CLIENT_APP_DIR/requirements.txt"

cat >"$SYSTEMD_SERVICE_FILE" <<EOF_SERVICE
[Unit]
Description=Narwhal Monitor Host Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$CLIENT_APP_DIR
Environment=PYTHONUNBUFFERED=1
EnvironmentFile=$CLIENT_ENV_FILE
ExecStart=$CLIENT_VENV_DIR/bin/python $CLIENT_APP_DIR/agent.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF_SERVICE

systemctl daemon-reload
systemctl enable --now narwhal-monitor-client.service

cat <<EOF_SUM

===== Client Install Summary =====
Mode: $MODE
Runtime: host agent (systemd)
Service Name: narwhal-monitor-client.service
Server URL: $server_url
Shared Secret: $secret
Host ID: $host_id
Report Interval: $interval s
Watch Disk File: /xfs_disk.img
Monitored Image Patterns: $monitored_patterns
Podman Socket: /run/podman/podman.sock (auto-detected by agent)
Env File: $CLIENT_ENV_FILE
Install Config: $CLIENT_INSTALL_ENV_FILE
Agent Directory: $CLIENT_APP_DIR
Venv Directory: $CLIENT_VENV_DIR
==================================
EOF_SUM
