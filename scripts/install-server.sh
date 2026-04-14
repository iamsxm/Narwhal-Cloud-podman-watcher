#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Please run as root: sudo bash scripts/install-server.sh"
  exit 1
fi

if ! command -v podman >/dev/null 2>&1; then
  echo "Installing podman..."
  apt-get update
  apt-get install -y podman
fi

read -rp "Server listen port [8080]: " PORT
PORT=${PORT:-8080}
read -rp "Shared secret (for client auth): " SECRET
if [[ -z "$SECRET" ]]; then
  echo "Shared secret cannot be empty"; exit 1
fi
read -rp "Disk alert threshold percent [80]: " TH
TH=${TH:-80}

mkdir -p /opt/narwhal-monitor/server-data
cat >/opt/narwhal-monitor/server.env <<EOF
SHARED_SECRET=$SECRET
ALERT_DISK_THRESHOLD_PERCENT=$TH
DB_PATH=/data/monitor.db
EOF

podman rm -f narwhal-monitor-server >/dev/null 2>&1 || true
podman build -t narwhal-monitor-server:latest -f server/Dockerfile server
podman run -d --name narwhal-monitor-server \
  --restart=always \
  -p ${PORT}:8080 \
  --env-file /opt/narwhal-monitor/server.env \
  -v /opt/narwhal-monitor/server-data:/data \
  narwhal-monitor-server:latest

echo "Server started: http://$(hostname -I | awk '{print $1}'):${PORT}"

cat <<EOF

===== Server Install Summary =====
Container Name: narwhal-monitor-server
Listen Port: $PORT
Shared Secret: $SECRET
Disk Alert Threshold: $TH%
Env File: /opt/narwhal-monitor/server.env
Data Dir: /opt/narwhal-monitor/server-data
Container Image: narwhal-monitor-server:latest
Web URL: http://$(hostname -I | awk '{print $1}'):${PORT}
==================================
EOF
