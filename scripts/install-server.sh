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

read -rp "Image source [local/github] (default local): " IMAGE_SOURCE
IMAGE_SOURCE=${IMAGE_SOURCE:-local}
IMAGE_SOURCE=$(echo "$IMAGE_SOURCE" | tr '[:upper:]' '[:lower:]')

read -rp "GitHub image (for github source) [ghcr.io/narwhal-cloud/podman-watcher-server:latest]: " GITHUB_IMAGE
GITHUB_IMAGE=${GITHUB_IMAGE:-ghcr.io/narwhal-cloud/podman-watcher-server:latest}

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

IMAGE_NAME="narwhal-monitor-server:latest"
case "$IMAGE_SOURCE" in
  local)
    podman build -t "$IMAGE_NAME" -f server/Dockerfile server
    ;;
  github)
    podman pull "$GITHUB_IMAGE"
    IMAGE_NAME="$GITHUB_IMAGE"
    ;;
  *)
    echo "Unsupported image source: $IMAGE_SOURCE"
    echo "Please choose 'local' or 'github'."
    exit 1
    ;;
esac

podman run -d --name narwhal-monitor-server \
  --restart=always \
  -p ${PORT}:8080 \
  --env-file /opt/narwhal-monitor/server.env \
  -v /opt/narwhal-monitor/server-data:/data \
  "$IMAGE_NAME"

echo "Server started: http://$(hostname -I | awk '{print $1}'):${PORT}"

cat <<EOF

===== Server Install Summary =====
Container Name: narwhal-monitor-server
Listen Port: $PORT
Shared Secret: $SECRET
Disk Alert Threshold: $TH%
Image Source: $IMAGE_SOURCE
Env File: /opt/narwhal-monitor/server.env
Data Dir: /opt/narwhal-monitor/server-data
Container Image: $IMAGE_NAME
Web URL: http://$(hostname -I | awk '{print $1}'):${PORT}
==================================
EOF
