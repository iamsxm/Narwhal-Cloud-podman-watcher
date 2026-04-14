#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Please run as root: sudo bash scripts/install-client.sh"
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

read -rp "GitHub image (for github source) [ghcr.io/narwhal-cloud/podman-watcher-client:latest]: " GITHUB_IMAGE
GITHUB_IMAGE=${GITHUB_IMAGE:-ghcr.io/narwhal-cloud/podman-watcher-client:latest}

read -rp "Server URL (e.g. http://1.2.3.4:8080): " SERVER_URL
read -rp "Shared secret: " SECRET
read -rp "Host ID [$(hostname)]: " HOST_ID
HOST_ID=${HOST_ID:-$(hostname)}
read -rp "Collect interval seconds [300]: " INTERVAL
INTERVAL=${INTERVAL:-300}

mkdir -p /opt/narwhal-monitor
cat >/opt/narwhal-monitor/client.env <<EOF
SERVER_URL=$SERVER_URL
SHARED_SECRET=$SECRET
HOST_ID=$HOST_ID
REPORT_INTERVAL=$INTERVAL
WATCH_DISK_FILE=/xfs_disk.img
EOF

podman rm -f narwhal-monitor-client >/dev/null 2>&1 || true

IMAGE_NAME="narwhal-monitor-client:latest"
case "$IMAGE_SOURCE" in
  local)
    podman build -t "$IMAGE_NAME" -f client/Dockerfile client
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

podman run -d --name narwhal-monitor-client \
  --restart=always \
  --network host \
  --pid host \
  -v /run/podman/podman.sock:/run/podman/podman.sock \
  -v /xfs_disk.img:/xfs_disk.img:ro \
  -v /data:/data:ro \
  --env-file /opt/narwhal-monitor/client.env \
  "$IMAGE_NAME"

echo "Client started and reporting to $SERVER_URL"

cat <<EOF

===== Client Install Summary =====
Container Name: narwhal-monitor-client
Server URL: $SERVER_URL
Shared Secret: $SECRET
Host ID: $HOST_ID
Report Interval: $INTERVAL s
Image Source: $IMAGE_SOURCE
Watch Disk File: /xfs_disk.img
Podman Socket: /run/podman/podman.sock
Mounts: /xfs_disk.img (ro), /data (ro)
Env File: /opt/narwhal-monitor/client.env
Container Image: $IMAGE_NAME
==================================
EOF
