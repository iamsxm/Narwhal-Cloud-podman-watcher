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
podman build -t narwhal-monitor-client:latest -f client/Dockerfile client
podman run -d --name narwhal-monitor-client \
  --restart=always \
  --network host \
  --pid host \
  -v /run/podman/podman.sock:/run/podman/podman.sock \
  -v /xfs_disk.img:/xfs_disk.img:ro \
  -v /data:/data:ro \
  --env-file /opt/narwhal-monitor/client.env \
  narwhal-monitor-client:latest

echo "Client started and reporting to $SERVER_URL"

cat <<EOF

===== Client Install Summary =====
Container Name: narwhal-monitor-client
Server URL: $SERVER_URL
Shared Secret: $SECRET
Host ID: $HOST_ID
Report Interval: $INTERVAL s
Watch Disk File: /xfs_disk.img
Podman Socket: /run/podman/podman.sock
Mounts: /xfs_disk.img (ro), /data (ro)
Env File: /opt/narwhal-monitor/client.env
Container Image: narwhal-monitor-client:latest
==================================
EOF
