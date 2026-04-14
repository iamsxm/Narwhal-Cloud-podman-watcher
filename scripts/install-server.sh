#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

detect_ghcr_owner() {
  local owner="narwhal-cloud"
  if command -v git >/dev/null 2>&1; then
    local remote_url
    remote_url="$(git -C "$ROOT_DIR" config --get remote.origin.url 2>/dev/null || true)"
    if [[ -n "$remote_url" ]]; then
      if [[ "$remote_url" =~ github\.com[:/]([^/]+)/[^/]+(\.git)?$ ]]; then
        owner="${BASH_REMATCH[1]}"
      fi
    fi
  fi
  echo "$owner"
}

generate_secret() {
  tr -d '-' </proc/sys/kernel/random/uuid | cut -c 1-25
}

pick_random_port() {
  local fallback=49152
  if ! command -v ss >/dev/null 2>&1; then
    echo "$fallback"
    return
  fi

  local candidate
  for _ in $(seq 1 120); do
    candidate="$(shuf -i 40000-65000 -n 1)"
    if ! ss -ltnH "( sport = :${candidate} )" | grep -q .; then
      echo "$candidate"
      return
    fi
  done

  echo "$fallback"
}

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Please run as root: sudo bash scripts/install-server.sh"
  exit 1
fi

if ! command -v podman >/dev/null 2>&1; then
  echo "Installing podman..."
  apt-get update
  apt-get install -y podman
fi

read -rp "Image source [local/github] (default github): " IMAGE_SOURCE
IMAGE_SOURCE=${IMAGE_SOURCE:-github}
IMAGE_SOURCE=$(echo "$IMAGE_SOURCE" | tr '[:upper:]' '[:lower:]')

DEFAULT_GITHUB_IMAGE="ghcr.io/$(detect_ghcr_owner)/podman-watcher-server:latest"
read -rp "GitHub image (for github source) [${DEFAULT_GITHUB_IMAGE}]: " GITHUB_IMAGE
GITHUB_IMAGE=${GITHUB_IMAGE:-$DEFAULT_GITHUB_IMAGE}

DEFAULT_PORT="$(pick_random_port)"
read -rp "Server listen port [${DEFAULT_PORT}]: " PORT
PORT=${PORT:-$DEFAULT_PORT}

DEFAULT_SECRET="$(generate_secret)"
read -rp "Shared secret (for client auth) [${DEFAULT_SECRET}]: " SECRET
SECRET=${SECRET:-$DEFAULT_SECRET}

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
    echo "Trying to pull $GITHUB_IMAGE..."
    if podman pull "$GITHUB_IMAGE"; then
      IMAGE_NAME="$GITHUB_IMAGE"
    else
      echo "[WARN] Pull github image failed. Falling back to local build (this avoids GHCR 403/private image issues)."
      podman build -t "$IMAGE_NAME" -f server/Dockerfile server
    fi
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
