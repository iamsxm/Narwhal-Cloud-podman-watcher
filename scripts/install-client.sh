#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLIENT_ENV_FILE="/opt/narwhal-monitor/client.env"
CLIENT_INSTALL_ENV_FILE="/opt/narwhal-monitor/client-install.env"
CONTAINER_NAME="narwhal-monitor-client"
MODE="${1:-install}"

if [[ "$MODE" != "install" && "$MODE" != "update" ]]; then
  echo "[ERROR] 用法: bash scripts/install-client.sh [install|update]"
  exit 1
fi

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

default_image_source="$(load_non_empty_or_default "$CLIENT_INSTALL_ENV_FILE" IMAGE_SOURCE "github")"
default_github_image="$(load_non_empty_or_default "$CLIENT_INSTALL_ENV_FILE" GITHUB_IMAGE "ghcr.io/$(detect_ghcr_owner)/podman-watcher-client:latest")"
default_log_enabled="$(load_non_empty_or_default "$CLIENT_INSTALL_ENV_FILE" LOG_ENABLED "yes")"
default_server_url="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SERVER_URL "http://127.0.0.1:8080")"
default_secret="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SHARED_SECRET "$(generate_secret)")"
default_host_id="$(load_non_empty_or_default "$CLIENT_ENV_FILE" HOST_ID "$(hostname)")"
default_interval="$(load_non_empty_or_default "$CLIENT_ENV_FILE" REPORT_INTERVAL "300")"

image_source="$(ask_with_default "Image source [local/github]" "$default_image_source")"
image_source=$(echo "$image_source" | tr '[:upper:]' '[:lower:]')
github_image="$(ask_with_default "GitHub image (for github source)" "$default_github_image")"
log_enabled="$(ask_with_default "Enable client logs in 'podman logs' [yes/no]" "$default_log_enabled")"
log_enabled=$(echo "$log_enabled" | tr '[:upper:]' '[:lower:]')
server_url="$(ask_with_default "Server URL (e.g. https://server.example.com or https://1.2.3.4)" "$default_server_url")"
secret="$(ask_with_default "Shared secret" "$default_secret")"
host_id="$(ask_with_default "Host ID" "$default_host_id")"
interval="$(ask_with_default "Collect interval seconds" "$default_interval")"

case "$log_enabled" in
  yes|y|true|1)
    log_enabled="yes"
    ;;
  no|n|false|0)
    log_enabled="no"
    ;;
  *)
    echo "Unsupported log option: $log_enabled"
    echo "Please choose 'yes' or 'no'."
    exit 1
    ;;
esac

mkdir -p /opt/narwhal-monitor
cat >"$CLIENT_ENV_FILE" <<ENV
SERVER_URL=$server_url
SHARED_SECRET=$secret
HOST_ID=$host_id
REPORT_INTERVAL=$interval
WATCH_DISK_FILE=/xfs_disk.img
ENV

cat >"$CLIENT_INSTALL_ENV_FILE" <<ENV
IMAGE_SOURCE=$image_source
GITHUB_IMAGE=$github_image
LOG_ENABLED=$log_enabled
ENV

podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

image_name="narwhal-monitor-client:latest"
case "$image_source" in
  local)
    podman build -t "$image_name" -f client/Dockerfile client
    ;;
  github)
    echo "Trying to pull $github_image..."
    if podman pull "$github_image"; then
      image_name="$github_image"
    else
      echo "[WARN] Pull github image failed. Falling back to local build (this avoids GHCR 403/private image issues)."
      podman build -t "$image_name" -f client/Dockerfile client
    fi
    ;;
  *)
    echo "Unsupported image source: $image_source"
    echo "Please choose 'local' or 'github'."
    exit 1
    ;;
esac

log_driver="none"
if [[ "$log_enabled" == "yes" ]]; then
  log_driver="k8s-file"
fi

podman run -d --name "$CONTAINER_NAME" \
  --restart=always \
  --log-driver="$log_driver" \
  --network host \
  --pid host \
  -v /run/podman/podman.sock:/run/podman/podman.sock \
  -v /xfs_disk.img:/xfs_disk.img:ro \
  -v /data:/data:ro \
  -e PODMAN_SOCKET=/run/podman/podman.sock \
  -e CONTAINER_HOST=unix:///run/podman/podman.sock \
  -e PYTHONUNBUFFERED=1 \
  --env-file "$CLIENT_ENV_FILE" \
  "$image_name"

echo "Client started and reporting to $server_url"

cat <<EOF_SUM

===== Client Install Summary =====
Mode: $MODE
Container Name: $CONTAINER_NAME
Client Logs Enabled: $log_enabled (podman log driver: $log_driver)
Server URL: $server_url
Shared Secret: $secret
Host ID: $host_id
Report Interval: $interval s
Image Source: $image_source
Watch Disk File: /xfs_disk.img
Podman Socket: /run/podman/podman.sock
Mounts: /xfs_disk.img (ro), /data (ro)
Env File: $CLIENT_ENV_FILE
Install Config: $CLIENT_INSTALL_ENV_FILE
Container Image: $image_name
==================================
EOF_SUM
