#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_ENV_FILE="/opt/narwhal-monitor/server.env"
SERVER_INSTALL_ENV_FILE="/opt/narwhal-monitor/server-install.env"
SERVER_DATA_DIR="/opt/narwhal-monitor/server-data"
TLS_DIR="/opt/narwhal-monitor/caddy"
CONTAINER_NAME="narwhal-monitor-server"
TLS_CONTAINER_NAME="narwhal-monitor-caddy"

MODE="${1:-install}"
if [[ "$MODE" != "install" && "$MODE" != "update" ]]; then
  echo "[ERROR] 用法: bash scripts/install-server.sh [install|update]"
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

ensure_root_and_deps() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Please run as root: sudo bash scripts/install-server.sh ${MODE}"
    exit 1
  fi

  if ! command -v podman >/dev/null 2>&1; then
    echo "Installing podman..."
    apt-get update
    apt-get install -y podman
  fi
}

setup_tls_proxy() {
  local host="$1"
  local upstream_port="$2"
  local enable_tls="$3"
  local tls_email="$4"

  podman rm -f "$TLS_CONTAINER_NAME" >/dev/null 2>&1 || true

  if [[ "$enable_tls" != "yes" ]]; then
    return
  fi

  mkdir -p "$TLS_DIR/config" "$TLS_DIR/data"

  local host_is_ip="no"
  if [[ "$host" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ || "$host" =~ : ]]; then
    host_is_ip="yes"
  fi

  local caddyfile="$TLS_DIR/Caddyfile"
  if [[ "$host_is_ip" == "yes" ]]; then
    cat >"$caddyfile" <<CADDY
https://$host {
  tls internal
  reverse_proxy 127.0.0.1:${upstream_port}
}
CADDY
  else
    if [[ -n "$tls_email" ]]; then
      cat >"$caddyfile" <<CADDY
{
  email $tls_email
}
https://$host {
  reverse_proxy 127.0.0.1:${upstream_port}
}
CADDY
    else
      cat >"$caddyfile" <<CADDY
https://$host {
  reverse_proxy 127.0.0.1:${upstream_port}
}
CADDY
    fi
  fi

  podman run -d --name "$TLS_CONTAINER_NAME" \
    --restart=always \
    --network host \
    -v "$TLS_DIR/Caddyfile:/etc/caddy/Caddyfile:ro" \
    -v "$TLS_DIR/data:/data" \
    -v "$TLS_DIR/config:/config" \
    docker.io/library/caddy:2
}

main() {
  ensure_root_and_deps

  local default_image_source="github"
  local default_github_image="ghcr.io/$(detect_ghcr_owner)/podman-watcher-server:latest"
  local default_port="$(pick_random_port)"
  local default_secret="$(generate_secret)"
  local default_th="80"
  local default_tls_enable="yes"
  local default_tls_host="$(hostname -I | awk '{print $1}')"
  local default_tls_email=""

  default_image_source="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" IMAGE_SOURCE "$default_image_source")"
  default_github_image="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" GITHUB_IMAGE "$default_github_image")"
  default_port="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" PORT "$default_port")"
  default_tls_enable="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" TLS_ENABLE "$default_tls_enable")"
  default_tls_host="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" TLS_HOST "$default_tls_host")"
  default_tls_email="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" TLS_EMAIL "$default_tls_email")"

  local env_secret env_th
  env_secret="$(load_kv_from_file "$SERVER_ENV_FILE" SHARED_SECRET || true)"
  env_th="$(load_kv_from_file "$SERVER_ENV_FILE" ALERT_DISK_THRESHOLD_PERCENT || true)"
  default_secret="${env_secret:-$default_secret}"
  default_th="${env_th:-$default_th}"

  local image_source github_image port secret th tls_enable tls_host tls_email

  image_source="$(ask_with_default "Image source [local/github]" "$default_image_source")"
  image_source=$(echo "$image_source" | tr '[:upper:]' '[:lower:]')
  github_image="$(ask_with_default "GitHub image (for github source)" "$default_github_image")"
  port="$(ask_with_default "Server listen port" "$default_port")"
  secret="$(ask_with_default "Shared secret (for client auth)" "$default_secret")"
  th="$(ask_with_default "Disk alert threshold percent" "$default_th")"
  tls_enable="$(ask_with_default "Enable HTTPS reverse proxy [yes/no]" "$default_tls_enable")"
  tls_enable=$(echo "$tls_enable" | tr '[:upper:]' '[:lower:]')

  if [[ "$tls_enable" == "yes" ]]; then
    tls_host="$(ask_with_default "TLS host (domain or IP)" "$default_tls_host")"
    tls_email="$(ask_with_default "TLS email (domain cert optional)" "$default_tls_email")"
  else
    tls_host=""
    tls_email=""
  fi

  mkdir -p "$SERVER_DATA_DIR"
  cat >"$SERVER_ENV_FILE" <<ENV
SHARED_SECRET=$secret
ALERT_DISK_THRESHOLD_PERCENT=$th
DB_PATH=/data/monitor.db
ENV

  cat >"$SERVER_INSTALL_ENV_FILE" <<ENV
IMAGE_SOURCE=$image_source
GITHUB_IMAGE=$github_image
PORT=$port
TLS_ENABLE=$tls_enable
TLS_HOST=$tls_host
TLS_EMAIL=$tls_email
ENV

  podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

  local image_name="narwhal-monitor-server:latest"
  case "$image_source" in
    local)
      podman build -t "$image_name" -f server/Dockerfile server
      ;;
    github)
      echo "Trying to pull $github_image..."
      if podman pull "$github_image"; then
        image_name="$github_image"
      else
        echo "[WARN] Pull github image failed. Falling back to local build (this avoids GHCR 403/private image issues)."
        podman build -t "$image_name" -f server/Dockerfile server
      fi
      ;;
    *)
      echo "Unsupported image source: $image_source"
      echo "Please choose 'local' or 'github'."
      exit 1
      ;;
  esac

  podman run -d --name "$CONTAINER_NAME" \
    --restart=always \
    -p ${port}:8080 \
    --env-file "$SERVER_ENV_FILE" \
    -v "$SERVER_DATA_DIR:/data" \
    "$image_name"

  setup_tls_proxy "$tls_host" "$port" "$tls_enable" "$tls_email"

  if [[ "$tls_enable" == "yes" ]]; then
    echo "Server started: https://${tls_host}"
  else
    echo "Server started: http://$(hostname -I | awk '{print $1}'):${port}"
  fi

  cat <<EOF_SUM

===== Server Install Summary =====
Mode: $MODE
Container Name: $CONTAINER_NAME
Backend Port: $port
Shared Secret: $secret
Disk Alert Threshold: $th%
Image Source: $image_source
Env File: $SERVER_ENV_FILE
Install Config: $SERVER_INSTALL_ENV_FILE
Data Dir: $SERVER_DATA_DIR
Container Image: $image_name
HTTPS Enabled: $tls_enable
HTTPS Host: ${tls_host:-N/A}
TLS Proxy Container: $TLS_CONTAINER_NAME
==================================
EOF_SUM
}

main "$@"
