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
RESET_DATA_ARG="${2:-}"
if [[ "$MODE" != "install" && "$MODE" != "update" ]]; then
  echo "[ERROR] 用法: bash scripts/install-server.sh [install|update] [--reset-data]"
  exit 1
fi
if [[ -n "$RESET_DATA_ARG" && "$RESET_DATA_ARG" != "--reset-data" ]]; then
  echo "[ERROR] 未知参数: $RESET_DATA_ARG"
  echo "[ERROR] 用法: bash scripts/install-server.sh [install|update] [--reset-data]"
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

is_truthy() {
  local value="${1:-}"
  value="$(echo "$value" | tr '[:upper:]' '[:lower:]')"
  [[ "$value" == "1" || "$value" == "true" || "$value" == "yes" || "$value" == "y" ]]
}

wipe_server_data() {
  if [[ -d "$SERVER_DATA_DIR" ]]; then
    rm -rf "${SERVER_DATA_DIR:?}/"* "${SERVER_DATA_DIR:?}"/.[!.]* "${SERVER_DATA_DIR:?}"/..?* 2>/dev/null || true
  fi
  mkdir -p "$SERVER_DATA_DIR"
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
  local tls_cert_mode="$5"
  local cloudflare_api_token="$6"
  local caddy_image="$7"

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
  if [[ "$tls_cert_mode" == "internal" || "$host_is_ip" == "yes" ]]; then
    cat >"$caddyfile" <<CADDY
https://$host {
  tls internal
  reverse_proxy 127.0.0.1:${upstream_port}
}
CADDY
  else
    if [[ "$tls_cert_mode" == "cloudflare_dns" ]]; then
      if [[ -z "$cloudflare_api_token" ]]; then
        echo "[ERROR] TLS cert mode 'cloudflare_dns' requires Cloudflare API token."
        exit 1
      fi
      cat >"$caddyfile" <<CADDY
{
$( [[ -n "$tls_email" ]] && echo "  email $tls_email" )
}
https://$host {
  tls {
    dns cloudflare {\$CLOUDFLARE_API_TOKEN}
  }
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
  fi

  if [[ "$tls_cert_mode" == "cloudflare_dns" ]]; then
    if [[ "$caddy_image" =~ ^docker\.io/caddy-dns/cloudflare(:.*)?$ ]]; then
      local normalized_tag="${BASH_REMATCH[1]}"
      [[ -z "$normalized_tag" ]] && normalized_tag=":latest"
      caddy_image="ghcr.io/caddy-dns/cloudflare${normalized_tag}"
      echo "[INFO] Remapped docker.io/caddy-dns/cloudflare to $caddy_image"
    fi
    local -a cf_caddy_candidates=(
      "$caddy_image"
      "ghcr.io/caddy-dns/cloudflare:latest"
      "ghcr.io/caddy-dns/cloudflare:2"
    )
    local selected_image=""
    local img=""
    for img in "${cf_caddy_candidates[@]}"; do
      [[ -z "$img" ]] && continue
      if podman pull "$img" >/dev/null 2>&1; then
        selected_image="$img"
        break
      fi
    done
    if [[ -z "$selected_image" ]]; then
      echo "[ERROR] Unable to pull Cloudflare DNS Caddy image."
      echo "        Tried: ${cf_caddy_candidates[*]}"
      echo "        Please verify network access / registry reachability, or set tls_cert_mode=auto/internal."
      exit 1
    fi
    caddy_image="$selected_image"
  fi

  local -a podman_args=(
    run -d --name "$TLS_CONTAINER_NAME"
    --restart=always
    --network host
    -v "$TLS_DIR/Caddyfile:/etc/caddy/Caddyfile:ro"
    -v "$TLS_DIR/data:/data"
    -v "$TLS_DIR/config:/config"
  )
  if [[ "$tls_cert_mode" == "cloudflare_dns" ]]; then
    podman_args+=( -e "CLOUDFLARE_API_TOKEN=$cloudflare_api_token" )
  fi
  podman_args+=( "$caddy_image" )

  podman "${podman_args[@]}"
}

print_https_guide() {
  cat <<'EOF_HTTPS_GUIDE'

===== HTTPS 配置指引（两种公网证书方式）=====
两种方式都会由 Caddy 自动续期证书，无需手工续期。

方式 A：域名直连（ACME HTTP-01，最简单）
适用：你使用 Cloudflare 托管 DNS，但可将该记录设置为 DNS only（灰云）。
  1) 在 Cloudflare DNS 中新增 A/AAAA 记录（例如 monitor.example.com）指向服务器公网 IP。
  2) 将该记录设置为 DNS only（灰云），不要走 Cloudflare 代理。
  3) 服务器放通 80/443 端口。
  4) 脚本填写建议：
     - Enable HTTPS reverse proxy: yes
     - TLS host: monitor.example.com
     - TLS cert mode: auto
     - TLS email: 建议填写
  5) Client 端 SERVER_URL 使用：https://monitor.example.com

方式 B：Cloudflare DNS Challenge（可橙云）
适用：你希望保留 Cloudflare 代理（橙云）或不便开放 80 端口。
  1) 在 Cloudflare 创建 API Token，权限至少包含：
     - Zone:DNS:Edit
     - Zone:Zone:Read
  2) 脚本填写建议：
     - Enable HTTPS reverse proxy: yes
     - TLS host: monitor.example.com
     - TLS cert mode: cloudflare_dns
     - Cloudflare API token: 填入上一步 token
  3) 脚本会自动使用带 Cloudflare DNS 模块的 Caddy 镜像并注入 token。
  4) Client 端 SERVER_URL 使用：https://monitor.example.com
==============================================

EOF_HTTPS_GUIDE
}

main() {
  ensure_root_and_deps
  local reset_data="no"
  if [[ "$RESET_DATA_ARG" == "--reset-data" ]] || is_truthy "${RESET_SERVER_DATA:-}"; then
    reset_data="yes"
  fi

  local default_image_source="github"
  local default_github_image="ghcr.io/$(detect_ghcr_owner)/podman-watcher-server:latest"
  local default_port="$(pick_random_port)"
  local default_secret="$(generate_secret)"
  local default_th="80"
  local default_tls_enable="yes"
  local default_tls_host="$(hostname -I | awk '{print $1}')"
  local default_tls_email=""
  local default_tls_cert_mode="auto"
  local default_cloudflare_api_token=""
  local default_alert_webhook_url=""
  local default_alert_webhook_min_severity="warning"

  default_image_source="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" IMAGE_SOURCE "$default_image_source")"
  default_github_image="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" GITHUB_IMAGE "$default_github_image")"
  default_port="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" PORT "$default_port")"
  default_tls_enable="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" TLS_ENABLE "$default_tls_enable")"
  default_tls_host="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" TLS_HOST "$default_tls_host")"
  default_tls_email="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" TLS_EMAIL "$default_tls_email")"
  default_tls_cert_mode="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" TLS_CERT_MODE "$default_tls_cert_mode")"
  default_cloudflare_api_token="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" CLOUDFLARE_API_TOKEN "$default_cloudflare_api_token")"

  local env_secret env_th env_alert_webhook_url env_alert_webhook_min_severity
  env_secret="$(load_kv_from_file "$SERVER_ENV_FILE" SHARED_SECRET || true)"
  env_th="$(load_kv_from_file "$SERVER_ENV_FILE" ALERT_DISK_THRESHOLD_PERCENT || true)"
  env_alert_webhook_url="$(load_kv_from_file "$SERVER_ENV_FILE" ALERT_WEBHOOK_URL || true)"
  env_alert_webhook_min_severity="$(load_kv_from_file "$SERVER_ENV_FILE" ALERT_WEBHOOK_MIN_SEVERITY || true)"
  default_secret="${env_secret:-$default_secret}"
  default_th="${env_th:-$default_th}"
  default_alert_webhook_url="${env_alert_webhook_url:-$default_alert_webhook_url}"
  default_alert_webhook_min_severity="${env_alert_webhook_min_severity:-$default_alert_webhook_min_severity}"

  local image_source github_image port secret th tls_enable tls_host tls_email tls_cert_mode cloudflare_api_token caddy_image alert_webhook_url alert_webhook_min_severity

  image_source="$(ask_with_default "Image source [local/github]" "$default_image_source")"
  image_source=$(echo "$image_source" | tr '[:upper:]' '[:lower:]')
  github_image="$(ask_with_default "GitHub image (for github source)" "$default_github_image")"
  port="$(ask_with_default "Server listen port" "$default_port")"
  secret="$(ask_with_default "Shared secret (for client auth)" "$default_secret")"
  th="$(ask_with_default "Disk alert threshold percent" "$default_th")"
  if [[ "$MODE" == "update" ]]; then
    alert_webhook_url="$default_alert_webhook_url"
    alert_webhook_min_severity="$default_alert_webhook_min_severity"
  else
    alert_webhook_url="$(ask_with_default "Security alert webhook URL (empty to disable)" "$default_alert_webhook_url")"
    alert_webhook_min_severity="$(ask_with_default "Webhook minimum severity [warning/critical]" "$default_alert_webhook_min_severity")"
  fi
  tls_enable="$(ask_with_default "Enable HTTPS reverse proxy [yes/no]" "$default_tls_enable")"
  tls_enable=$(echo "$tls_enable" | tr '[:upper:]' '[:lower:]')

  if [[ "$tls_enable" == "yes" ]]; then
    print_https_guide
    tls_host="$(ask_with_default "TLS host (domain or IP)" "$default_tls_host")"
    tls_email="$(ask_with_default "TLS email (domain cert optional)" "$default_tls_email")"
    tls_cert_mode="$(ask_with_default "TLS cert mode [auto/internal/cloudflare_dns]" "$default_tls_cert_mode")"
    tls_cert_mode=$(echo "$tls_cert_mode" | tr '[:upper:]' '[:lower:]')
    case "$tls_cert_mode" in
      auto|internal|cloudflare_dns) ;;
      *)
        echo "[WARN] Unknown TLS cert mode '$tls_cert_mode', fallback to auto."
        tls_cert_mode="auto"
        ;;
    esac

    if [[ "$tls_cert_mode" == "auto" ]]; then
      if [[ "$tls_host" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ || "$tls_host" =~ : ]]; then
        echo "[INFO] TLS host 看起来是 IP，auto 将自动切换为 internal（自签证书）。"
        tls_cert_mode="internal"
      fi
    elif [[ "$tls_cert_mode" == "internal" ]]; then
      true
    fi

    if [[ "$tls_cert_mode" == "cloudflare_dns" ]]; then
      cloudflare_api_token="$(ask_with_default "Cloudflare API token (Zone DNS Edit)" "$default_cloudflare_api_token")"
      caddy_image="ghcr.io/caddy-dns/cloudflare:latest"
    else
      cloudflare_api_token=""
      caddy_image="docker.io/library/caddy:2"
    fi
  else
    tls_host=""
    tls_email=""
    tls_cert_mode=""
    cloudflare_api_token=""
    caddy_image=""
  fi

  mkdir -p "$SERVER_DATA_DIR"
  cat >"$SERVER_ENV_FILE" <<ENV
SHARED_SECRET=$secret
ALERT_DISK_THRESHOLD_PERCENT=$th
ALERT_WEBHOOK_URL=$alert_webhook_url
ALERT_WEBHOOK_MIN_SEVERITY=$alert_webhook_min_severity
DB_PATH=/data/monitor.db
ENV

  cat >"$SERVER_INSTALL_ENV_FILE" <<ENV
IMAGE_SOURCE=$image_source
GITHUB_IMAGE=$github_image
PORT=$port
TLS_ENABLE=$tls_enable
TLS_HOST=$tls_host
TLS_EMAIL=$tls_email
TLS_CERT_MODE=$tls_cert_mode
CLOUDFLARE_API_TOKEN=$cloudflare_api_token
ENV

  podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

  if [[ "$reset_data" == "yes" ]]; then
    echo "[INFO] 检测到 reset-data，请求清空历史采集数据（初始化数据库）..."
    wipe_server_data
  fi

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

  setup_tls_proxy "$tls_host" "$port" "$tls_enable" "$tls_email" "$tls_cert_mode" "$cloudflare_api_token" "$caddy_image"

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
Security Webhook: ${alert_webhook_url:-disabled}
Webhook Minimum Severity: $alert_webhook_min_severity
Disk Alert Threshold: $th%
Image Source: $image_source
Env File: $SERVER_ENV_FILE
Install Config: $SERVER_INSTALL_ENV_FILE
Data Dir: $SERVER_DATA_DIR
Data Reset: $reset_data
Container Image: $image_name
HTTPS Enabled: $tls_enable
HTTPS Host: ${tls_host:-N/A}
TLS Proxy Container: $TLS_CONTAINER_NAME
TLS Cert Mode: ${tls_cert_mode:-N/A}
Caddy Image: ${caddy_image:-N/A}
==================================
EOF_SUM
}

main "$@"
