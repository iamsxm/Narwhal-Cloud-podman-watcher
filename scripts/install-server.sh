#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_VERSION="$(tr -d '[:space:]' < "$ROOT_DIR/VERSION")"
SERVER_ENV_FILE="/opt/narwhal-monitor/server.env"
SERVER_INSTALL_ENV_FILE="/opt/narwhal-monitor/server-install.env"
SERVER_DATA_DIR="/opt/narwhal-monitor/server-data"
TLS_DIR="/opt/narwhal-monitor/caddy"
TLS_CA_EXPORT_DIR="/opt/narwhal-monitor/tls-ca"
CONTAINER_NAME="narwhal-monitor-server"
TLS_CONTAINER_NAME="narwhal-monitor-caddy"
DEPLOY_LOCK_FILE="/run/narwhal-monitor-server-deploy-v2.lock"
# 专用网络：避免使用 Podman 默认 10.88.0.0/16，规避与宿主机已有私网网卡冲突。
NARWHAL_NETWORK_NAME="narwhal-monitor-net"
# shellcheck source=scripts/lib/interactive.sh
source "$ROOT_DIR/scripts/lib/interactive.sh"

MODE="${1:-install}"
RESET_DATA_ARG="${2:-}"
if [[ "$MODE" != "install" && "$MODE" != "update" && "$MODE" != "reset-password" ]]; then
  echo "[ERROR] 用法: bash scripts/install-server.sh [install|update|reset-password] [--reset-data]"
  exit 1
fi
if [[ -n "$RESET_DATA_ARG" && "$RESET_DATA_ARG" != "--reset-data" ]]; then
  echo "[ERROR] 未知参数: $RESET_DATA_ARG"
  echo "[ERROR] 用法: bash scripts/install-server.sh [install|update|reset-password] [--reset-data]"
  exit 1
fi
if [[ "$MODE" == "reset-password" && -n "$RESET_DATA_ARG" ]]; then
  echo "[ERROR] reset-password 不接受 --reset-data"
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

generate_dashboard_username() {
  echo "narwhal-$(generate_secret | cut -c 1-10)"
}

generate_dashboard_password() {
  printf '%s%s' "$(generate_secret)" "$(generate_secret)"
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

# 将 IPv4 地址转换为整数，便于做子网归属判断。
ip_to_int() {
  local ip="$1"
  local a b c d
  IFS='.' read -r a b c d <<<"$ip"
  echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

# 判断给定的子网是否与宿主机已有网卡/路由冲突。
# 冲突判定：
#   1) 宿主机任一非 loopback 网卡已配置该子网内的地址；
#   2) 已存在指向该子网的路由（如其它私网 bridge）。
# 注意：更新流程会先通过 `podman network exists` 复用同名网络并提前返回，
# 因此这里无需跳过本项目网桥——否则会漏判与其它 Podman 网络（如默认 podman 网桥）
# 的子网重叠，导致新建网络失败并错误回退到默认网络。
subnet_conflicts() {
  local subnet="$1"
  local net="${subnet%/*}"
  local prefix="${subnet#*/}"
  local net_int mask_int
  net_int="$(ip_to_int "$net")"
  mask_int="$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))"

  local iface addr addr_int
  while read -r iface addr; do
    [[ "$iface" == "lo" ]] && continue
    addr="${addr%%/*}"
    case "$addr" in
      *:*) continue ;;  # 跳过 IPv6
    esac
    addr_int="$(ip_to_int "$addr")"
    if (( (addr_int & mask_int) == (net_int & mask_int) )); then
      return 0
    fi
  done < <(ip -o -4 addr show 2>/dev/null | awk '{print $2, $4}')

  # 已有指向该子网的路由（排除默认路由 0.0.0.0/0）。
  if ip route show to "$subnet" 2>/dev/null \
      | grep -v -E '^default' \
      | grep -q .; then
    return 0
  fi

  return 1
}

# 确保存在专用的 Podman 网络，且子网不与宿主机已有私网冲突。
# 通过 NARWHAL_NETWORK_NAME 返回网络名称（全局），并打印最终使用的子网。
ensure_narwhal_network() {
  if ! command -v podman >/dev/null 2>&1; then
    echo "[WARN] 未检测到 podman，跳过专用网络创建，Server 将使用默认网络。"
    NARWHAL_NETWORK_NAME=""
    return 0
  fi

  # 已存在则直接复用，不再做冲突检测。
  # 原因：subnet_conflicts 会把本网络自身的路由（如 10.233.0.0/16 dev narwhal-monitor0）
  # 误判为“与宿主机冲突”，导致更新时反复销毁重建网络、使正在运行的 Server 断网。
  # 冲突退避仅发生在“首次新建”网络时（见下方候选子网逻辑）。
  if podman network exists "$NARWHAL_NETWORK_NAME" >/dev/null 2>&1; then
    local existing_subnet=""
    existing_subnet="$(podman network inspect "$NARWHAL_NETWORK_NAME" \
      --format '{{range .Subnets}}{{.Subnet}}{{end}}' 2>/dev/null || true)"
    echo "[INFO] 复用已存在的专用网络 $NARWHAL_NETWORK_NAME (subnet=${existing_subnet:-未知})。"
    return 0
  fi

  # 候选子网，按顺序尝试：先排除与宿主机冲突的子网，再实际创建；
  # 若某个子网创建失败（例如与其它 Podman 网络子网重叠），继续尝试下一个，
  # 而不是直接回退到默认网络，以保证专用网络能尽可能被创建出来。
  local -a candidates=(
    "10.233.0.0/16"
    "10.99.0.0/16"
    "10.135.0.0/16"
    "10.155.0.0/16"
    "10.199.0.0/16"
    "10.209.0.0/16"
    "172.20.0.0/16"
    "172.28.0.0/16"
  )
  local candidate=""
  local create_err=""
  for candidate in "${candidates[@]}"; do
    if subnet_conflicts "$candidate"; then
      echo "[INFO] 候选子网 $candidate 与宿主机冲突，退避到下一个。"
      continue
    fi
    if ! create_err="$(podman network create --subnet "$candidate" "$NARWHAL_NETWORK_NAME" 2>&1)"; then
      echo "[WARN] 候选子网 $candidate 创建失败：$create_err（尝试下一个）。"
      continue
    fi
    echo "[INFO] 已创建专用网络 $NARWHAL_NETWORK_NAME (subnet=$candidate)，规避与宿主机已有私网网卡冲突。"
    return 0
  done

  echo "[WARN] 所有候选子网均无法创建专用网络，回退到 Podman 默认网络（可能存在私网冲突风险）。"
  NARWHAL_NETWORK_NAME=""
  return 0
}

ask_with_default() {
  local prompt="$1"
  local current="$2"
  local answer=""
  if [[ "$MODE" == "update" ]]; then
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
      gsub(/\r/, "")
      pos = index($0, "=")
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

ask_choice_with_default() {
  local prompt="$1"
  local current="$2"
  shift 2
  if [[ "$MODE" == "update" ]]; then
    echo "$current"
    return
  fi
  narwhal_choose "$prompt" "$current" "$@"
}

acquire_deploy_lock() {
  if [[ "${NARWHAL_SERVER_DEPLOY_LOCKED:-0}" == "1" ]]; then
    if (( ${NARWHAL_SERVER_DEPLOY_WAITED:-0} > 0 )); then
      echo "[OK] 已等待 ${NARWHAL_SERVER_DEPLOY_WAITED} 秒，部署锁现已释放，继续当前流程。"
    fi
    return
  fi
  local -a locked_command=(
    env NARWHAL_SERVER_DEPLOY_LOCKED=1
    NARWHAL_SERVER_DEPLOY_WAITED=0
    bash "$ROOT_DIR/scripts/install-server.sh" "$MODE"
  )
  if [[ -n "$RESET_DATA_ARG" ]]; then
    locked_command+=( "$RESET_DATA_ARG" )
  fi

  local waited_seconds=0
  local lock_result=0
  while true; do
    locked_command[2]="NARWHAL_SERVER_DEPLOY_WAITED=$waited_seconds"
    set +e
    flock --exclusive --nonblock --close --conflict-exit-code 75 \
      "$DEPLOY_LOCK_FILE" "${locked_command[@]}"
    lock_result=$?
    set -e
    if [[ "$lock_result" -ne 75 ]]; then
      exit "$lock_result"
    fi
    if (( waited_seconds == 0 )); then
      echo "[INFO] 检测到另一个 Server 安装或自动更新正在执行，等待其释放部署锁（最长 5 分钟）..."
      if command -v systemctl >/dev/null 2>&1 \
        && systemctl is-active --quiet narwhal-monitor-server-update.service; then
        echo "[INFO] 后台自动更新服务当前为 active；可在另一终端查看："
        echo "       journalctl -fu narwhal-monitor-server-update.service"
      fi
    fi
    if (( waited_seconds >= 300 )); then
      break
    fi
    sleep 5
    waited_seconds=$((waited_seconds + 5))
    if (( waited_seconds % 30 == 0 )); then
      echo "[INFO] 仍在等待其他部署完成：${waited_seconds}/300 秒..."
    fi
  done
  echo "[ERROR] 等待 Server 部署锁超过 5 分钟，可能已有安装或自动更新仍在运行。"
  echo "[INFO] 可检查: systemctl status narwhal-monitor-server-update.service --no-pager"
  exit 1
}

remove_container_for_replace() {
  local container_name="$1"
  local display_name="$2"
  local existing_id=""
  existing_id="$(podman container inspect --format '{{.Id}}' "$container_name" 2>/dev/null || true)"
  if [[ -n "$existing_id" ]]; then
    echo "[INFO] 正在替换现有 $display_name 容器: ${existing_id:0:12}"
    if ! podman rm -f --time 10 "$container_name"; then
      echo "[WARN] 首次删除旧 $display_name 容器失败，尝试强制停止后再次删除..."
      podman stop --time 5 "$container_name" >/dev/null 2>&1 || true
      podman rm -f --time 0 "$container_name" || true
    fi
  fi
  if podman container inspect "$container_name" >/dev/null 2>&1; then
    echo "[ERROR] 旧 $display_name 容器仍占用名称 '$container_name'，拒绝继续以免产生半更新状态。"
    podman container inspect --format 'ID={{.Id}} Status={{.State.Status}} Error={{.State.Error}}' \
      "$container_name" 2>/dev/null || true
    exit 1
  fi
}

# 等待指定主机端口不再被监听（netavark 端口回收存在竞态，释放需要一点时间）。
wait_for_port_free() {
  local port="$1"
  local waited=0
  if ! command -v ss >/dev/null 2>&1; then
    return 0
  fi
  while (( waited < 30 )); do
    if ! ss -ltnH "sport = :$port" 2>/dev/null | grep -q .; then
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  echo "[WARN] 端口 $port 在 30 秒内仍被占用，继续尝试创建容器。" >&2
  return 0
}

# 释放被遗留转发进程（pasta/conmon/netavark 等）占用的端口。
# 仅清理容器运行时相关进程，避免误杀无关进程。
free_port() {
  local port="$1"
  command -v ss >/dev/null 2>&1 || return 1
  local attempt pid comm holders
  for attempt in $(seq 1 10); do
    holders="$(ss -ltnp "sport = :$port" 2>/dev/null | grep -oE 'pid=[0-9]+' | sed 's/pid=//' | sort -u)"
    [[ -z "$holders" ]] && return 0
    for pid in $holders; do
      comm="$(cat "/proc/$pid/comm" 2>/dev/null || true)"
      case "$comm" in
        netavark|pasta|slirp4netns|conmon|rootlesskit|vpnkit|containerd*|podman*)
          echo "[INFO] 释放端口 $port：终止遗留转发进程 pid=$pid ($comm)" >&2
          kill -TERM "$pid" 2>/dev/null || true
          ;;
        *)
          echo "[WARN] 端口 $port 被非容器转发进程占用 (pid=$pid, $comm)，跳过自动清理。" >&2
          ;;
      esac
    done
    sleep 1
  done
  return 1
}

# 等待端口释放；若仍被容器转发进程占用则主动清理后重试。
ensure_port_free() {
  local port="$1"
  wait_for_port_free "$port"
  if ss -ltnp "sport = :$port" 2>/dev/null | grep -q .; then
    free_port "$port" || true
    sleep 1
  fi
}

# 解析一个可绑定的 Server 后端端口。
# 优先复用期望端口（必要时清理遗留转发进程）；若实在无法释放（如被容器命名空间内
# 的转发进程长期占用且无法归因），则改用新的随机空闲端口，确保 Server 容器必定能启动。
# 客户端始终通过 HTTPS/443 访问，后端端口对客户端透明，切换端口不影响客户端连接。
resolve_free_server_port() {
  local desired="$1"
  # 仅保留数字：防止 server-install.env 中的 PORT 被旧版本误写为诊断文本
  # （如 "PORT=[WARN] ... 61912 ..."）后持续污染端口绑定。
  desired="${desired//[^0-9]/}"
  if [[ -z "$desired" ]]; then
    desired="$(pick_random_port)"
  fi
  ensure_port_free "$desired"
  if ! ss -ltnH "sport = :$desired" 2>/dev/null | grep -q .; then
    echo "$desired"
    return 0
  fi
  echo "[WARN] 端口 $desired 无法释放，改用新的随机空闲端口以避免 Server 无法启动。" >&2
  local candidate tries=0
  while (( tries < 50 )); do
    candidate="$(pick_random_port)"
    if ! ss -ltnH "sport = :$candidate" 2>/dev/null | grep -q .; then
      echo "$candidate"
      return 0
    fi
    tries=$((tries + 1))
  done
  echo "$desired"
}

replace_server_container() {
  local image_name="$1"
  local port_binding="$2"
  local network_name="${3:-}"
  remove_container_for_replace "$CONTAINER_NAME" "Server"

  local -a net_args=()
  if [[ -n "$network_name" ]]; then
    net_args=( --network "$network_name" )
  fi

  # 提取发布端口的主机端口（如 127.0.0.1:61912:8080 -> 61912）。
  local pb="${port_binding#*:}"
  local host_port="${pb%%:*}"

  local new_id=""
  local attempt=""
  local tried_default_net="no"
  for attempt in 1 2 3 4 5; do
    ensure_port_free "$host_port"
    # 注意：不要写成 `... && break`，否则 podman run 失败时 set -e 会静默中止整个脚本。
    new_id="$(podman run -d --name "$CONTAINER_NAME" \
      --restart=always \
      "${net_args[@]}" \
      -p "$port_binding" \
      --env-file "$SERVER_ENV_FILE" \
      -v "$SERVER_DATA_DIR:/data" \
      -v "$TLS_CA_EXPORT_DIR:/tls-ca:ro" \
      "$image_name" 2>&1)" || true
    new_id="$(printf '%s' "$new_id" | tr -d '[:space:]')"
    if [[ "$new_id" == *"address already in use"* ]]; then
      echo "[WARN] 端口 $host_port 仍被占用（尝试 $attempt/5），清理后重试..."
      podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
      sleep 3
      continue
    fi
    # 若使用专用网络创建容器失败，回退到默认网络再试一次。
    # Caddy 以 --network host 反代 127.0.0.1:<host_port>，因此网络选择不影响后端可达性。
    if [[ -n "$network_name" && "$tried_default_net" != "yes" && ! "$new_id" =~ ^[0-9a-fA-F]{12,}$ ]]; then
      echo "[WARN] 使用专用网络 $network_name 创建 Server 容器失败（${new_id}），回退到默认网络重试。"
      net_args=()
      tried_default_net="yes"
      podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
      continue
    fi
    if [[ ! "$new_id" =~ ^[0-9a-fA-F]{12,}$ ]]; then
      echo "[ERROR] 新 Server 容器创建失败: $new_id"
      exit 1
    fi
    break
  done
  if [[ -z "$new_id" ]]; then
    echo "[ERROR] 新 Server 容器创建失败（端口 $host_port 持续被占用）。"
    exit 1
  fi
  echo "$new_id"

  local running="false"
  local runtime_version=""
  local attempt=""
  for attempt in $(seq 1 30); do
    running="$(podman container inspect --format '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null || true)"
    runtime_version="$(
      podman container inspect --format '{{range .Config.Env}}{{println .}}{{end}}' \
        "$CONTAINER_NAME" 2>/dev/null \
        | awk -F= '$1=="NARWHAL_VERSION"{print substr($0,index($0,"=")+1);exit}'
    )"
    if [[ "$running" == "true" && "$runtime_version" == "$PROJECT_VERSION" ]]; then
      echo "[OK] Server 容器已运行，版本 v$runtime_version。"
      return
    fi
    sleep 1
  done
  echo "[ERROR] Server 容器启动或版本验证失败: running=${running:-unknown}, runtime_version=${runtime_version:-unknown}, expected=$PROJECT_VERSION"
  podman logs --tail 120 "$CONTAINER_NAME" 2>&1 || true
  exit 1
}

setup_tls_proxy() {
  local host="$1"
  local upstream_port="$2"
  local enable_tls="$3"
  local tls_email="$4"
  local tls_cert_mode="$5"
  local cloudflare_api_token="$6"
  local caddy_image="$7"

  remove_container_for_replace "$TLS_CONTAINER_NAME" "TLS Proxy"
  mkdir -p "$TLS_CA_EXPORT_DIR"

  if [[ "$enable_tls" != "yes" ]]; then
    rm -f "$TLS_CA_EXPORT_DIR/root.crt"
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

  # 显式拉取 Caddy 镜像，避免仅依赖 podman run 自动拉取时出现不清晰的失败。
  if ! podman pull "$caddy_image" >/dev/null 2>&1; then
    echo "[WARN] 拉取 Caddy 镜像 $caddy_image 失败，将尝试由 podman run 自动拉取（若仍失败请检查 registry 可达性）。"
  fi

  local -a podman_args=(
    run -d --replace --name "$TLS_CONTAINER_NAME"
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

  local tls_container_id=""
  if ! tls_container_id="$(podman "${podman_args[@]}")"; then
    echo "[ERROR] TLS Proxy 容器创建失败。"
    exit 1
  fi
  echo "$tls_container_id"

  local tls_running="false"
  local tls_attempt=""
  for tls_attempt in $(seq 1 30); do
    tls_running="$(podman container inspect --format '{{.State.Running}}' "$TLS_CONTAINER_NAME" 2>/dev/null || true)"
    if [[ "$tls_running" == "true" ]]; then
      break
    fi
    sleep 1
  done
  if [[ "$tls_running" != "true" ]]; then
    echo "[ERROR] TLS Proxy 容器未能进入运行状态。"
    podman logs --tail 100 "$TLS_CONTAINER_NAME" 2>&1 || true
    exit 1
  fi
  if ! podman exec "$TLS_CONTAINER_NAME" caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1; then
    echo "[WARN] TLS Proxy 配置校验未通过（若容器已在运行通常不影响实际服务）；日志如下："
    podman logs --tail 100 "$TLS_CONTAINER_NAME" 2>&1 || true
  fi
  echo "[OK] TLS Proxy 容器已运行。"

  if [[ "$tls_cert_mode" == "internal" || "$host_is_ip" == "yes" ]]; then
    local generated_root="$TLS_DIR/data/caddy/pki/authorities/local/root.crt"
    local attempt=""
    for attempt in $(seq 1 30); do
      if [[ -s "$generated_root" ]]; then
        install -m 0644 "$generated_root" "$TLS_CA_EXPORT_DIR/root.crt.tmp"
        mv -f "$TLS_CA_EXPORT_DIR/root.crt.tmp" "$TLS_CA_EXPORT_DIR/root.crt"
        echo "[OK] Internal TLS CA exported for authenticated Client bootstrap."
        return
      fi
      sleep 1
    done
    echo "[ERROR] Caddy internal CA was not generated within 30 seconds."
    podman logs --tail 100 "$TLS_CONTAINER_NAME" 2>&1 || true
    return 1
  fi
  rm -f "$TLS_CA_EXPORT_DIR/root.crt"
}

replace_kv_in_file() {
  local file="$1"
  local key="$2"
  local value="$3"
  local temp_file
  temp_file="$(mktemp "${file}.tmp.XXXXXX")"
  awk -v k="$key" -v v="$value" '
    BEGIN { replaced = 0 }
    {
      pos = index($0, "=")
      current_key = pos > 0 ? substr($0, 1, pos - 1) : ""
      if (current_key == k) {
        if (!replaced) print k "=" v
        replaced = 1
      } else {
        print
      }
    }
    END { if (!replaced) print k "=" v }
  ' "$file" >"$temp_file"
  chmod 0600 "$temp_file"
  mv -f "$temp_file" "$file"
}

reset_server_password() {
  if [[ ! -f "$SERVER_ENV_FILE" ]]; then
    echo "[ERROR] Server 尚未安装，找不到 $SERVER_ENV_FILE"
    exit 1
  fi
  local dashboard_username dashboard_password
  dashboard_username="$(load_kv_from_file "$SERVER_ENV_FILE" DASHBOARD_USERNAME || true)"
  dashboard_username="${dashboard_username:-$(generate_dashboard_username)}"
  dashboard_password="$(generate_dashboard_password)"
  replace_kv_in_file "$SERVER_ENV_FILE" DASHBOARD_USERNAME "$dashboard_username"
  replace_kv_in_file "$SERVER_ENV_FILE" DASHBOARD_PASSWORD "$dashboard_password"
  echo "[INFO] 已生成新的 Server Dashboard 随机密码，正在重建 Server 容器使其生效..."
  bash "$ROOT_DIR/scripts/install-server.sh" update
}

print_https_guide() {
  cat <<'EOF_HTTPS_GUIDE'

===== HTTPS 配置指引 =====
三种方式都会由 Caddy 自动续期证书。域名使用公网 CA，IP 使用内部 CA。

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

方式 C：直接使用 IP（内部 CA）
  1) TLS host 填写 Server 公网 IP，TLS cert mode 选择 auto 或 internal。
  2) Client 端 SERVER_URL 使用 https://SERVER_IP，不要追加随机 Backend Port。
  3) Client 安装器会通过共享密钥认证接口自动获取、验证并保存公开根证书。
  4) 不会传输 CA 私钥，也不会降级为跳过 TLS 验证。
==============================================

EOF_HTTPS_GUIDE
}

main() {
  ensure_root_and_deps
  acquire_deploy_lock
  if [[ "$MODE" == "reset-password" ]]; then
    reset_server_password
    return
  fi
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
  local default_conn_warning_threshold="500"
  local default_conn_critical_threshold="1000"
  local default_connection_stop_threshold="1500"
  local default_connection_stop_duration_seconds="900"
  local default_connection_stop_max_gap_seconds="600"
  local default_offline_host_purge_seconds="86400"
  local default_dashboard_username
  local default_dashboard_password
  default_dashboard_username="$(generate_dashboard_username)"
  default_dashboard_password="$(generate_dashboard_password)"

  default_image_source="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" IMAGE_SOURCE "$default_image_source")"
  default_github_image="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" GITHUB_IMAGE "$default_github_image")"
  default_port="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" PORT "$default_port")"
  default_tls_enable="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" TLS_ENABLE "$default_tls_enable")"
  default_tls_host="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" TLS_HOST "$default_tls_host")"
  default_tls_email="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" TLS_EMAIL "$default_tls_email")"
  default_tls_cert_mode="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" TLS_CERT_MODE "$default_tls_cert_mode")"
  default_cloudflare_api_token="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" CLOUDFLARE_API_TOKEN "$default_cloudflare_api_token")"

  local env_secret env_th env_alert_webhook_url env_alert_webhook_min_severity env_dashboard_username env_dashboard_password
  local env_conn_warning_threshold env_conn_critical_threshold env_connection_stop_threshold env_connection_stop_duration_seconds env_connection_stop_max_gap_seconds env_offline_host_purge_seconds
  env_secret="$(load_kv_from_file "$SERVER_ENV_FILE" SHARED_SECRET || true)"
  env_th="$(load_kv_from_file "$SERVER_ENV_FILE" ALERT_DISK_THRESHOLD_PERCENT || true)"
  env_alert_webhook_url="$(load_kv_from_file "$SERVER_ENV_FILE" ALERT_WEBHOOK_URL || true)"
  env_alert_webhook_min_severity="$(load_kv_from_file "$SERVER_ENV_FILE" ALERT_WEBHOOK_MIN_SEVERITY || true)"
  env_dashboard_username="$(load_kv_from_file "$SERVER_ENV_FILE" DASHBOARD_USERNAME || true)"
  env_dashboard_password="$(load_kv_from_file "$SERVER_ENV_FILE" DASHBOARD_PASSWORD || true)"
  env_conn_warning_threshold="$(load_kv_from_file "$SERVER_ENV_FILE" ALERT_CONN_WARNING_THRESHOLD || true)"
  env_conn_critical_threshold="$(load_kv_from_file "$SERVER_ENV_FILE" ALERT_CONN_CRITICAL_THRESHOLD || true)"
  env_connection_stop_threshold="$(load_kv_from_file "$SERVER_ENV_FILE" CONNECTION_STOP_THRESHOLD || true)"
  env_connection_stop_duration_seconds="$(load_kv_from_file "$SERVER_ENV_FILE" CONNECTION_STOP_DURATION_SECONDS || true)"
  env_connection_stop_max_gap_seconds="$(load_kv_from_file "$SERVER_ENV_FILE" CONNECTION_STOP_MAX_GAP_SECONDS || true)"
  env_offline_host_purge_seconds="$(load_kv_from_file "$SERVER_ENV_FILE" OFFLINE_HOST_PURGE_SECONDS || true)"
  default_secret="${env_secret:-$default_secret}"
  default_th="${env_th:-$default_th}"
  default_alert_webhook_url="${env_alert_webhook_url:-$default_alert_webhook_url}"
  default_alert_webhook_min_severity="${env_alert_webhook_min_severity:-$default_alert_webhook_min_severity}"
  default_dashboard_username="${env_dashboard_username:-$default_dashboard_username}"
  default_dashboard_password="${env_dashboard_password:-$default_dashboard_password}"
  default_conn_warning_threshold="${env_conn_warning_threshold:-$default_conn_warning_threshold}"
  default_conn_critical_threshold="${env_conn_critical_threshold:-$default_conn_critical_threshold}"
  default_connection_stop_threshold="${env_connection_stop_threshold:-$default_connection_stop_threshold}"
  default_connection_stop_duration_seconds="${env_connection_stop_duration_seconds:-$default_connection_stop_duration_seconds}"
  default_connection_stop_max_gap_seconds="${env_connection_stop_max_gap_seconds:-$default_connection_stop_max_gap_seconds}"
  default_offline_host_purge_seconds="${env_offline_host_purge_seconds:-$default_offline_host_purge_seconds}"

  local image_source github_image port secret th tls_enable tls_host tls_email tls_cert_mode cloudflare_api_token caddy_image alert_webhook_url alert_webhook_min_severity

  image_source="$(ask_choice_with_default "请选择 Server 镜像来源" "$default_image_source" \
    "github|GitHub Container Registry（推荐）" \
    "local|本机源码构建")"
  image_source=$(echo "$image_source" | tr '[:upper:]' '[:lower:]')
  github_image="$(ask_with_default "GitHub image (for github source)" "$default_github_image")"
  port="$(ask_with_default "Server listen port" "$default_port")"
  # 若期望端口被占用且无法释放，则改用新的随机空闲端口（对客户端透明）。
  port="$(resolve_free_server_port "$port")"
  secret="$(ask_with_default "Shared secret (for client auth)" "$default_secret")"
  th="$(ask_with_default "Disk alert threshold percent" "$default_th")"
  if [[ "$MODE" == "update" ]]; then
    alert_webhook_url="$default_alert_webhook_url"
    alert_webhook_min_severity="$default_alert_webhook_min_severity"
  else
    alert_webhook_url="$(ask_with_default "Security alert webhook URL (empty to disable)" "$default_alert_webhook_url")"
    alert_webhook_min_severity="$(ask_choice_with_default "请选择 Webhook 最低告警级别" "$default_alert_webhook_min_severity" \
      "warning|warning 及以上" \
      "critical|仅 critical")"
  fi
  tls_enable="$(ask_choice_with_default "是否启用 HTTPS 反向代理" "$default_tls_enable" \
    "yes|启用（推荐）" \
    "no|不启用")"
  tls_enable=$(echo "$tls_enable" | tr '[:upper:]' '[:lower:]')

  if [[ "$tls_enable" == "yes" ]]; then
    print_https_guide
    tls_host="$(ask_with_default "TLS host (domain or IP)" "$default_tls_host")"
    tls_email="$(ask_with_default "TLS email (domain cert optional)" "$default_tls_email")"
    tls_cert_mode="$(ask_choice_with_default "请选择 TLS 证书模式" "$default_tls_cert_mode" \
      "auto|自动：域名使用公网 CA，IP 自动切换内部 CA" \
      "internal|内部 CA：适合直接使用 IP" \
      "cloudflare_dns|Cloudflare DNS Challenge")"
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

  mkdir -p "$SERVER_DATA_DIR" "$TLS_CA_EXPORT_DIR"
  cat >"$SERVER_ENV_FILE" <<ENV
NARWHAL_VERSION=$PROJECT_VERSION
SHARED_SECRET=$secret
ALERT_DISK_THRESHOLD_PERCENT=$th
ALERT_CONN_WARNING_THRESHOLD=$default_conn_warning_threshold
ALERT_CONN_CRITICAL_THRESHOLD=$default_conn_critical_threshold
CONNECTION_STOP_THRESHOLD=$default_connection_stop_threshold
CONNECTION_STOP_DURATION_SECONDS=$default_connection_stop_duration_seconds
CONNECTION_STOP_MAX_GAP_SECONDS=$default_connection_stop_max_gap_seconds
OFFLINE_HOST_PURGE_SECONDS=$default_offline_host_purge_seconds
ALERT_WEBHOOK_URL=$alert_webhook_url
ALERT_WEBHOOK_MIN_SEVERITY=$alert_webhook_min_severity
DB_PATH=/data/monitor.db
TLS_CA_CERT_PATH=/tls-ca/root.crt
DASHBOARD_USERNAME=$default_dashboard_username
DASHBOARD_PASSWORD=$default_dashboard_password
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
  chmod 0600 "$SERVER_ENV_FILE" "$SERVER_INSTALL_ENV_FILE"

  if [[ "$reset_data" == "yes" ]]; then
    echo "[INFO] 检测到 reset-data，请求清空历史采集数据（初始化数据库）..."
    wipe_server_data
  fi

  local image_name="narwhal-monitor-server:latest"
  case "$image_source" in
    local)
      podman build --build-arg "APP_VERSION=$PROJECT_VERSION" -t "$image_name" -f server/Dockerfile server
      ;;
    github)
      echo "Trying to pull $github_image..."
      if podman pull "$github_image"; then
        image_name="$github_image"
      else
        echo "[WARN] Pull github image failed. Falling back to local build (this avoids GHCR 403/private image issues)."
        podman build --build-arg "APP_VERSION=$PROJECT_VERSION" -t "$image_name" -f server/Dockerfile server
      fi
      ;;
    *)
      echo "Unsupported image source: $image_source"
      echo "Please choose 'local' or 'github'."
      exit 1
      ;;
  esac

  local port_binding="${port}:8080"
  if [[ "$tls_enable" == "yes" ]]; then
    port_binding="127.0.0.1:${port}:8080"
  fi

  # 创建专用网络并规避与宿主机已有私网（如 10.88.0.0/16）的冲突。
  ensure_narwhal_network

  # Keep the current Server available until the replacement image is ready, then
  # perform one serialized, verified and idempotent container replacement.
  replace_server_container "$image_name" "$port_binding" "$NARWHAL_NETWORK_NAME"

  setup_tls_proxy "$tls_host" "$port" "$tls_enable" "$tls_email" "$tls_cert_mode" "$cloudflare_api_token" "$caddy_image"
  bash "$ROOT_DIR/scripts/setup-auto-update.sh" server "$ROOT_DIR"

  if [[ "$tls_enable" == "yes" ]]; then
    echo "Server started: https://${tls_host}"
  else
    echo "Server started: http://$(hostname -I | awk '{print $1}'):${port}"
  fi

  cat <<EOF_SUM

===== Server Install Summary =====
Mode: $MODE
Version: $PROJECT_VERSION
Container Name: $CONTAINER_NAME
Backend Port: $port
Backend Binding: $port_binding
Shared Secret: $(if [[ "$MODE" == "install" && "${NARWHAL_AUTO_UPDATE:-0}" != "1" ]]; then echo "$secret"; else echo "preserved (see $SERVER_ENV_FILE)"; fi)
Dashboard Username: $(if [[ "${NARWHAL_AUTO_UPDATE:-0}" == "1" ]]; then echo "preserved (see $SERVER_ENV_FILE)"; else echo "$default_dashboard_username"; fi)
Dashboard Password: $(if [[ "${NARWHAL_AUTO_UPDATE:-0}" == "1" ]]; then echo "preserved (see $SERVER_ENV_FILE)"; else echo "$default_dashboard_password"; fi)
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
Client Server URL: $(if [[ "$tls_enable" == "yes" ]]; then echo "https://${tls_host}"; else echo "http://$(hostname -I | awk '{print $1}'):${port}"; fi)
TLS CA Bootstrap: $(if [[ "$tls_cert_mode" == "internal" ]]; then echo "HMAC-authenticated /api/v1/tls/ca"; else echo "system/public trust"; fi)
Caddy Image: ${caddy_image:-N/A}
Automatic Updates: enabled (origin/main every 15 minutes)
==================================
EOF_SUM
}

main "$@"
