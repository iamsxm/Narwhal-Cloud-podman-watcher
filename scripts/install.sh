#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_BASE_DIR="/opt/narwhal-monitor"
UNINSTALL_IMAGES_TO_REMOVE=()

require_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "[ERROR] 请使用 root 运行：sudo bash scripts/install.sh"
    exit 1
  fi
}

ensure_cmd() {
  local cmd="$1"
  local pkg="$2"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[INFO] 安装依赖: $pkg"
    apt-get update
    apt-get install -y "$pkg"
  fi
}

install_deps() {
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "[ERROR] 仅支持 Debian/Ubuntu (apt-get) 自动安装依赖，请手动安装 podman/git/curl 后重试。"
    exit 1
  fi

  ensure_cmd podman podman
  ensure_cmd git git
  ensure_cmd curl curl
}

update_repo_self() {
  if [[ ! -d "$ROOT_DIR/.git" ]]; then
    echo "[WARN] 当前目录不是 git 仓库，跳过脚本自更新。"
    return
  fi

  echo "[INFO] 更新安装脚本与仓库代码（git pull --ff-only）..."
  git -C "$ROOT_DIR" fetch --all --prune
  git -C "$ROOT_DIR" pull --ff-only
}

cleanup_after_update() {
  if [[ "${SKIP_CLEANUP_ON_UPDATE:-0}" == "1" ]]; then
    echo "[INFO] 检测到 SKIP_CLEANUP_ON_UPDATE=1，跳过更新后清理。"
    return
  fi

  echo "[INFO] 更新完成，开始清理无用文件与旧镜像..."

  if command -v podman >/dev/null 2>&1; then
    podman container prune -f >/dev/null 2>&1 || true
    podman image prune -af >/dev/null 2>&1 || true
    podman volume prune -f >/dev/null 2>&1 || true
    podman network prune -f >/dev/null 2>&1 || true
    echo "[INFO] Podman 无用资源清理完成。"
  fi

  if command -v apt-get >/dev/null 2>&1; then
    apt-get autoremove -y >/dev/null 2>&1 || true
    apt-get clean >/dev/null 2>&1 || true
    echo "[INFO] apt 缓存与无用依赖清理完成。"
  fi
}

run_installer() {
  local target="$1"
  local mode="$2"
  case "$target" in
    server)
      bash "$ROOT_DIR/scripts/install-server.sh" "$mode"
      ;;
    client)
      bash "$ROOT_DIR/scripts/install-client.sh" "$mode"
      ;;
    both)
      echo "[INFO] 先处理 Server，再处理 Client。"
      bash "$ROOT_DIR/scripts/install-server.sh" "$mode"
      bash "$ROOT_DIR/scripts/install-client.sh" "$mode"
      ;;
    *)
      echo "[ERROR] 不支持的安装目标: $target"
      exit 1
      ;;
  esac
}

remove_container_if_exists() {
  local name="$1"
  if podman container exists "$name" >/dev/null 2>&1; then
    echo "[INFO] 删除容器: $name"
    podman rm -f "$name" >/dev/null 2>&1 || true
  fi
}

remove_image_if_exists() {
  local image="$1"
  if podman image exists "$image" >/dev/null 2>&1; then
    echo "[INFO] 删除镜像: $image"
    podman rmi -f "$image" >/dev/null 2>&1 || true
  fi
}

detect_ghcr_owner() {
  local owner="narwhal-cloud"
  if command -v git >/dev/null 2>&1; then
    local remote_url=""
    remote_url="$(git -C "$ROOT_DIR" config --get remote.origin.url 2>/dev/null || true)"
    if [[ -n "$remote_url" && "$remote_url" =~ github\.com[:/]([^/]+)/[^/]+(\.git)?$ ]]; then
      owner="${BASH_REMATCH[1]}"
    fi
  fi
  echo "$owner"
}

append_unique_image() {
  local image="$1"
  [[ -n "$image" ]] || return 0
  case "$image" in
    IMAGE_SOURCE=*|GITHUB_IMAGE=*|PORT=*|TLS_ENABLE=*|TLS_HOST=*|TLS_EMAIL=*|TLS_CERT_MODE=*|CLOUDFLARE_API_TOKEN=*|*=*)
      return 0
      ;;
  esac

  local existing=""
  for existing in "${UNINSTALL_IMAGES_TO_REMOVE[@]-}"; do
    if [[ "$existing" == "$image" ]]; then
      return 0
    fi
  done
  UNINSTALL_IMAGES_TO_REMOVE+=("$image")
}

collect_images_from_saved_configs() {
  local client_install_env="$INSTALL_BASE_DIR/client-install.env"
  local server_install_env="$INSTALL_BASE_DIR/server-install.env"

  if [[ -f "$client_install_env" ]]; then
    local client_image=""
    client_image="$(awk -F= '$1=="GITHUB_IMAGE"{print substr($0, index($0, "=") + 1); exit}' "$client_install_env" 2>/dev/null || true)"
    append_unique_image "$client_image"
  fi

  if [[ -f "$server_install_env" ]]; then
    local server_image=""
    server_image="$(awk -F= '$1=="GITHUB_IMAGE"{print substr($0, index($0, "=") + 1); exit}' "$server_install_env" 2>/dev/null || true)"
    append_unique_image "$server_image"
  fi
}

remove_images_by_repository_pattern() {
  local pattern="$1"
  [[ -n "$pattern" ]] || return 0

  local image_id=""
  while IFS= read -r image_id; do
    [[ -z "$image_id" ]] && continue
    echo "[INFO] 删除镜像ID: $image_id (匹配: $pattern)"
    podman rmi -f "$image_id" >/dev/null 2>&1 || true
  done < <(podman images --format '{{.ID}} {{.Repository}}:{{.Tag}}' | awk -v p="$pattern" '$2 ~ p {print $1}')
}

uninstall_narwhal_related() {
  echo "[INFO] 开始卸载 Narwhal-Cloud-podman-watcher 相关 Podman 资源..."
  echo "[INFO] 仅清理本项目相关资源，不会删除其他已有 Podman 容器。"

  if command -v podman >/dev/null 2>&1; then
    local owner=""
    owner="$(detect_ghcr_owner)"

    remove_container_if_exists "narwhal-monitor-client"
    remove_container_if_exists "narwhal-monitor-server"
    remove_container_if_exists "narwhal-monitor-caddy"

    UNINSTALL_IMAGES_TO_REMOVE=(
      "narwhal-monitor-client:latest"
      "narwhal-monitor-server:latest"
      "ghcr.io/narwhal-cloud/podman-watcher-client:latest"
      "ghcr.io/narwhal-cloud/podman-watcher-server:latest"
      "ghcr.io/${owner}/podman-watcher-client:latest"
      "ghcr.io/${owner}/podman-watcher-server:latest"
      "docker.io/library/caddy:2"
      "ghcr.io/caddy-dns/cloudflare:latest"
      "ghcr.io/caddy-dns/cloudflare:2"
    )

    collect_images_from_saved_configs

    local image=""
    for image in "${UNINSTALL_IMAGES_TO_REMOVE[@]}"; do
      remove_image_if_exists "$image"
    done

    # 清理同仓库下可能存在的非 latest 标签镜像（例如手动指定了版本标签）。
    remove_images_by_repository_pattern '^ghcr\.io/(narwhal-cloud|'"$owner"')/podman-watcher-(client|server)$'
    remove_images_by_repository_pattern '^ghcr\.io/caddy-dns/cloudflare$'
  else
    echo "[WARN] 未检测到 podman，跳过容器/镜像删除，仅清理本项目配置目录。"
  fi

  if [[ -d "$INSTALL_BASE_DIR" ]]; then
    echo "[INFO] 删除配置与数据目录: $INSTALL_BASE_DIR"
    rm -rf "$INSTALL_BASE_DIR"
  fi

  echo "[OK] 卸载完成：Narwhal-Cloud-podman-watcher 相关资源已清理。"
}

main() {
  require_root

  echo "=== Narwhal Monitor 一键安装/更新器 ==="
  echo "该脚本会自动补齐依赖，并启动交互式安装或无感更新。"

  local action
  read -rp "请选择操作 [install/update/uninstall] (默认 install): " action
  action=${action:-install}

  case "$action" in
    install)
      install_deps
      local mode
      read -rp "请选择目标 [server/client/both] (默认 client): " mode
      mode=${mode:-client}
      run_installer "$mode" install
      ;;
    update)
      install_deps
      local mode
      read -rp "请选择目标 [server/client/both] (默认 client): " mode
      mode=${mode:-client}
      update_repo_self
      run_installer "$mode" update
      cleanup_after_update
      ;;
    uninstall)
      uninstall_narwhal_related
      ;;
    *)
      echo "[ERROR] 不支持的操作: $action"
      exit 1
      ;;
  esac

  echo "[OK] $action 流程执行完成。"
}

main "$@"
