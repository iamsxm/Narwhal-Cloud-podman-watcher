#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

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

main() {
  require_root

  echo "=== Narwhal Monitor 一键安装/更新器 ==="
  echo "该脚本会自动补齐依赖，并启动交互式安装或无感更新。"

  install_deps

  local action
  read -rp "请选择操作 [install/update] (默认 install): " action
  action=${action:-install}

  local mode
  read -rp "请选择目标 [server/client/both] (默认 client): " mode
  mode=${mode:-client}

  case "$action" in
    install)
      run_installer "$mode" install
      ;;
    update)
      update_repo_self
      run_installer "$mode" update
      cleanup_after_update
      ;;
    *)
      echo "[ERROR] 不支持的操作: $action"
      exit 1
      ;;
  esac

  echo "[OK] $action 流程执行完成。"
}

main "$@"
