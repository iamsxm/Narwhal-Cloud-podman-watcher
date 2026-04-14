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

run_installer() {
  local target="$1"
  case "$target" in
    server)
      bash "$ROOT_DIR/scripts/install-server.sh"
      ;;
    client)
      bash "$ROOT_DIR/scripts/install-client.sh"
      ;;
    both)
      echo "[INFO] 先安装 Server，再安装 Client。"
      bash "$ROOT_DIR/scripts/install-server.sh"
      bash "$ROOT_DIR/scripts/install-client.sh"
      ;;
    *)
      echo "[ERROR] 不支持的安装目标: $target"
      exit 1
      ;;
  esac
}

main() {
  require_root

  echo "=== Narwhal Monitor 一键安装器 ==="
  echo "该脚本会自动补齐依赖，并启动交互式安装。"

  install_deps

  local mode
  read -rp "请选择安装模式 [server/client/both] (默认 client): " mode
  mode=${mode:-client}

  run_installer "$mode"

  echo "[OK] 安装流程执行完成。"
}

main "$@"
