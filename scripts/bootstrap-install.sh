#!/usr/bin/env bash
set -euo pipefail

REPO_URL_DEFAULT="https://github.com/podcctv/Narwhal-Cloud-podman-watcher.git"
INSTALL_BASE_DEFAULT="/opt"

REPO_URL="${REPO_URL:-$REPO_URL_DEFAULT}"
INSTALL_BASE_DIR="${INSTALL_BASE_DIR:-$INSTALL_BASE_DEFAULT}"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "[ERROR] 请使用 root 运行：sudo bash bootstrap-install.sh"
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "[ERROR] 未检测到 git，且当前系统不支持 apt-get 自动安装。请先手动安装 git。"
    exit 1
  fi
  echo "[INFO] 安装依赖: git"
  apt-get update
  apt-get install -y git
fi

mkdir -p "$INSTALL_BASE_DIR"

repo_name="$(basename "$REPO_URL")"
repo_name="${repo_name%.git}"
repo_dir="$INSTALL_BASE_DIR/$repo_name"

if [[ -d "$repo_dir/.git" ]]; then
  echo "[INFO] 检测到已存在仓库，执行更新: $repo_dir"
  git -C "$repo_dir" fetch --all --prune
  git -C "$repo_dir" pull --ff-only
else
  echo "[INFO] 克隆仓库到: $repo_dir"
  git clone "$REPO_URL" "$repo_dir"
fi

echo "[INFO] 启动一键安装脚本..."
bash "$repo_dir/scripts/install.sh"
