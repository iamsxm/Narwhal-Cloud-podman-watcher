#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="iamsxm"
REPO_NAME="Narwhal-Cloud-podman-watcher"
INSTALL_DIR="/opt/narwhal-monitor"
BIN_PATH="$INSTALL_DIR/narwhal-client"
ENV_FILE="$INSTALL_DIR/client.env"
SERVICE_FILE="/etc/systemd/system/narwhal-monitor-client.service"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "[ERROR] 请使用 root 权限运行：sudo bash $0"
  exit 1
fi

echo "=========================================="
echo "  Narwhal Monitor Rust 二进制客户端安装器"
echo "  (0 Python 依赖、静态单文件、极速启动)"
echo "=========================================="

# 1. 架构检测
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)
    ASSET_NAME="narwhal-client-linux-amd64"
    ;;
  aarch64|arm64)
    ASSET_NAME="narwhal-client-linux-arm64"
    ;;
  *)
    echo "[ERROR] 不支持的架构: $ARCH"
    exit 1
    ;;
esac

echo "[1/4] 检测到系统架构: $ARCH ($ASSET_NAME)"

# 2. 下载二进制文件
mkdir -p "$INSTALL_DIR"
DOWNLOAD_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/latest/download/${ASSET_NAME}"

echo "[2/4] 从 GitHub Release 下载静态二进制..."
if ! curl -fsSL "$DOWNLOAD_URL" -o "$BIN_PATH.tmp"; then
  # 降级尝试从具体版本或 Raw 下载
  echo "[WARN] latest release 下载失败，尝试从 Release 资产获取..."
  VERSION="$(curl -fsSL "https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/main/VERSION" 2>/dev/null || echo "1.6.28")"
  DOWNLOAD_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/v${VERSION}/${ASSET_NAME}"
  curl -fsSL "$DOWNLOAD_URL" -o "$BIN_PATH.tmp"
fi

mv "$BIN_PATH.tmp" "$BIN_PATH"
chmod +x "$BIN_PATH"

# 3. 收集并保存配置
echo "[3/4] 配置连接参数..."

ask_input() {
  local prompt="$1"
  local default_val="$2"
  local user_input=""
  if [[ -c /dev/tty ]]; then
    printf "%s" "$prompt" >/dev/tty
    read -r user_input </dev/tty || true
  fi
  if [[ -n "$user_input" ]]; then
    printf "%s" "$user_input"
  else
    printf "%s" "$default_val"
  fi
}

DEFAULT_SERVER_URL="${SERVER_URL:-}"
if [[ -z "$DEFAULT_SERVER_URL" && -f "$ENV_FILE" ]]; then
  DEFAULT_SERVER_URL="$(grep '^SERVER_URL=' "$ENV_FILE" | cut -d= -f2- || true)"
fi
DEFAULT_SERVER_URL="${DEFAULT_SERVER_URL:-http://127.0.0.1:8080}"

DEFAULT_SECRET="${SHARED_SECRET:-}"
if [[ -z "$DEFAULT_SECRET" && -f "$ENV_FILE" ]]; then
  DEFAULT_SECRET="$(grep '^SHARED_SECRET=' "$ENV_FILE" | cut -d= -f2- || true)"
fi

DEFAULT_HOST_ID="${HOST_ID:-}"
if [[ -z "$DEFAULT_HOST_ID" && -f "$ENV_FILE" ]]; then
  DEFAULT_HOST_ID="$(grep '^HOST_ID=' "$ENV_FILE" | cut -d= -f2- || true)"
fi
DEFAULT_HOST_ID="${DEFAULT_HOST_ID:-$(hostname)}"

if [[ -z "${SERVER_URL:-}" ]]; then
  SERVER_URL="$(ask_input "请输入 Server 地址 [$DEFAULT_SERVER_URL]: " "$DEFAULT_SERVER_URL")"
fi

if [[ -z "${SHARED_SECRET:-}" ]]; then
  SHARED_SECRET="$(ask_input "请输入通信密钥 SHARED_SECRET [${DEFAULT_SECRET:-必填}]: " "$DEFAULT_SECRET")"
fi

if [[ -z "${HOST_ID:-}" ]]; then
  HOST_ID="$(ask_input "请输入当前主机 ID HOST_ID [$DEFAULT_HOST_ID]: " "$DEFAULT_HOST_ID")"
fi

if [[ -z "$SHARED_SECRET" ]]; then
  echo "[ERROR] SHARED_SECRET 不能为空！"
  exit 1
fi

cat >"$ENV_FILE" <<EOF_ENV
SERVER_URL=$SERVER_URL
SHARED_SECRET=$SHARED_SECRET
HOST_ID=$HOST_ID
REPORT_INTERVAL=300
ACTION_POLL_INTERVAL=10
CONTAINER_RUNTIMES=auto
DOCKER_MONITOR_MODE=notice
MONITORED_IMAGE_PATTERNS=*
MONITORED_INCUS_PATTERNS=*
INCUS_PROJECT=default
SECURITY_MONITOR_ENABLED=true
EOF_ENV
chmod 0600 "$ENV_FILE"

# 4. 配置 systemd 服务
echo "[4/4] 注册并启动 systemd 服务..."
cat >"$SERVICE_FILE" <<EOF_SERVICE
[Unit]
Description=Narwhal Monitor Rust Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$BIN_PATH
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF_SERVICE

systemctl daemon-reload
systemctl enable narwhal-monitor-client.service >/dev/null 2>&1
systemctl restart narwhal-monitor-client.service

echo ""
echo "=========================================="
echo "  Rust 客户端部署完成！"
echo "  - 二进制路径: $BIN_PATH"
echo "  - 服务状态: 运行中 (Active)"
echo "  - 日志查看: sudo journalctl -u narwhal-monitor-client -f"
echo "=========================================="
