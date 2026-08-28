#!/usr/bin/env bash
set -euo pipefail

RAW_BASE="https://raw.githubusercontent.com/iamsxm/Narwhal-Cloud-podman-watcher/main"
INSTALL_DIR="/opt/narwhal-monitor"
APP_DIR="$INSTALL_DIR/client-agent"
VENV_DIR="$APP_DIR/.venv"
ENV_FILE="$INSTALL_DIR/client.env"
SERVICE_FILE="/etc/systemd/system/narwhal-monitor-client.service"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "[ERROR] 请使用 root 权限运行：sudo bash $0"
  exit 1
fi

echo "=========================================="
echo "  Narwhal Monitor Client 独立轻量安装器"
echo "  (无需下载完整仓库源码，仅下载 Client 组件)"
echo "=========================================="

# 1. 检测并安装系统基础依赖
install_dependencies() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "[1/5] 安装系统依赖 (python3, venv, curl)..."
    apt-get update -qq
    apt-get install -y -qq python3 python3-venv python3-pip curl >/dev/null 2>&1 || true
    local py_minor
    py_minor="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true)"
    if [[ -n "$py_minor" ]]; then
      apt-get install -y -qq "python${py_minor}-venv" >/dev/null 2>&1 || true
    fi
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 python3-pip curl >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 python3-pip curl >/dev/null 2>&1 || true
  fi
}

install_dependencies

# 2. 创建目录并下载 client 代码
echo "[2/5] 下载 Client Agent 运行文件..."
mkdir -p "$APP_DIR"

curl -fsSL "$RAW_BASE/VERSION" -o "$INSTALL_DIR/VERSION" 2>/dev/null || echo "1.6.27" > "$INSTALL_DIR/VERSION"
PROJECT_VERSION="$(tr -d '[:space:]' < "$INSTALL_DIR/VERSION")"

curl -fsSL "$RAW_BASE/client/agent.py" -o "$APP_DIR/agent.py"
curl -fsSL "$RAW_BASE/client/requirements.txt" -o "$APP_DIR/requirements.txt"

# 3. 准备 Python 虚拟环境与依赖
echo "[3/5] 构建 Python 运行环境..."
if [[ ! -d "$VENV_DIR" || ! -x "$VENV_DIR/bin/pip" ]]; then
  rm -rf "$VENV_DIR"
  python3 -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/pip" install --upgrade pip -q >/dev/null 2>&1 || true
"$VENV_DIR/bin/pip" install -r "$APP_DIR/requirements.txt" -q >/dev/null 2>&1

# 4. 配置环境变量
echo "[4/5] 配置连接参数..."

# 支持通过环境变量直接传入，未传入则交互式询问
DEFAULT_SERVER_URL="${SERVER_URL:-}"
if [[ -z "$DEFAULT_SERVER_URL" && -f "$ENV_FILE" ]]; then
  DEFAULT_SERVER_URL="$(grep '^SERVER_URL=' "$ENV_FILE" | cut -d= -f2- || true)"
fi
if [[ -z "$DEFAULT_SERVER_URL" ]]; then
  DEFAULT_SERVER_URL="http://127.0.0.1:8080"
fi

DEFAULT_SECRET="${SHARED_SECRET:-}"
if [[ -z "$DEFAULT_SECRET" && -f "$ENV_FILE" ]]; then
  DEFAULT_SECRET="$(grep '^SHARED_SECRET=' "$ENV_FILE" | cut -d= -f2- || true)"
fi

DEFAULT_HOST_ID="${HOST_ID:-}"
if [[ -z "$DEFAULT_HOST_ID" && -f "$ENV_FILE" ]]; then
  DEFAULT_HOST_ID="$(grep '^HOST_ID=' "$ENV_FILE" | cut -d= -f2- || true)"
fi
if [[ -z "$DEFAULT_HOST_ID" ]]; then
  DEFAULT_HOST_ID="$(hostname)"
fi

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

# 如果未通过环境变量传入，则从控制台交互式读取
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
  echo ""
  echo "[ERROR] SHARED_SECRET 不能为空！"
  echo "你可以通过以下任一方式运行："
  echo "1. 交互运行: curl -fsSL $RAW_BASE/scripts/bootstrap-client.sh | sudo bash"
  echo "2. 带参数运行: sudo SERVER_URL=http://x.x.x.x:8080 SHARED_SECRET=你的密钥 HOST_ID=节点名称 bash -c \"\$(curl -fsSL $RAW_BASE/scripts/bootstrap-client.sh)\""
  exit 1
fi

cat >"$ENV_FILE" <<EOF_ENV
NARWHAL_VERSION=$PROJECT_VERSION
SERVER_URL=$SERVER_URL
SHARED_SECRET=$SHARED_SECRET
SERVER_TLS_CA_FILE=
HOST_ID=$HOST_ID
REPORT_INTERVAL=300
ACTION_POLL_INTERVAL=10
CONTAINER_RUNTIMES=auto
DOCKER_MONITOR_MODE=notice
MONITORED_IMAGE_PATTERNS=*
MONITORED_INCUS_PATTERNS=*
INCUS_PROJECT=default
SECURITY_MONITOR_ENABLED=true
SECURITY_CONFIG_AUDIT_ENABLED=true
SECURITY_AUTO_REMEDIATE_XMRIG=true
SECURITY_AUTO_REMEDIATE_XRAYR=true
SECURITY_PANEL_PAIRING_DETECTION_ENABLED=true
SECURITY_ALLOWED_PANEL_DOMAINS=
EOF_ENV
chmod 0600 "$ENV_FILE"

# 5. 配置并启动 systemd 服务
echo "[5/5] 配置并启动 systemd 服务..."
cat >"$SERVICE_FILE" <<EOF_SERVICE
[Unit]
Description=Narwhal Monitor Host Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
Environment=PYTHONUNBUFFERED=1
EnvironmentFile=$ENV_FILE
ExecStart=$VENV_DIR/bin/python $APP_DIR/agent.py
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
echo "  Client Agent 安装成功并已启动！"
echo "  - 版本: $PROJECT_VERSION"
echo "  - 服务名称: narwhal-monitor-client"
echo "  - Server 地址: $SERVER_URL"
echo "  - Host ID: $HOST_ID"
echo "  - 配置文件: $ENV_FILE"
echo "=========================================="
echo ""
echo "查看实时日志请运行: sudo journalctl -u narwhal-monitor-client -f"
