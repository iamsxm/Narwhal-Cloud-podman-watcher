#!/usr/bin/env bash
set -u

BASE_DIR="/opt/narwhal-monitor"
REPO_DIR="/opt/Narwhal-Cloud-podman-watcher"
SERVER_NAME="narwhal-monitor-server"
CADDY_NAME="narwhal-monitor-caddy"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "[ERROR] 请使用 root 运行：sudo bash scripts/diagnose-server.sh"
  exit 1
fi

section() {
  printf '\n===== %s =====\n' "$1"
}

redact_env() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo "missing: $file"
    return
  fi
  awk -F= '
    /^[[:space:]]*($|#)/ { print; next }
    {
      key=$1
      if (toupper(key) ~ /(SECRET|PASSWORD|TOKEN|WEBHOOK|API_KEY|PRIVATE_KEY)/) {
        print key "=[REDACTED]"
      } else {
        print
      }
    }
  ' "$file"
}

container_summary() {
  local name="$1"
  if ! podman container inspect "$name" >/dev/null 2>&1; then
    echo "$name: missing"
    return
  fi
  podman inspect --format \
    'id={{.Id}} name={{.Name}} status={{.State.Status}} running={{.State.Running}} pid={{.State.Pid}} conmon={{.State.ConmonPid}} image={{.ImageName}} ports={{json .NetworkSettings.Ports}} networks={{json .NetworkSettings.Networks}}' \
    "$name" 2>&1 || true
}

section "HOST"
hostnamectl 2>/dev/null || hostname
date -Is
uname -a
df -h / "$BASE_DIR" 2>/dev/null || true

section "REPOSITORY"
if [[ -d "$REPO_DIR/.git" ]]; then
  printf 'version='; tr -d '[:space:]' <"$REPO_DIR/VERSION" 2>/dev/null || true; echo
  git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null || true
  git -C "$REPO_DIR" status --short 2>/dev/null || true
else
  echo "missing: $REPO_DIR"
fi

section "AUTO UPDATE"
systemctl status narwhal-monitor-server-update.service \
  narwhal-monitor-server-update.timer --no-pager -l 2>&1 || true
systemctl show narwhal-monitor-server-update.service \
  -p Result -p KillMode -p Delegate -p TimeoutStartUSec -p TimeoutStopUSec 2>/dev/null || true
journalctl -u narwhal-monitor-server-update.service -n 100 --no-pager \
  -o short-iso 2>/dev/null | grep -E 'systemd\[1\]|auto-update.sh\[' || true

section "PODMAN"
podman info --format \
  'version={{.Version.Version}} network_backend={{.Host.NetworkBackend}} cgroup_manager={{.Host.CgroupManager}} database_backend={{.Host.DatabaseBackend}}' \
  2>&1 || true
podman ps -a --no-trunc --format \
  'table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}\t{{.Image}}' 2>&1 || true
container_summary "$SERVER_NAME"
container_summary "$CADDY_NAME"
podman stats --no-stream --format \
  'table {{.Name}}\tCPU={{.CPU}}\tMEM={{.MemUsage}}\tNET={{.NetIO}}\tPIDS={{.PIDs}}' \
  "$SERVER_NAME" "$CADDY_NAME" 2>&1 || true

section "LIBPOD SCOPES"
systemctl list-units --type=scope --all --no-pager 2>/dev/null \
  | grep -E 'libpod-(conmon-)?[0-9a-f]{12}|UNIT' || true
echo "提示：同一 Narwhal 组件出现多个 active libpod scope，通常表示旧版更新误杀 conmon 后留下 OCI 孤立进程。"

section "NETWORK AND HTTP"
ss -ltnp 2>/dev/null | grep -E ':(80|443|8080|[0-9]{5})[[:space:]]' || true
backend_port="$(awk -F= '$1=="PORT"{print $2;exit}' "$BASE_DIR/server-install.env" 2>/dev/null || true)"
if [[ "$backend_port" =~ ^[0-9]{1,5}$ ]]; then
  curl --max-time 5 -sS -o /dev/null \
    -w "backend_127.0.0.1:${backend_port}=%{http_code} error=%{errormsg}\n" \
    "http://127.0.0.1:${backend_port}/" || true
fi
tls_host="$(awk -F= '$1=="TLS_HOST"{print substr($0,index($0,"=")+1);exit}' "$BASE_DIR/server-install.env" 2>/dev/null || true)"
if [[ -n "$tls_host" ]]; then
  curl --max-time 5 -k -sS -o /dev/null \
    -w "https_${tls_host}=%{http_code} error=%{errormsg}\n" \
    "https://${tls_host}/" || true
fi

section "REDACTED SERVER CONFIG"
redact_env "$BASE_DIR/server-install.env"
redact_env "$BASE_DIR/server.env"

section "RECENT SERVER LOG"
timeout 10 podman logs --tail 80 "$SERVER_NAME" 2>&1 || true

section "RECENT CADDY LOG"
timeout 10 podman logs --tail 80 "$CADDY_NAME" 2>&1 || true

echo
echo "[OK] 只读诊断完成；输出中的密钥、密码、Token 与 Webhook 已隐藏。"
