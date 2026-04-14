#!/usr/bin/env bash
set -euo pipefail

# 用法:
#   bash scripts/query-single-container.sh <容器名或ID>
# 例子:
#   bash scripts/query-single-container.sh fuckip-agent
#   bash scripts/query-single-container.sh 61736e1d9d7b

TARGET="${1:-}"
if [[ -z "${TARGET}" ]]; then
  echo "用法: bash scripts/query-single-container.sh <容器名或ID>" >&2
  exit 1
fi

if command -v podman >/dev/null 2>&1; then
  RUNTIME="podman"
elif command -v podman-remote >/dev/null 2>&1; then
  RUNTIME="podman-remote"
else
  echo "未找到 podman 或 podman-remote" >&2
  exit 1
fi

echo "[info] runtime=${RUNTIME}"
echo "[info] target=${TARGET}"

echo "\n===== 1) 容器是否存在 ====="
"${RUNTIME}" ps -a --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}' | grep -E "(^|\|)${TARGET}(\||$)" || true

echo "\n===== 2) stats(json) ====="
"${RUNTIME}" stats --no-stream --format json "${TARGET}" || true

echo "\n===== 3) stats(兼容格式) ====="
"${RUNTIME}" stats --no-stream --format '{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}|{{.NetInput}}|{{.NetOutput}}' "${TARGET}" || true

echo "\n===== 4) inspect 关键字段 ====="
"${RUNTIME}" inspect "${TARGET}" --format 'name={{.Name}} pid={{.State.Pid}} running={{.State.Running}} status={{.State.Status}} started={{.State.StartedAt}}'

echo "\n===== 5) top ====="
"${RUNTIME}" top "${TARGET}" pcpu,pid,comm,args || true

echo "\n===== 6) 若网络值仍为空，读 /proc/<pid>/net/dev ====="
PID="$("${RUNTIME}" inspect "${TARGET}" --format '{{.State.Pid}}' 2>/dev/null || true)"
if [[ -n "${PID}" && "${PID}" != "0" && -r "/proc/${PID}/net/dev" ]]; then
  echo "pid=${PID}"
  cat "/proc/${PID}/net/dev"
else
  echo "无法读取 /proc/<pid>/net/dev（可能容器未运行或权限限制）"
fi

