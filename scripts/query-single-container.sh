#!/usr/bin/env bash
set -euo pipefail

# 用法:
#   bash scripts/query-single-container.sh <容器名或ID> [podman|docker|incus]
# 例子:
#   bash scripts/query-single-container.sh fuckip-agent
#   bash scripts/query-single-container.sh 61736e1d9d7b

TARGET="${1:-}"
RUNTIME="${2:-}"
if [[ -z "${TARGET}" ]]; then
  echo "用法: bash scripts/query-single-container.sh <容器名或ID> [podman|docker|incus]" >&2
  exit 1
fi

if [[ -z "$RUNTIME" ]]; then
  for candidate in podman podman-remote docker incus; do
    command -v "$candidate" >/dev/null 2>&1 || continue
    if [[ "$candidate" == "incus" ]]; then
      if "$candidate" list "$TARGET" type=container --format csv,noheader -c n 2>/dev/null | grep -Fxq "$TARGET"; then
        RUNTIME="$candidate"
        break
      fi
    elif "$candidate" inspect "$TARGET" >/dev/null 2>&1; then
      RUNTIME="$candidate"
      break
    fi
  done
fi

if [[ -z "$RUNTIME" ]] || ! command -v "$RUNTIME" >/dev/null 2>&1; then
  echo "未找到目标容器或对应运行时（podman/docker/incus）" >&2
  exit 1
fi

echo "[info] runtime=${RUNTIME}"
echo "[info] target=${TARGET}"

if [[ "$RUNTIME" == "incus" ]]; then
  echo "\n===== 1) Incus 容器是否存在 ====="
  incus list "$TARGET" type=container --format json || true

  echo "\n===== 2) Incus 原始指标 ====="
  incus query /1.0/metrics | grep -E "name=\"${TARGET}\"" || true

  echo "\n===== 3) Incus 状态 ====="
  incus query "/1.0/instances/${TARGET}/state" || true

  echo "\n===== 4) 容器内存/磁盘/网络 ====="
  incus exec "$TARGET" -- sh -lc 'cat /proc/meminfo; df -P / /data 2>/dev/null || true; cat /proc/net/dev' || true

  echo "\n===== 5) top ====="
  incus exec "$TARGET" -- ps -eo pcpu,pid,comm,args || true
  exit 0
fi

echo "\n===== 1) 容器是否存在 ====="
"${RUNTIME}" ps -a --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}' | grep -E "(^|\|)${TARGET}(\||$)" || true

echo "\n===== 2) stats(json) ====="
"${RUNTIME}" stats --no-stream --format json "${TARGET}" || true

echo "\n===== 3) stats(兼容格式) ====="
stats_templates=(
  '{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}'
  '{{.CPU}}|{{.MemUsage}}|{{.NetIO}}'
  '{{.CPU}}|{{.MemUsageBytes}}|{{.NetIO}}'
)
stats_rendered=""
for tpl in "${stats_templates[@]}"; do
  if stats_rendered="$("${RUNTIME}" stats --no-stream --format "${tpl}" "${TARGET}" 2>/dev/null)"; then
    if [[ -n "${stats_rendered}" ]]; then
      echo "${stats_rendered}"
      break
    fi
  fi
done

if [[ -z "${stats_rendered}" ]]; then
  echo "未获取到兼容格式输出（不同 Podman/Docker 版本模板字段可能不同）"
fi

echo "\n===== 4) inspect 关键字段 ====="
"${RUNTIME}" inspect "${TARGET}" --format 'name={{.Name}} pid={{.State.Pid}} running={{.State.Running}} status={{.State.Status}} started={{.State.StartedAt}}'

echo "\n===== 5) top ====="
if [[ "$RUNTIME" == "docker" ]]; then
  "${RUNTIME}" top "${TARGET}" -eo pcpu,pid,comm,args || true
else
  "${RUNTIME}" top "${TARGET}" pcpu,pid,comm,args || true
fi

echo "\n===== 6) 若网络值仍为空，读 /proc/<pid>/net/dev ====="
PID="$("${RUNTIME}" inspect "${TARGET}" --format '{{.State.Pid}}' 2>/dev/null || true)"
if [[ -n "${PID}" && "${PID}" != "0" && -r "/proc/${PID}/net/dev" ]]; then
  echo "pid=${PID}"
  cat "/proc/${PID}/net/dev"
else
  echo "无法读取 /proc/<pid>/net/dev（可能容器未运行或权限限制）"
fi
