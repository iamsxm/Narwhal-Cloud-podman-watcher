#!/usr/bin/env bash
set -u

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${1:-/tmp/podman-raw-${TS}}"
LOG_DIR="${OUT_DIR}/commands"
CONTAINER_DIR="${OUT_DIR}/containers"
mkdir -p "${LOG_DIR}" "${CONTAINER_DIR}"

SUMMARY_FILE="${OUT_DIR}/summary.txt"
MANIFEST_FILE="${OUT_DIR}/manifest.tsv"

echo -e "name\texit_code\tstdout_file\tstderr_file" > "${MANIFEST_FILE}"

run_cmd() {
  local name="$1"
  shift
  local out_file="${LOG_DIR}/${name}.out"
  local err_file="${LOG_DIR}/${name}.err"

  "$@" >"${out_file}" 2>"${err_file}"
  local code=$?
  echo -e "${name}\t${code}\t${out_file}\t${err_file}" >> "${MANIFEST_FILE}"
  return 0
}

run_shell() {
  local name="$1"
  local cmd="$2"
  local out_file="${LOG_DIR}/${name}.out"
  local err_file="${LOG_DIR}/${name}.err"

  bash -lc "${cmd}" >"${out_file}" 2>"${err_file}"
  local code=$?
  echo -e "${name}\t${code}\t${out_file}\t${err_file}" >> "${MANIFEST_FILE}"
  return 0
}

# Host baseline raw values
run_cmd host_date_utc date -u
run_cmd host_uname uname -a
run_cmd host_uptime uptime
run_cmd host_nproc nproc
run_cmd host_meminfo cat /proc/meminfo
run_cmd host_cpuinfo cat /proc/cpuinfo
run_cmd host_loadavg cat /proc/loadavg
run_cmd host_proc_stat cat /proc/stat
run_cmd host_disk_df df -hT
run_cmd host_disk_df_inode df -i
run_cmd host_net_dev cat /proc/net/dev
run_cmd host_net_snmp cat /proc/net/snmp
run_cmd host_net_sockstat cat /proc/net/sockstat
run_cmd host_ps ps aux --sort=-%cpu
run_shell host_ss_tuna "ss -tuna"

# Podman presence and metadata
if command -v podman >/dev/null 2>&1; then
  PODMAN_BIN="podman"
elif command -v podman-remote >/dev/null 2>&1; then
  PODMAN_BIN="podman-remote"
else
  PODMAN_BIN=""
fi

echo "podman_bin=${PODMAN_BIN}" > "${OUT_DIR}/env.txt"

if [[ -z "${PODMAN_BIN}" ]]; then
  {
    echo "No podman binary found on host."
    echo "Generated at: ${TS}"
    echo "Output dir: ${OUT_DIR}"
  } > "${SUMMARY_FILE}"
  tar -C "$(dirname "${OUT_DIR}")" -czf "${OUT_DIR}.tar.gz" "$(basename "${OUT_DIR}")"
  echo "[DONE] ${OUT_DIR}.tar.gz"
  exit 0
fi

run_cmd podman_version "${PODMAN_BIN}" version --format json
run_cmd podman_info "${PODMAN_BIN}" info --format json
run_cmd podman_ps_all "${PODMAN_BIN}" ps -a --format json
run_cmd podman_network_ls "${PODMAN_BIN}" network ls --format json
run_cmd podman_stats_all "${PODMAN_BIN}" stats --all --no-stream --format json

IDS_FILE="${OUT_DIR}/container_ids.txt"
"${PODMAN_BIN}" ps -a --format '{{.ID}} {{.Names}} {{.State}}' > "${IDS_FILE}" 2>"${OUT_DIR}/container_ids.err"

container_count=0
while IFS=' ' read -r cid cname cstate; do
  [[ -z "${cid:-}" ]] && continue
  container_count=$((container_count + 1))

  safe_name="${cname//[^a-zA-Z0-9_.-]/_}"
  prefix="${CONTAINER_DIR}/${safe_name}_${cid}"

  run_cmd "container_${safe_name}_${cid}_inspect" "${PODMAN_BIN}" inspect "${cid}"
  run_cmd "container_${safe_name}_${cid}_stats" "${PODMAN_BIN}" stats --no-stream --format json "${cid}"
  run_cmd "container_${safe_name}_${cid}_top" "${PODMAN_BIN}" top "${cid}" pid,ppid,user,pcpu,pmem,vsz,rss,time,comm,args
  run_cmd "container_${safe_name}_${cid}_ports" "${PODMAN_BIN}" port "${cid}"

  "${PODMAN_BIN}" inspect "${cid}" > "${prefix}.inspect.json" 2> "${prefix}.inspect.err"
  "${PODMAN_BIN}" stats --no-stream --format json "${cid}" > "${prefix}.stats.json" 2> "${prefix}.stats.err"
  "${PODMAN_BIN}" top "${cid}" pid,ppid,user,pcpu,pmem,vsz,rss,time,comm,args > "${prefix}.top.txt" 2> "${prefix}.top.err"
done < "${IDS_FILE}"

{
  echo "Generated at (UTC): ${TS}"
  echo "Output dir: ${OUT_DIR}"
  echo "Podman command: ${PODMAN_BIN}"
  echo "Container count: ${container_count}"
  echo ""
  echo "Raw values collected include:"
  echo "- Host CPU raw counters (/proc/stat), logical CPU count (nproc), CPU inventory (/proc/cpuinfo), loadavg"
  echo "- Host memory raw values (/proc/meminfo)"
  echo "- Host network counters (/proc/net/dev, /proc/net/snmp, sockstat, ss -tuna)"
  echo "- Host process list (ps aux)"
  echo "- Podman version/info/network/ps"
  echo "- Container inspect full JSON (limits, pid, mounts, net config, state, restart policy...)"
  echo "- Container stats raw JSON (CPU%, MEM usage/limit, NET I/O, BLOCK I/O, PIDs when supported)"
  echo "- Container process table (podman top)"
} > "${SUMMARY_FILE}"

tar -C "$(dirname "${OUT_DIR}")" -czf "${OUT_DIR}.tar.gz" "$(basename "${OUT_DIR}")"

echo "[DONE] bundle: ${OUT_DIR}.tar.gz"
echo "[DONE] summary: ${SUMMARY_FILE}"
echo "请把 tar.gz 或 summary.txt + manifest.tsv 回传，我再基于真实字段改造 client->server 原始值透传与统计分析。"
