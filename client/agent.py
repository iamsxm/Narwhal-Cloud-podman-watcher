import argparse
import hmac
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import time
from typing import Dict, List, Tuple

import requests
from urllib.parse import urlparse


_warned_missing_bins = set()
_podman_bin = None
_container_bin = None
_net_counters: Dict[str, Dict[str, float]] = {}
_warned_parse_paths = set()


def _is_containerized_runtime() -> bool:
    return os.path.exists("/run/.containerenv") or os.path.exists("/.dockerenv")


def get_podman_bin() -> str:
    global _podman_bin
    if _podman_bin is not None:
        return _podman_bin

    # In containerized deployments we usually mount the host Podman socket.
    # Prefer podman-remote in containers so we can inspect host containers.
    # For host-based agents prefer local podman first, because podman-remote
    # often exists but is not configured with a valid CONTAINER_HOST.
    bin_candidates = ("podman-remote", "podman") if _is_containerized_runtime() else ("podman", "podman-remote")
    for name in bin_candidates:
        if shutil.which(name):
            _podman_bin = name
            return _podman_bin

    _podman_bin = ""
    if "podman" not in _warned_missing_bins:
        _warned_missing_bins.add("podman")
        print("missing command: podman (or podman-remote)")
    return _podman_bin


def get_container_bin() -> str:
    global _container_bin
    if _container_bin is not None:
        return _container_bin

    podman = get_podman_bin()
    if podman:
        _container_bin = podman
        return _container_bin

    docker_bin = shutil.which("docker")
    if docker_bin:
        _container_bin = "docker"
        return _container_bin

    _container_bin = ""
    if "container_runtime" not in _warned_missing_bins:
        _warned_missing_bins.add("container_runtime")
        print("missing command: podman (or podman-remote) / docker")
    return _container_bin


def run(cmd: List[str]) -> str:
    env = None
    if cmd and cmd[0] == "podman-remote":
        socket_path = os.getenv("PODMAN_SOCKET", "/run/podman/podman.sock")
        if "CONTAINER_HOST" not in os.environ and os.path.exists(socket_path):
            env = os.environ.copy()
            env["CONTAINER_HOST"] = f"unix://{socket_path}"
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    except FileNotFoundError:
        if cmd and cmd[0] not in _warned_missing_bins:
            _warned_missing_bins.add(cmd[0])
            print(f"missing command: {cmd[0]}")
        return ""
    if p.returncode != 0:
        return ""
    return p.stdout


def parse_size(s: str) -> int:
    m = re.match(r"([0-9.]+)([kKmMgGtTpP]?[bB]?)?", s.strip())
    if not m:
        return 0
    n = float(m.group(1))
    unit = (m.group(2) or "").lower()
    mult = 1
    if unit.startswith("k"):
        mult = 1024
    elif unit.startswith("m"):
        mult = 1024**2
    elif unit.startswith("g"):
        mult = 1024**3
    elif unit.startswith("t"):
        mult = 1024**4
    return int(n * mult)


def _normalize_stat_number(raw: object) -> float:
    if raw is None:
        return 0.0
    if isinstance(raw, (int, float)):
        return float(raw)
    text = str(raw).strip()
    if not text:
        return 0.0
    if text.endswith("%"):
        text = text[:-1].strip()
    try:
        return float(text)
    except ValueError:
        return 0.0


def _normalize_key(key: object) -> str:
    text = str(key or "").strip().lower()
    return "".join(ch for ch in text if ch.isalnum())


def _find_value_ci(item: Dict[str, object], keys: List[str]) -> object:
    if not isinstance(item, dict):
        return None
    normalized_map = {_normalize_key(k): v for k, v in item.items()}
    for key in keys:
        k = _normalize_key(key)
        if k in normalized_map and normalized_map[k] is not None:
            return normalized_map[k]
    return None


def _pick_first(item: Dict[str, object], keys: List[str]) -> object:
    for key in keys:
        if key in item and item.get(key) is not None:
            return item.get(key)
    return None


def _parse_stats_json(stats_text: str) -> Dict[str, float | int]:
    cpu_percent = 0.0
    mem_bytes = 0
    net_rx_total_bytes = 0
    net_tx_total_bytes = 0

    if not stats_text:
        return {
            "cpu_percent": cpu_percent,
            "mem_bytes": mem_bytes,
            "net_rx_total_bytes": net_rx_total_bytes,
            "net_tx_total_bytes": net_tx_total_bytes,
        }

    try:
        payload = json.loads(stats_text)
    except Exception:
        payload = None

    item = None
    if isinstance(payload, list) and payload:
        item = payload[0]
    elif isinstance(payload, dict):
        item = payload

    if isinstance(item, dict):
        cpu_percent = _normalize_stat_number(
            _find_value_ci(item, ["CPU", "CPUPerc", "CPU%", "cpu_percent", "cpu"])
            or _pick_first(item, ["CPU", "CPUPerc", "CPU%"])
        )
        if cpu_percent <= 0:
            cpu_nano = _normalize_stat_number(
                _find_value_ci(item, ["CPUNano", "cpu_nano", "cpu_nanoseconds", "cpu_time"])
            )
            if cpu_nano > 0:
                # 某些运行时仅提供累计 CPU 时间，无法可靠算百分比。
                # 这里保留为 0，后续会尝试 template/top 兜底。
                cpu_percent = 0.0

        mem_usage = _find_value_ci(item, ["MemUsage", "Mem Usage", "mem_usage", "memory"])
        if mem_usage is None:
            mem_usage = _pick_first(item, ["MemUsage", "Mem Usage"])
        if mem_usage is not None:
            mem_bytes = parse_size(str(mem_usage).split("/")[0].strip())
        else:
            mem_bytes = int(
                _normalize_stat_number(
                    _find_value_ci(item, ["MemUsageBytes", "MemUsageBytesValue", "mem_usage_bytes", "memory_bytes"])
                    or _pick_first(item, ["MemUsageBytes", "MemUsageBytesValue"])
                )
            )

        net_io = _find_value_ci(item, ["NetIO", "Net I/O", "net_io"])
        if net_io is None:
            net_io = _pick_first(item, ["NetIO", "Net I/O"])
        if net_io is not None:
            net = str(net_io).split("/")
            if len(net) == 2:
                net_rx_total_bytes = parse_size(net[0].strip())
                net_tx_total_bytes = parse_size(net[1].strip())
        else:
            net_in = _normalize_stat_number(
                _find_value_ci(item, ["NetInput", "Net In", "net_input", "rxbytes", "rx"])
                or _pick_first(item, ["NetInput", "Net In"])
            )
            net_out = _normalize_stat_number(
                _find_value_ci(item, ["NetOutput", "Net Out", "net_output", "txbytes", "tx"])
                or _pick_first(item, ["NetOutput", "Net Out"])
            )
            net_rx_total_bytes = int(net_in)
            net_tx_total_bytes = int(net_out)

        if net_rx_total_bytes <= 0 and net_tx_total_bytes <= 0:
            network_obj = _find_value_ci(item, ["Network", "Networks", "network", "networks"])
            if isinstance(network_obj, dict):
                rx_sum = 0.0
                tx_sum = 0.0
                for net_item in network_obj.values():
                    if not isinstance(net_item, dict):
                        continue
                    rx_sum += _normalize_stat_number(
                        _find_value_ci(net_item, ["RxBytes", "rx_bytes", "rx", "received"])
                    )
                    tx_sum += _normalize_stat_number(
                        _find_value_ci(net_item, ["TxBytes", "tx_bytes", "tx", "transmit"])
                    )
                net_rx_total_bytes = int(rx_sum)
                net_tx_total_bytes = int(tx_sum)

    return {
        "cpu_percent": cpu_percent,
        "mem_bytes": mem_bytes,
        "net_rx_total_bytes": net_rx_total_bytes,
        "net_tx_total_bytes": net_tx_total_bytes,
    }


def _parse_stats_template(stats_text: str) -> Dict[str, float | int]:
    cpu_percent = 0.0
    mem_bytes = 0
    net_rx_total_bytes = 0
    net_tx_total_bytes = 0

    parts = (stats_text or "").strip().split("|")
    if len(parts) >= 3:
        cpu_percent = _normalize_stat_number(parts[0])
        mem_bytes = parse_size(parts[1].split("/")[0].strip())
        net = parts[2].split("/")
        if len(net) == 2:
            net_rx_total_bytes = parse_size(net[0].strip())
            net_tx_total_bytes = parse_size(net[1].strip())
        if len(parts) >= 4 and net_rx_total_bytes <= 0:
            net_rx_total_bytes = parse_size(parts[2].strip())
        if len(parts) >= 5 and net_tx_total_bytes <= 0:
            net_tx_total_bytes = parse_size(parts[3].strip())

    return {
        "cpu_percent": cpu_percent,
        "mem_bytes": mem_bytes,
        "net_rx_total_bytes": net_rx_total_bytes,
        "net_tx_total_bytes": net_tx_total_bytes,
    }


def _parse_stats_compact(stats_text: str) -> Dict[str, float | int]:
    parts = (stats_text or "").strip().split("|")
    if len(parts) < 4:
        return {"cpu_percent": 0.0, "mem_bytes": 0, "net_rx_total_bytes": 0, "net_tx_total_bytes": 0}
    return {
        "cpu_percent": _normalize_stat_number(parts[0]),
        "mem_bytes": parse_size(parts[1]),
        "net_rx_total_bytes": parse_size(parts[2]),
        "net_tx_total_bytes": parse_size(parts[3]),
    }


def _derive_net_bps(container_key: str, rx_total: int, tx_total: int) -> Tuple[float, float]:
    now = float(time.time())
    prev = _net_counters.get(container_key)
    _net_counters[container_key] = {"ts": now, "rx": float(rx_total), "tx": float(tx_total)}
    if not prev:
        return 0.0, 0.0

    dt = now - float(prev.get("ts", 0.0))
    if dt <= 0:
        return 0.0, 0.0

    rx_delta = max(0.0, float(rx_total) - float(prev.get("rx", 0.0)))
    tx_delta = max(0.0, float(tx_total) - float(prev.get("tx", 0.0)))
    return rx_delta / dt, tx_delta / dt


def _count_proc_net_lines(path: str) -> int:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    except Exception:
        return 0
    if len(lines) <= 1:
        return 0
    return len(lines) - 1


def _count_connections_from_pid(pid: int) -> int:
    if pid <= 0:
        return 0
    base = f"/proc/{pid}/net"
    files = ("tcp", "tcp6", "udp", "udp6")
    total = 0
    for name in files:
        total += _count_proc_net_lines(f"{base}/{name}")
    return total


def _read_net_bytes_from_pid(pid: int) -> Tuple[int, int]:
    if pid <= 0:
        return 0, 0
    path = f"/proc/{pid}/net/dev"
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    except Exception:
        return 0, 0
    if len(lines) <= 2:
        return 0, 0

    rx_total = 0
    tx_total = 0
    for line in lines[2:]:
        if ":" not in line:
            continue
        _, data = line.split(":", 1)
        cols = data.split()
        if len(cols) < 16:
            continue
        try:
            rx_total += int(cols[0])
            tx_total += int(cols[8])
        except ValueError:
            continue
    return rx_total, tx_total


def _count_connections_from_exec(runtime: str, name: str) -> int:
    if not runtime:
        return 0
    out = run(
        [
            runtime,
            "exec",
            name,
            "sh",
            "-lc",
            "ss -Hantup 2>/dev/null | wc -l || (netstat -antup 2>/dev/null | tail -n +3 | wc -l)",
        ]
    )
    return int(out.strip() or 0) if out.strip().isdigit() else 0


def collect_top_cpu_process(name: str) -> Dict[str, object]:
    runtime = get_container_bin()
    if not runtime:
        return {"pid": 0, "cpu_percent": 0.0, "command": ""}

    top_cmd = [runtime, "top", name, "pcpu,pid,comm,args"]
    if runtime == "docker":
        top_cmd = [runtime, "top", name, "-eo", "pcpu,pid,comm,args"]
    out = run(top_cmd)
    best = {"pid": 0, "cpu_percent": 0.0, "command": ""}
    for line in out.splitlines():
        text = line.strip()
        if not text or text.lower().startswith("pcpu"):
            continue
        parts = text.split(None, 3)
        if len(parts) < 3:
            continue
        cpu = _normalize_stat_number(parts[0])
        pid = int(parts[1]) if parts[1].isdigit() else 0
        cmd = parts[3] if len(parts) >= 4 else parts[2]
        if cpu >= float(best["cpu_percent"]):
            best = {"pid": pid, "cpu_percent": cpu, "command": cmd}
    return best


def _image_matches(image: str, patterns: List[str]) -> bool:
    if not patterns:
        return False
    val = image.strip().lower()
    for p in patterns:
        token = p.strip().lower()
        if not token:
            continue
        if token in val:
            return True
    return False


def podman_containers() -> List[Dict[str, str]]:
    runtime = get_container_bin()
    if not runtime:
        return []
    patterns_env = os.getenv(
        "MONITORED_IMAGE_PATTERNS",
        "docker.io/narwhalcloud/debian,docker.io/library/alpine,alpine",
    )
    patterns = [x.strip() for x in patterns_env.split(",") if x.strip()]
    out = run([runtime, "ps", "--format", "{{.ID}}|{{.Names}}|{{.Image}}"])
    items: List[Dict[str, str]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("|", 2)
        if len(parts) != 3:
            continue
        container_id, name, image = parts
        image = image.strip()
        if not _image_matches(image, patterns):
            continue
        items.append({"id": container_id.strip(), "name": name.strip(), "image": image})
    return items




def _parse_df_target(df_out: str, target: str) -> Dict[str, int]:
    for line in df_out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        mountpoint = parts[5]
        if mountpoint != target:
            continue
        return {
            "total_bytes": int(parts[1]) * 1024,
            "avail_bytes": int(parts[3]) * 1024,
        }
    return {"total_bytes": 0, "avail_bytes": 0}


def collect_container_disk_usage(name: str) -> Dict[str, Dict[str, int] | int]:
    runtime = get_container_bin()
    if not runtime:
        return {
            "rw_bytes": 0,
            "rootfs_bytes": 0,
            "fs": {"root": {"total_bytes": 0, "avail_bytes": 0}, "data": {"total_bytes": 0, "avail_bytes": 0}},
        }

    rw_bytes = 0
    rootfs_bytes = 0
    inspect = run([runtime, "container", "inspect", "--size", name])
    if inspect:
        try:
            item = json.loads(inspect)[0]
            rw_bytes = int(item.get("SizeRw") or 0)
            rootfs_bytes = int(item.get("SizeRootFs") or 0)
        except Exception:
            pass

    fs_df = run([runtime, "exec", name, "sh", "-lc", "df -P / /data 2>/dev/null || true"])
    fs = {
        "root": _parse_df_target(fs_df, "/"),
        "data": _parse_df_target(fs_df, "/data"),
    }
    return {"rw_bytes": rw_bytes, "rootfs_bytes": rootfs_bytes, "fs": fs}


def collect_container(name: str, container_id: str = "") -> Dict:
    runtime = get_container_bin()
    if not runtime:
        return {
            "id": container_id,
            "name": name,
            "cpu_percent": 0.0,
            "mem_bytes": 0,
            "net_rx_bps": 0.0,
            "net_tx_bps": 0.0,
            "conn_count": 0,
            "disk": collect_disk_alert(),
            "container_disk": {"rw_bytes": 0, "rootfs_bytes": 0},
        }

    cpu_percent = 0.0
    mem = 0
    rx_total = 0
    tx_total = 0
    net_rx = 0.0
    net_tx = 0.0

    stats_json = run([runtime, "stats", "--no-stream", "--format", "json", name])
    parsed_stats = _parse_stats_json(stats_json)
    stats_tpl = run([runtime, "stats", "--no-stream", "--format", "{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}|{{.NetInput}}|{{.NetOutput}}", name])
    parsed_tpl = _parse_stats_template(stats_tpl)
    stats_compact = run([runtime, "stats", "--no-stream", "--format", "{{.CPU}}|{{.MemUsageBytes}}|{{.NetInput}}|{{.NetOutput}}", name])
    parsed_compact = _parse_stats_compact(stats_compact)

    cpu_candidates = [parsed_stats["cpu_percent"], parsed_tpl["cpu_percent"], parsed_compact["cpu_percent"]]
    mem_candidates = [parsed_stats["mem_bytes"], parsed_tpl["mem_bytes"], parsed_compact["mem_bytes"]]
    net_candidates = [
        (parsed_stats["net_rx_total_bytes"], parsed_stats["net_tx_total_bytes"]),
        (parsed_tpl["net_rx_total_bytes"], parsed_tpl["net_tx_total_bytes"]),
        (parsed_compact["net_rx_total_bytes"], parsed_compact["net_tx_total_bytes"]),
    ]

    for c in cpu_candidates:
        if float(c) > 0:
            cpu_percent = float(c)
            break
    for m in mem_candidates:
        if int(m) > 0:
            mem = int(m)
            break
    for rx_c, tx_c in net_candidates:
        if int(rx_c) > 0 or int(tx_c) > 0:
            rx_total = int(rx_c)
            tx_total = int(tx_c)
            break

    inspect = run([runtime, "inspect", name])
    conn_count = 0
    pid = 0
    if inspect:
        try:
            d = json.loads(inspect)[0]
            pid = int(d.get("State", {}).get("Pid", 0) or 0)
            if pid:
                conn_count = _count_connections_from_pid(pid)
                if conn_count <= 0:
                    conn_out = run(["sh", "-lc", f"ss -Hantup | grep -c 'pid={pid},'"])
                    conn_count = int(conn_out.strip() or 0)
        except Exception:
            pass

    if rx_total <= 0 and tx_total <= 0 and pid > 0:
        proc_rx, proc_tx = _read_net_bytes_from_pid(pid)
        if proc_rx > 0 or proc_tx > 0:
            rx_total = proc_rx
            tx_total = proc_tx

    container_key = container_id or name
    net_rx, net_tx = _derive_net_bps(container_key, rx_total, tx_total)

    if stats_json.strip() == "" and stats_tpl.strip() == "" and stats_compact.strip() == "":
        warn_key = f"{runtime}:stats-empty"
        if warn_key not in _warned_parse_paths:
            _warned_parse_paths.add(warn_key)
            print(f"warn: '{runtime} stats' returned empty output; CPU/内存/网络将显示为 0。")
    if conn_count <= 0:
        conn_count = _count_connections_from_exec(runtime, name)

    disk = collect_disk_alert()
    container_disk = collect_container_disk_usage(name)
    top_cpu_process = collect_top_cpu_process(name)
    if cpu_percent <= 0 and float(top_cpu_process.get("cpu_percent") or 0) > 0:
        cpu_percent = float(top_cpu_process.get("cpu_percent") or 0)
    return {
        "id": container_id,
        "name": name,
        "cpu_percent": cpu_percent,
        "mem_bytes": mem,
        "net_rx_bps": net_rx,
        "net_tx_bps": net_tx,
        "conn_count": conn_count,
        "disk": disk,
        "container_disk": container_disk,
        "top_cpu_process": top_cpu_process,
    }


def collect_disk_alert() -> Dict:
    file_path = os.getenv("WATCH_DISK_FILE", "/xfs_disk.img")
    image_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

    root_device = ""
    root_avail_bytes = 0
    root_total_bytes = 0
    df_root = run(["df", "-P", "/"])
    if df_root:
        lines = df_root.splitlines()
        if len(lines) >= 2:
            parts = lines[1].split()
            if len(parts) >= 6:
                root_device = parts[0]
                root_total_bytes = int(parts[1]) * 1024
                root_avail_bytes = int(parts[3]) * 1024

    data_avail_bytes = 0
    data_total_bytes = 0
    df = run(["df", "-P", "/data"])
    used = 0.0
    if df:
        lines = df.splitlines()
        if len(lines) >= 2:
            parts = lines[1].split()
            if len(parts) >= 6:
                used = float(parts[4].rstrip("%"))
                data_total_bytes = int(parts[1]) * 1024
                data_avail_bytes = int(parts[3]) * 1024
    return {
        "file": file_path,
        "size_bytes": image_size,
        "used_percent": used,
        "root_device": root_device,
        "root_total_bytes": root_total_bytes,
        "root_avail_bytes": root_avail_bytes,
        "data_total_bytes": data_total_bytes,
        "data_avail_bytes": data_avail_bytes,
    }


def network_health() -> Tuple[bool, bool]:
    runtime = get_container_bin()
    if not runtime:
        return False, False

    network_probe_prefix = "echo ok"
    if runtime != "docker":
        network_probe_prefix = f"{runtime} network inspect fuckme >/dev/null 2>&1 && echo ok"

    v4 = bool(
        run(
            [
                "sh",
                "-lc",
                f"{network_probe_prefix} >/dev/null && curl -4 -s --max-time 5 ip.sb >/dev/null && echo ok",
            ]
        ).strip()
    )
    v6 = bool(
        run(
            [
                "sh",
                "-lc",
                f"{network_probe_prefix} >/dev/null && curl -6 -s --max-time 5 ip.sb >/dev/null && echo ok",
            ]
        ).strip()
    )
    return v4, v6


def sign(body: bytes, secret: str, ts: int) -> str:
    return hmac.new(secret.encode(), body + str(ts).encode(), hashlib.sha256).hexdigest()


def normalize_server_url(server: str) -> str:
    cleaned = (server or "").strip()
    if not cleaned:
        return "https://127.0.0.1:8080"
    if not urlparse(cleaned).scheme:
        cleaned = f"https://{cleaned}"
    return cleaned


def push(server: str, secret: str, payload: Dict) -> None:
    server = normalize_server_url(server)
    body = json.dumps(payload, ensure_ascii=False).encode()
    ts = int(time.time())
    sig = sign(body, secret, ts)
    r = requests.post(
        f"{server.rstrip('/')}/api/v1/report",
        data=body,
        headers={"Content-Type": "application/json", "X-Timestamp": str(ts), "X-Signature": sig},
        timeout=15,
    )
    r.raise_for_status()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default=os.getenv("SERVER_URL", "https://127.0.0.1:8080"))
    parser.add_argument("--secret", default=os.getenv("SHARED_SECRET", "change-me"))
    parser.add_argument("--interval", type=int, default=int(os.getenv("REPORT_INTERVAL", "300")))
    parser.add_argument("--host-id", default=os.getenv("HOST_ID", socket.gethostname()))
    args = parser.parse_args()

    while True:
        containers = podman_containers()
        v4, v6 = network_health()
        payload = {
            "host_id": args.host_id,
            "timestamp": int(time.time()),
            "podman_network": {"ipv4_ok": v4, "ipv6_ok": v6},
            "containers": [collect_container(c["name"], c.get("id", "")) for c in containers],
        }
        try:
            push(args.server, args.secret, payload)
            print(f"reported {len(containers)} containers to {args.server}")
        except Exception as e:
            print(f"report failed: {e}")
        time.sleep(max(60, args.interval))


if __name__ == "__main__":
    main()
