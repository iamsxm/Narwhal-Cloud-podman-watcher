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
_net_counters: Dict[str, Dict[str, float]] = {}


def get_podman_bin() -> str:
    global _podman_bin
    if _podman_bin is not None:
        return _podman_bin

    # In containerized deployments we usually mount the host Podman socket.
    # Prefer podman-remote first so we can see host containers instead of an
    # empty in-container local Podman store.
    for name in ("podman-remote", "podman"):
        if shutil.which(name):
            _podman_bin = name
            return _podman_bin

    _podman_bin = ""
    if "podman" not in _warned_missing_bins:
        _warned_missing_bins.add("podman")
        print("missing command: podman (or podman-remote)")
    return _podman_bin


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
        cpu_percent = _normalize_stat_number(_pick_first(item, ["CPU", "CPUPerc", "CPU%"]))

        mem_usage = _pick_first(item, ["MemUsage", "Mem Usage"])
        if mem_usage is not None:
            mem_bytes = parse_size(str(mem_usage).split("/")[0].strip())
        else:
            mem_bytes = int(_normalize_stat_number(_pick_first(item, ["MemUsageBytes", "MemUsageBytesValue"])))

        net_io = _pick_first(item, ["NetIO", "Net I/O"])
        if net_io is not None:
            net = str(net_io).split("/")
            if len(net) == 2:
                net_rx_total_bytes = parse_size(net[0].strip())
                net_tx_total_bytes = parse_size(net[1].strip())
        else:
            net_in = _normalize_stat_number(_pick_first(item, ["NetInput", "Net In"]))
            net_out = _normalize_stat_number(_pick_first(item, ["NetOutput", "Net Out"]))
            net_rx_total_bytes = int(net_in)
            net_tx_total_bytes = int(net_out)

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
    if len(parts) >= 4:
        cpu_percent = _normalize_stat_number(parts[0])
        mem_bytes = parse_size(parts[1].split("/")[0].strip())
        net = parts[2].split("/")
        if len(net) == 2:
            net_rx_total_bytes = parse_size(net[0].strip())
            net_tx_total_bytes = parse_size(net[1].strip())
        if net_rx_total_bytes <= 0:
            net_rx_total_bytes = parse_size(parts[2].strip())
        if net_tx_total_bytes <= 0:
            net_tx_total_bytes = parse_size(parts[3].strip())

    return {
        "cpu_percent": cpu_percent,
        "mem_bytes": mem_bytes,
        "net_rx_total_bytes": net_rx_total_bytes,
        "net_tx_total_bytes": net_tx_total_bytes,
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


def collect_top_cpu_process(name: str) -> Dict[str, object]:
    podman = get_podman_bin()
    if not podman:
        return {"pid": 0, "cpu_percent": 0.0, "command": ""}

    out = run([podman, "top", name, "pcpu,pid,comm,args"])
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
    podman = get_podman_bin()
    if not podman:
        return []
    patterns_env = os.getenv(
        "MONITORED_IMAGE_PATTERNS",
        "docker.io/narwhalcloud/debian,docker.io/library/alpine,alpine",
    )
    patterns = [x.strip() for x in patterns_env.split(",") if x.strip()]
    out = run([podman, "ps", "--format", "{{.ID}}|{{.Names}}|{{.Image}}"])
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
    podman = get_podman_bin()
    if not podman:
        return {
            "rw_bytes": 0,
            "rootfs_bytes": 0,
            "fs": {"root": {"total_bytes": 0, "avail_bytes": 0}, "data": {"total_bytes": 0, "avail_bytes": 0}},
        }

    rw_bytes = 0
    rootfs_bytes = 0
    inspect = run([podman, "container", "inspect", "--size", name])
    if inspect:
        try:
            item = json.loads(inspect)[0]
            rw_bytes = int(item.get("SizeRw") or 0)
            rootfs_bytes = int(item.get("SizeRootFs") or 0)
        except Exception:
            pass

    fs_df = run([podman, "exec", name, "sh", "-lc", "df -P / /data 2>/dev/null || true"])
    fs = {
        "root": _parse_df_target(fs_df, "/"),
        "data": _parse_df_target(fs_df, "/data"),
    }
    return {"rw_bytes": rw_bytes, "rootfs_bytes": rootfs_bytes, "fs": fs}


def collect_container(name: str, container_id: str = "") -> Dict:
    podman = get_podman_bin()
    if not podman:
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
    net_rx = 0.0
    net_tx = 0.0

    stats_json = run([podman, "stats", "--no-stream", "--format", "json", name])
    parsed_stats = _parse_stats_json(stats_json)
    cpu_percent = float(parsed_stats["cpu_percent"])
    mem = int(parsed_stats["mem_bytes"])
    rx_total = int(parsed_stats["net_rx_total_bytes"])
    tx_total = int(parsed_stats["net_tx_total_bytes"])
    container_key = container_id or name
    net_rx, net_tx = _derive_net_bps(container_key, rx_total, tx_total)

    if cpu_percent <= 0 and mem <= 0 and rx_total <= 0 and tx_total <= 0:
        stats_tpl = run([podman, "stats", "--no-stream", "--format", "{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}|{{.NetInput}}|{{.NetOutput}}", name])
        parsed_tpl = _parse_stats_template(stats_tpl)
        cpu_percent = float(parsed_tpl["cpu_percent"])
        mem = int(parsed_tpl["mem_bytes"])
        rx_total = int(parsed_tpl["net_rx_total_bytes"])
        tx_total = int(parsed_tpl["net_tx_total_bytes"])
        net_rx, net_tx = _derive_net_bps(container_key, rx_total, tx_total)

    inspect = run([podman, "inspect", name])
    conn_count = 0
    if inspect:
        try:
            d = json.loads(inspect)[0]
            pid = d.get("State", {}).get("Pid", 0)
            if pid:
                conn_out = run(["sh", "-lc", f"ss -Hantup | grep -c 'pid={pid},'"])
                conn_count = int(conn_out.strip() or 0)
        except Exception:
            pass

    disk = collect_disk_alert()
    container_disk = collect_container_disk_usage(name)
    top_cpu_process = collect_top_cpu_process(name)
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
    podman = get_podman_bin()
    if not podman:
        return False, False

    v4 = bool(
        run(
            [
                "sh",
                "-lc",
                f"{podman} network inspect fuckme >/dev/null 2>&1 && curl -4 -s --max-time 5 ip.sb >/dev/null && echo ok",
            ]
        ).strip()
    )
    v6 = bool(
        run(
            [
                "sh",
                "-lc",
                f"{podman} network inspect fuckme >/dev/null 2>&1 && curl -6 -s --max-time 5 ip.sb >/dev/null && echo ok",
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
