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


_warned_missing_bins = set()
_podman_bin = None


def get_podman_bin() -> str:
    global _podman_bin
    if _podman_bin is not None:
        return _podman_bin

    for name in ("podman", "podman-remote"):
        if shutil.which(name):
            _podman_bin = name
            return _podman_bin

    _podman_bin = ""
    if "podman" not in _warned_missing_bins:
        _warned_missing_bins.add("podman")
        print("missing command: podman (or podman-remote)")
    return _podman_bin


def run(cmd: List[str]) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True)
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


def podman_containers() -> List[str]:
    podman = get_podman_bin()
    if not podman:
        return []
    out = run([podman, "ps", "--format", "{{.Names}}"])
    return [x.strip() for x in out.splitlines() if x.strip()]


def collect_container(name: str) -> Dict:
    podman = get_podman_bin()
    if not podman:
        return {
            "name": name,
            "cpu_percent": 0.0,
            "mem_bytes": 0,
            "net_rx_bps": 0.0,
            "net_tx_bps": 0.0,
            "conn_count": 0,
            "disk": collect_disk_alert(),
        }

    stats = run([podman, "stats", "--no-stream", "--format", "json", name])
    cpu_percent = 0.0
    mem = 0
    net_rx = 0.0
    net_tx = 0.0
    if stats:
        try:
            arr = json.loads(stats)
            if arr:
                s = arr[0]
                cpu_percent = float(str(s.get("CPU", "0")).replace("%", "") or 0)
                mem = parse_size(str(s.get("MemUsage", "0")).split("/")[0].strip())
                net = str(s.get("NetIO", "0 / 0")).split("/")
                if len(net) == 2:
                    net_rx = parse_size(net[0].strip()) / 300.0
                    net_tx = parse_size(net[1].strip()) / 300.0
        except Exception:
            pass

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
    return {
        "name": name,
        "cpu_percent": cpu_percent,
        "mem_bytes": mem,
        "net_rx_bps": net_rx,
        "net_tx_bps": net_tx,
        "conn_count": conn_count,
        "disk": disk,
    }


def collect_disk_alert() -> Dict:
    file_path = os.getenv("WATCH_DISK_FILE", "/xfs_disk.img")
    if not os.path.exists(file_path):
        return {"file": file_path, "size_bytes": 0, "used_percent": 0}

    size = os.path.getsize(file_path)
    df = run(["df", "-P", "/data"])
    used = 0.0
    if df:
        lines = df.splitlines()
        if len(lines) >= 2:
            parts = lines[1].split()
            if len(parts) >= 5:
                used = float(parts[4].rstrip("%"))
    return {"file": file_path, "size_bytes": size, "used_percent": used}


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


def push(server: str, secret: str, payload: Dict) -> None:
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
    parser.add_argument("--server", default=os.getenv("SERVER_URL", "http://127.0.0.1:8080"))
    parser.add_argument("--secret", default=os.getenv("SHARED_SECRET", "change-me"))
    parser.add_argument("--interval", type=int, default=int(os.getenv("REPORT_INTERVAL", "300")))
    parser.add_argument("--host-id", default=os.getenv("HOST_ID", socket.gethostname()))
    args = parser.parse_args()

    while True:
        names = podman_containers()
        v4, v6 = network_health()
        payload = {
            "host_id": args.host_id,
            "timestamp": int(time.time()),
            "podman_network": {"ipv4_ok": v4, "ipv6_ok": v6},
            "containers": [collect_container(n) for n in names],
        }
        try:
            push(args.server, args.secret, payload)
            print(f"reported {len(names)} containers to {args.server}")
        except Exception as e:
            print(f"report failed: {e}")
        time.sleep(max(60, args.interval))


if __name__ == "__main__":
    main()
