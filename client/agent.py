import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import time
from typing import Dict, List, Tuple
from urllib.parse import quote, urlparse

import requests

_warned_missing_bins = set()
_podman_bin = None
_container_bin = None
_runtime_bins = None
_net_counters: Dict[str, Dict[str, float]] = {}
_cpu_counters: Dict[str, Dict[str, float]] = {}
_warned_parse_paths = set()
_geoip_country_cache: Dict[str, str] = {}
_incus_metrics_cache: Dict[str, object] = {"ts": 0.0, "text": "", "parsed": {}}
_packet_counters: Dict[str, Dict[str, float]] = {}
_protocol_counters: Dict[str, Dict[str, float]] = {}
_access_log_states: Dict[str, Dict[str, object]] = {}
_security_last_sample_ts = 0.0


def _is_containerized_runtime() -> bool:
    return os.path.exists("/run/.containerenv") or os.path.exists("/.dockerenv")


def get_podman_bin(warn: bool = True) -> str:
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
    if warn and "podman" not in _warned_missing_bins:
        _warned_missing_bins.add("podman")
        print("missing command: podman (or podman-remote)")
    return _podman_bin


def _runtime_kind(runtime: str) -> str:
    name = os.path.basename(runtime or "")
    return "podman" if name in ("podman", "podman-remote") else name


def _docker_monitor_mode() -> str:
    mode = os.getenv("DOCKER_MONITOR_MODE", "notice").strip().lower()
    return mode if mode in ("notice", "full", "off") else "notice"


def get_runtime_bins() -> Dict[str, str]:
    """Return all enabled and available container runtimes.

    CONTAINER_RUNTIMES accepts ``auto`` (the default) or a comma-separated
    subset of podman,docker,incus.  Unlike the legacy fallback logic this lets
    a host report containers from multiple runtimes in the same cycle.
    """
    global _runtime_bins
    if _runtime_bins is not None:
        return dict(_runtime_bins)

    configured = os.getenv("CONTAINER_RUNTIMES", "auto").strip().lower()
    requested = [x.strip() for x in configured.split(",") if x.strip()]
    auto = not requested or "auto" in requested
    enabled = ("podman", "docker", "incus") if auto else tuple(dict.fromkeys(requested))
    invalid = [name for name in enabled if name not in ("podman", "docker", "incus")]
    if invalid:
        print(f"warn: unsupported container runtimes ignored: {', '.join(invalid)}")

    found: Dict[str, str] = {}
    if "podman" in enabled:
        podman = get_podman_bin(warn=False)
        if podman:
            found["podman"] = podman
    for name in ("docker", "incus"):
        if name not in enabled:
            continue
        if shutil.which(name):
            found[name] = name

    if not found and "container_runtimes" not in _warned_missing_bins:
        _warned_missing_bins.add("container_runtimes")
        wanted = ", ".join(x for x in enabled if x in ("podman", "docker", "incus"))
        print(f"missing command: no enabled container runtime found ({wanted})")
    elif not auto:
        for name in enabled:
            if name in ("podman", "docker", "incus") and name not in found:
                key = f"runtime:{name}"
                if key not in _warned_missing_bins:
                    _warned_missing_bins.add(key)
                    print(f"missing command: enabled runtime '{name}' is not installed or not in PATH")

    _runtime_bins = found
    return dict(found)


def get_container_bin() -> str:
    global _container_bin
    if _container_bin is not None:
        return _container_bin

    runtimes = get_runtime_bins()
    for name in ("podman", "docker", "incus"):
        if name in runtimes:
            _container_bin = runtimes[name]
            return _container_bin

    _container_bin = ""
    if "container_runtime" not in _warned_missing_bins:
        _warned_missing_bins.add("container_runtime")
        print("missing command: podman (or podman-remote) / docker / incus")
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


def run_first_success(commands: List[List[str]]) -> str:
    for cmd in commands:
        out = run(cmd)
        if out.strip():
            return out
    return ""


def _runtime_base(runtime: str, project: str = "") -> List[str]:
    cmd = [runtime]
    if _runtime_kind(runtime) == "incus" and project:
        cmd.extend(["--project", project])
    return cmd


def _runtime_exec_cmd(runtime: str, name: str, shell_command: str, project: str = "") -> List[str]:
    cmd = _runtime_base(runtime, project) + ["exec", name]
    if _runtime_kind(runtime) == "incus":
        cmd.append("--")
    return cmd + ["sh", "-lc", shell_command]


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
    mem_percent = 0.0
    net_rx_total_bytes = 0
    net_tx_total_bytes = 0

    if not stats_text:
        return {
            "cpu_percent": cpu_percent,
            "mem_bytes": mem_bytes,
            "mem_percent": mem_percent,
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
        mem_percent = _normalize_stat_number(
            _find_value_ci(item, ["MemPerc", "Mem%", "mem_percent", "memory_percent"])
            or _pick_first(item, ["MemPerc", "Mem%"])
        )
        if mem_percent <= 0:
            mem_limit = _normalize_stat_number(
                _find_value_ci(item, ["MemLimit", "MemLimitBytes", "mem_limit", "memory_limit"])
            )
            if mem_limit > 0 and mem_bytes > 0:
                mem_percent = (float(mem_bytes) / mem_limit) * 100.0

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
        "mem_percent": mem_percent,
        "net_rx_total_bytes": net_rx_total_bytes,
        "net_tx_total_bytes": net_tx_total_bytes,
    }


def _parse_stats_template(stats_text: str) -> Dict[str, float | int]:
    cpu_percent = 0.0
    mem_bytes = 0
    mem_percent = 0.0
    net_rx_total_bytes = 0
    net_tx_total_bytes = 0

    parts = (stats_text or "").strip().split("|")
    if len(parts) >= 3:
        cpu_percent = _normalize_stat_number(parts[0])
        mem_bytes = parse_size(parts[1].split("/")[0].strip())
        mem_usage_parts = parts[1].split("/")
        if len(mem_usage_parts) == 2:
            mem_total = parse_size(mem_usage_parts[1].strip())
            if mem_total > 0 and mem_bytes > 0:
                mem_percent = (float(mem_bytes) / mem_total) * 100.0
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
        "mem_percent": mem_percent,
        "net_rx_total_bytes": net_rx_total_bytes,
        "net_tx_total_bytes": net_tx_total_bytes,
    }


def _parse_stats_compact(stats_text: str) -> Dict[str, float | int]:
    parts = (stats_text or "").strip().split("|")
    if len(parts) < 3:
        return {"cpu_percent": 0.0, "mem_bytes": 0, "mem_percent": 0.0, "net_rx_total_bytes": 0, "net_tx_total_bytes": 0}
    net_rx_total_bytes = 0
    net_tx_total_bytes = 0
    net = parts[2].split("/")
    if len(net) == 2:
        net_rx_total_bytes = parse_size(net[0].strip())
        net_tx_total_bytes = parse_size(net[1].strip())
    elif len(parts) >= 4:
        net_rx_total_bytes = parse_size(parts[2])
        net_tx_total_bytes = parse_size(parts[3])
    return {
        "cpu_percent": _normalize_stat_number(parts[0]),
        "mem_bytes": parse_size(parts[1]),
        "mem_percent": 0.0,
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


def _derive_cpu_percent(container_key: str, cpu_seconds: float) -> float:
    now = float(time.time())
    prev = _cpu_counters.get(container_key)
    _cpu_counters[container_key] = {"ts": now, "cpu": float(cpu_seconds)}
    if not prev:
        return 0.0
    dt = now - float(prev.get("ts", 0.0))
    if dt <= 0:
        return 0.0
    delta = max(0.0, float(cpu_seconds) - float(prev.get("cpu", 0.0)))
    return (delta / dt) * 100.0


def _derive_packet_rates(container_key: str, rx_packets: int, tx_packets: int) -> Tuple[float, float]:
    now = float(time.time())
    prev = _packet_counters.get(container_key)
    _packet_counters[container_key] = {
        "ts": now,
        "rx_packets": float(rx_packets),
        "tx_packets": float(tx_packets),
    }
    if not prev:
        return 0.0, 0.0
    dt = now - float(prev.get("ts", 0.0))
    if dt <= 0:
        return 0.0, 0.0
    rx_delta = max(0.0, float(rx_packets) - float(prev.get("rx_packets", 0.0)))
    tx_delta = max(0.0, float(tx_packets) - float(prev.get("tx_packets", 0.0)))
    return rx_delta / dt, tx_delta / dt


def _read_protocol_counters(pid: int) -> Dict[str, int]:
    wanted = {
        "Tcp": ("ActiveOpens", "AttemptFails", "EstabResets", "OutRsts"),
        "Udp": ("OutDatagrams", "NoPorts", "InErrors"),
    }
    result: Dict[str, int] = {}
    if pid <= 0:
        return result
    try:
        with open(f"/proc/{pid}/net/snmp", "r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.read().splitlines()
    except Exception:
        return result
    for index in range(0, len(lines) - 1, 2):
        header = lines[index].split()
        values = lines[index + 1].split()
        if not header or not values or header[0] != values[0]:
            continue
        protocol = header[0].rstrip(":")
        if protocol not in wanted:
            continue
        mapping = dict(zip(header[1:], values[1:]))
        for field in wanted[protocol]:
            try:
                result[f"{protocol}_{field}"] = int(mapping.get(field, "0"))
            except ValueError:
                result[f"{protocol}_{field}"] = 0
    return result


def _derive_protocol_rates(container_key: str, counters: Dict[str, int]) -> Dict[str, float]:
    now = float(time.time())
    previous = _protocol_counters.get(container_key)
    current: Dict[str, float] = {"ts": now}
    current.update({key: float(value) for key, value in counters.items()})
    _protocol_counters[container_key] = current
    if not previous:
        return {f"{key}_per_second": 0.0 for key in counters}
    dt = now - float(previous.get("ts", 0.0))
    if dt <= 0:
        return {f"{key}_per_second": 0.0 for key in counters}
    return {
        f"{key}_per_second": max(0.0, float(value) - float(previous.get(key, value))) / dt
        for key, value in counters.items()
    }


_PROM_LABEL_RE = re.compile(r'(\w+)="((?:\\.|[^"\\])*)"')


def _parse_prometheus_labels(raw: str) -> Dict[str, str]:
    labels: Dict[str, str] = {}
    for match in _PROM_LABEL_RE.finditer(raw or ""):
        value = match.group(2)
        try:
            value = json.loads(f'"{value}"')
        except Exception:
            pass
        labels[match.group(1)] = value
    return labels


def _parse_incus_metrics(text: str) -> Dict[Tuple[str, str], Dict[str, float]]:
    """Parse the subset of Incus OpenMetrics used by this agent."""
    result: Dict[Tuple[str, str], Dict[str, float]] = {}
    wanted = {
        "incus_cpu_seconds_total",
        "incus_cpu_effective_total",
        "incus_memory_MemTotal_bytes",
        "incus_network_receive_bytes_total",
        "incus_network_transmit_bytes_total",
        "incus_network_receive_packets_total",
        "incus_network_transmit_packets_total",
        "incus_filesystem_size_bytes",
        "incus_filesystem_avail_bytes",
    }
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+([^\s]+)", line)
        if not match or match.group(1) not in wanted:
            continue
        metric, raw_labels, raw_value = match.groups()
        try:
            value = float(raw_value)
        except ValueError:
            continue
        labels = _parse_prometheus_labels(raw_labels or "")
        if labels.get("type") not in (None, "container"):
            continue
        name = labels.get("name", "")
        if not name:
            continue
        project = labels.get("project", "default")
        item = result.setdefault(
            (project, name),
            {
                "cpu_seconds": 0.0,
                "effective_cpus": 0.0,
                "mem_bytes": 0.0,
                "net_rx_total_bytes": 0.0,
                "net_tx_total_bytes": 0.0,
                "net_rx_total_packets": 0.0,
                "net_tx_total_packets": 0.0,
                "fs_total_bytes": 0.0,
                "fs_avail_bytes": 0.0,
            },
        )
        if metric == "incus_cpu_seconds_total":
            if labels.get("mode", "") != "idle":
                item["cpu_seconds"] += value
        elif metric == "incus_cpu_effective_total":
            item["effective_cpus"] = value
        elif metric == "incus_memory_MemTotal_bytes":
            item["mem_bytes"] = value
        elif metric == "incus_network_receive_bytes_total":
            if labels.get("device") != "lo":
                item["net_rx_total_bytes"] += value
        elif metric == "incus_network_transmit_bytes_total":
            if labels.get("device") != "lo":
                item["net_tx_total_bytes"] += value
        elif metric == "incus_network_receive_packets_total":
            if labels.get("device") != "lo":
                item["net_rx_total_packets"] += value
        elif metric == "incus_network_transmit_packets_total":
            if labels.get("device") != "lo":
                item["net_tx_total_packets"] += value
        elif metric == "incus_filesystem_size_bytes":
            item["fs_total_bytes"] = max(item["fs_total_bytes"], value)
        elif metric == "incus_filesystem_avail_bytes":
            item["fs_avail_bytes"] = max(item["fs_avail_bytes"], value)
    return result


def _get_incus_metrics(runtime: str = "incus") -> Dict[Tuple[str, str], Dict[str, float]]:
    now = float(time.time())
    cached_ts = float(_incus_metrics_cache.get("ts", 0.0) or 0.0)
    if now - cached_ts < 7 and isinstance(_incus_metrics_cache.get("parsed"), dict):
        return _incus_metrics_cache["parsed"]  # type: ignore[return-value]
    text = run([runtime, "query", "/1.0/metrics"])
    parsed = _parse_incus_metrics(text)
    _incus_metrics_cache.update({"ts": now, "text": text, "parsed": parsed})
    return parsed


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


def _decode_proc_addr(hex_ip: str, is_v6: bool = False) -> str:
    try:
        raw = bytes.fromhex(hex_ip)
        if is_v6:
            return str(ipaddress.IPv6Address(raw[::-1]))
        return str(ipaddress.IPv4Address(raw[::-1]))
    except Exception:
        return ""


def _collect_tcp_remote_ips(pid: int) -> Dict[str, int]:
    return _collect_remote_ips_by_proto(pid, "tcp")


def _collect_udp_remote_ips(pid: int) -> Dict[str, int]:
    return _collect_remote_ips_by_proto(pid, "udp")


def _parse_remote_endpoint_ip(endpoint: str) -> str:
    text = (endpoint or "").strip()
    if not text or text in ("*", "*:*"):
        return ""
    if text.startswith("[") and "]" in text:
        return text[1:text.find("]")]
    if text.count(":") >= 2:
        # IPv6 endpoint，可能是 "2001:db8::1:443" 或 "::ffff:1.2.3.4:443"
        host, _, _ = text.rpartition(":")
        return host.strip("[]")
    if ":" in text:
        return text.split(":", 1)[0]
    return text


def _is_trackable_ip(ip: str) -> bool:
    if not ip:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # 私网地址也保留，GeoIP 失败时统一归为 UN，避免前端“国家 Top3”整列为空。
    if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
        return False
    return True


def _collect_remote_ips_from_exec(runtime: str, name: str, proto: str, project: str = "") -> Dict[str, int]:
    if not runtime or not name:
        return {}
    if proto == "udp":
        cmd = "ss -Huan 2>/dev/null | awk '{print $5}' || (netstat -nu 2>/dev/null | awk 'NR>2{print $5}')"
    else:
        cmd = "ss -Htan state established 2>/dev/null | awk '{print $5}' || (netstat -nt 2>/dev/null | awk 'NR>2{print $5}')"
    out = run(_runtime_exec_cmd(runtime, name, cmd, project))
    ip_counter: Dict[str, int] = {}
    for line in out.splitlines():
        ip = _parse_remote_endpoint_ip(line)
        if not _is_trackable_ip(ip):
            continue
        ip_counter[ip] = ip_counter.get(ip, 0) + 1
    return ip_counter


def _collect_remote_ips_by_proto(pid: int, proto: str) -> Dict[str, int]:
    if pid <= 0:
        return {}
    ip_counter: Dict[str, int] = {}
    if proto == "udp":
        files = (("udp", False), ("udp6", True))
    else:
        files = (("tcp", False), ("tcp6", True))
    for name, is_v6 in files:
        path = f"/proc/{pid}/net/{name}"
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()[1:]
        except Exception:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            rem = parts[2]
            state = parts[3].upper()
            # TCP 仅统计 ESTABLISHED；UDP 无连接状态语义，统计所有有效远端。
            if proto == "tcp" and state != "01":
                continue
            if ":" not in rem:
                continue
            rem_ip_hex = rem.split(":", 1)[0]
            ip = _decode_proc_addr(rem_ip_hex, is_v6=is_v6)
            if not ip:
                continue
            if ip in ("0.0.0.0", "::"):
                continue
            if not _is_trackable_ip(ip):
                continue
            ip_counter[ip] = ip_counter.get(ip, 0) + 1
    return ip_counter


def _geoip_country_batch(ip_counts: Dict[str, int]) -> List[Dict[str, int | str]]:
    if not ip_counts:
        return []
    unresolved = [ip for ip in ip_counts.keys() if ip not in _geoip_country_cache]
    if unresolved:
        try:
            payload = [{"query": ip} for ip in unresolved[:100]]
            resp = requests.post("http://ip-api.com/batch?fields=status,query,countryCode", json=payload, timeout=8)
            if resp.ok:
                for item in resp.json():
                    query = str(item.get("query") or "")
                    if not query:
                        continue
                    if item.get("status") == "success":
                        _geoip_country_cache[query] = str(item.get("countryCode") or "UN")
                    else:
                        _geoip_country_cache[query] = "UN"
        except Exception:
            for ip in unresolved:
                _geoip_country_cache[ip] = "UN"

    country_counter: Dict[str, Dict[str, int | str]] = {}
    for ip, cnt in ip_counts.items():
        country = _geoip_country_cache.get(ip, "UN")
        if country not in country_counter:
            country_counter[country] = {"country": country, "connections": 0, "ip_count": 0}
        country_counter[country]["connections"] = int(country_counter[country]["connections"]) + int(cnt)
        country_counter[country]["ip_count"] = int(country_counter[country]["ip_count"]) + 1
    return sorted(country_counter.values(), key=lambda x: int(x["connections"]), reverse=True)


def _read_mem_usage_from_pid(pid: int) -> Tuple[int, float]:
    if pid <= 0:
        return 0, 0.0
    base = f"/proc/{pid}/root/sys/fs/cgroup"
    candidates = (
        (f"{base}/memory.current", f"{base}/memory.max"),  # cgroup v2
        (f"{base}/memory/memory.usage_in_bytes", f"{base}/memory/memory.limit_in_bytes"),  # cgroup v1
    )
    for usage_path, limit_path in candidates:
        try:
            with open(usage_path, "r", encoding="utf-8", errors="ignore") as f:
                usage_raw = f.read().strip()
            with open(limit_path, "r", encoding="utf-8", errors="ignore") as f:
                limit_raw = f.read().strip()
        except Exception:
            continue
        if not usage_raw.isdigit():
            continue
        usage = int(usage_raw)
        if usage <= 0:
            continue
        if limit_raw.isdigit():
            limit = int(limit_raw)
            if limit > 0 and limit < (1 << 60):
                return usage, (float(usage) / float(limit)) * 100.0
        return usage, 0.0
    return 0, 0.0


def _read_process_count_from_pid(pid: int) -> int:
    if pid <= 0:
        return 0
    for path in (
        f"/proc/{pid}/root/sys/fs/cgroup/pids.current",
        f"/proc/{pid}/root/sys/fs/cgroup/pids/pids.current",
    ):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                value = handle.read().strip()
            if value.isdigit():
                return int(value)
        except Exception:
            continue
    return 0


def _read_net_stats_from_pid(pid: int) -> Tuple[int, int, int, int]:
    if pid <= 0:
        return 0, 0, 0, 0
    path = f"/proc/{pid}/net/dev"
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    except Exception:
        return 0, 0, 0, 0
    if len(lines) <= 2:
        return 0, 0, 0, 0

    rx_total = 0
    tx_total = 0
    rx_packets = 0
    tx_packets = 0
    for line in lines[2:]:
        if ":" not in line:
            continue
        interface, data = line.split(":", 1)
        if interface.strip() == "lo":
            continue
        cols = data.split()
        if len(cols) < 16:
            continue
        try:
            rx_total += int(cols[0])
            rx_packets += int(cols[1])
            tx_total += int(cols[8])
            tx_packets += int(cols[9])
        except ValueError:
            continue
    return rx_total, tx_total, rx_packets, tx_packets


def _read_net_bytes_from_pid(pid: int) -> Tuple[int, int]:
    rx_total, tx_total, _, _ = _read_net_stats_from_pid(pid)
    return rx_total, tx_total


def _count_connections_from_exec(runtime: str, name: str, project: str = "") -> int:
    if not runtime or not name:
        return 0
    cmd = (
        "if command -v ss >/dev/null 2>&1; then "
        "  (ss -Htan 2>/dev/null; ss -Huan 2>/dev/null) | wc -l; "
        "elif command -v netstat >/dev/null 2>&1; then "
        "  tcp=$(netstat -nt 2>/dev/null | awk 'NR>2' | wc -l); "
        "  udp=$(netstat -nu 2>/dev/null | awk 'NR>2' | wc -l); "
        "  echo $((tcp + udp)); "
        "else "
        "  echo 0; "
        "fi"
    )
    out = run(_runtime_exec_cmd(runtime, name, cmd, project)).strip()
    return int(out) if out.isdigit() else 0


def _parse_port(hex_port: str) -> int:
    try:
        return int(hex_port, 16)
    except (TypeError, ValueError):
        return 0


def _collect_socket_security(pid: int) -> Dict[str, object]:
    result: Dict[str, object] = {
        "tcp_states": {},
        "syn_recv_count": 0,
        "incoming_established": 0,
        "outbound_established": 0,
        "outbound_unique_ips": 0,
        "outbound_unique_ports": 0,
        "suspicious_outbound_connections": 0,
        "scan_unique_ports_max": 0,
        "scan_source_ip": "",
        "listening_ports": [],
    }
    if pid <= 0:
        return result

    entries: List[Dict[str, object]] = []
    for filename, is_v6 in (("tcp", False), ("tcp6", True), ("udp", False), ("udp6", True)):
        try:
            with open(f"/proc/{pid}/net/{filename}", "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()[1:]
        except Exception:
            continue
        proto = "udp" if filename.startswith("udp") else "tcp"
        for line in lines:
            parts = line.split()
            if len(parts) < 4 or ":" not in parts[1] or ":" not in parts[2]:
                continue
            local_ip_hex, local_port_hex = parts[1].rsplit(":", 1)
            remote_ip_hex, remote_port_hex = parts[2].rsplit(":", 1)
            entries.append(
                {
                    "proto": proto,
                    "state": parts[3].upper(),
                    "local_port": _parse_port(local_port_hex),
                    "remote_port": _parse_port(remote_port_hex),
                    "remote_ip": _decode_proc_addr(remote_ip_hex, is_v6=is_v6),
                }
            )

    listening_ports = {
        int(x["local_port"])
        for x in entries
        if x["proto"] == "tcp" and x["state"] == "0A" and int(x["local_port"]) > 0
    }
    state_names = {
        "01": "established",
        "02": "syn_sent",
        "03": "syn_recv",
        "04": "fin_wait1",
        "05": "fin_wait2",
        "06": "time_wait",
        "07": "close",
        "08": "close_wait",
        "09": "last_ack",
        "0A": "listen",
        "0B": "closing",
    }
    tcp_states: Dict[str, int] = {}
    outbound_ips = set()
    outbound_ports = set()
    inbound_source_ports: Dict[str, set] = {}
    suspicious_ports = {
        int(x.strip())
        for x in os.getenv("SECURITY_SUSPICIOUS_OUTBOUND_PORTS", "25,465,587,23,445,6667").split(",")
        if x.strip().isdigit()
    }
    suspicious_connections = 0
    incoming_established = 0
    outbound_established = 0
    syn_recv = 0

    for entry in entries:
        proto = str(entry["proto"])
        state = str(entry["state"])
        local_port = int(entry["local_port"])
        remote_port = int(entry["remote_port"])
        remote_ip = str(entry["remote_ip"])
        if proto == "tcp":
            state_name = state_names.get(state, state.lower())
            tcp_states[state_name] = tcp_states.get(state_name, 0) + 1
            if state == "03":
                syn_recv += 1
            if state not in ("01", "02", "03"):
                continue
        elif remote_port <= 0:
            continue

        incoming = local_port in listening_ports or state == "03"
        if incoming:
            if state == "01":
                incoming_established += 1
            if _is_trackable_ip(remote_ip):
                inbound_source_ports.setdefault(remote_ip, set()).add(local_port)
            continue
        if not _is_trackable_ip(remote_ip):
            continue
        outbound_ips.add(remote_ip)
        if remote_port > 0:
            outbound_ports.add(remote_port)
        if state == "01" or proto == "udp":
            outbound_established += 1
            if remote_port in suspicious_ports:
                suspicious_connections += 1

    scan_source_ip = ""
    scan_unique_ports_max = 0
    for source_ip, ports in inbound_source_ports.items():
        if len(ports) > scan_unique_ports_max:
            scan_unique_ports_max = len(ports)
            scan_source_ip = source_ip

    result.update(
        {
            "tcp_states": tcp_states,
            "syn_recv_count": syn_recv,
            "incoming_established": incoming_established,
            "outbound_established": outbound_established,
            "outbound_unique_ips": len(outbound_ips),
            "outbound_unique_ports": len(outbound_ports),
            "suspicious_outbound_connections": suspicious_connections,
            "scan_unique_ports_max": scan_unique_ports_max,
            "scan_source_ip": scan_source_ip,
            "listening_ports": sorted(listening_ports),
        }
    )
    return result


_NGINX_ACCESS_RE = re.compile(r'^([^ ]+)\s+.*?"([A-Z]+)\s+([^ ]+)\s+[^\"]+"\s+(\d{3})\b')


def _parse_access_log_line(line: str) -> Dict[str, object] | None:
    text = (line or "").strip()
    if not text:
        return None
    try:
        item = json.loads(text)
    except Exception:
        item = None
    if isinstance(item, dict):
        request = item.get("request") if isinstance(item.get("request"), dict) else item
        remote_ip = str(
            request.get("client_ip")
            or request.get("remote_ip")
            or request.get("remote_addr")
            or item.get("remote_addr")
            or ""
        )
        status = item.get("status", request.get("status", 0))
        try:
            status_int = int(status or 0)
        except (TypeError, ValueError):
            status_int = 0
        return {
            "ip": remote_ip,
            "status": status_int,
            "method": str(request.get("method") or item.get("request_method") or ""),
            "uri": str(request.get("uri") or item.get("request_uri") or ""),
        }
    match = _NGINX_ACCESS_RE.match(text)
    if not match:
        return None
    return {"ip": match.group(1), "method": match.group(2), "uri": match.group(3), "status": int(match.group(4))}


def _collect_access_log_stats(interval_seconds: float) -> Dict[str, object]:
    raw_paths = os.getenv("SECURITY_ACCESS_LOG_PATHS", "").strip()
    paths = [x.strip() for x in raw_paths.split(",") if x.strip()]
    stats: Dict[str, object] = {
        "enabled": bool(paths),
        "readable_files": 0,
        "requests": 0,
        "requests_per_second": 0.0,
        "unique_ips": 0,
        "top_ip": "",
        "top_ip_requests": 0,
        "top_ip_requests_per_second": 0.0,
        "status_4xx": 0,
        "status_5xx": 0,
        "top_ip_4xx": "",
        "top_ip_4xx_requests": 0,
        "suspicious_requests": 0,
        "suspicious_unique_paths": 0,
        "top_scanner_ip": "",
        "top_scanner_requests": 0,
        "parse_errors": 0,
    }
    if not paths:
        return stats
    max_bytes = max(65536, int(os.getenv("SECURITY_ACCESS_LOG_MAX_BYTES", "1048576")))
    ip_counts: Dict[str, int] = {}
    ip_4xx_counts: Dict[str, int] = {}
    scanner_ip_counts: Dict[str, int] = {}
    suspicious_paths_seen = set()
    requests_count = 0
    status_4xx = 0
    status_5xx = 0
    parse_errors = 0
    readable_files = 0
    web_scan_patterns = [
        item.strip().lower()
        for item in os.getenv(
            "SECURITY_WEB_SCAN_PATTERNS",
            ".env,.git,wp-login,wp-admin,phpmyadmin,actuator,server-status,cgi-bin,vendor/phpunit,etc/passwd,boaform,hnap1",
        ).split(",")
        if item.strip()
    ]

    for path in paths:
        try:
            stat = os.stat(path)
            state = _access_log_states.get(path, {})
            inode = int(getattr(stat, "st_ino", 0) or 0)
            if not state:
                _access_log_states[path] = {"inode": inode, "offset": int(stat.st_size)}
                readable_files += 1
                continue
            previous_inode = int(state.get("inode", 0) or 0)
            previous_offset = int(state.get("offset", 0) or 0)
            if previous_inode != inode or previous_offset > stat.st_size:
                previous_offset = 0
            start = max(previous_offset, int(stat.st_size) - max_bytes)
            skip_partial_line = start > previous_offset
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(start)
                if skip_partial_line:
                    f.readline()
                lines = f.readlines()
                offset = f.tell()
            _access_log_states[path] = {"inode": inode, "offset": offset}
            readable_files += 1
        except Exception:
            continue
        for line in lines[-20000:]:
            event = _parse_access_log_line(line)
            if not event:
                parse_errors += 1
                continue
            requests_count += 1
            ip = str(event.get("ip") or "")
            if ip:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
            status = int(event.get("status") or 0)
            if 400 <= status < 500:
                status_4xx += 1
                if ip and status in (401, 403, 429):
                    ip_4xx_counts[ip] = ip_4xx_counts.get(ip, 0) + 1
            elif status >= 500:
                status_5xx += 1
            uri = str(event.get("uri") or "")
            uri_lower = uri.lower()
            if uri_lower and any(pattern in uri_lower for pattern in web_scan_patterns):
                suspicious_paths_seen.add(uri.split("?", 1)[0][:500])
                if ip:
                    scanner_ip_counts[ip] = scanner_ip_counts.get(ip, 0) + 1

    top_ip = ""
    top_ip_requests = 0
    for ip, count in ip_counts.items():
        if count > top_ip_requests:
            top_ip = ip
            top_ip_requests = count
    top_ip_4xx = ""
    top_ip_4xx_requests = 0
    for ip, count in ip_4xx_counts.items():
        if count > top_ip_4xx_requests:
            top_ip_4xx = ip
            top_ip_4xx_requests = count
    top_scanner_ip = ""
    top_scanner_requests = 0
    for ip, count in scanner_ip_counts.items():
        if count > top_scanner_requests:
            top_scanner_ip = ip
            top_scanner_requests = count
    interval = max(1.0, float(interval_seconds))
    stats.update(
        {
            "readable_files": readable_files,
            "requests": requests_count,
            "requests_per_second": requests_count / interval,
            "unique_ips": len(ip_counts),
            "top_ip": top_ip,
            "top_ip_requests": top_ip_requests,
            "top_ip_requests_per_second": top_ip_requests / interval,
            "status_4xx": status_4xx,
            "status_5xx": status_5xx,
            "top_ip_4xx": top_ip_4xx,
            "top_ip_4xx_requests": top_ip_4xx_requests,
            "suspicious_requests": sum(scanner_ip_counts.values()),
            "suspicious_unique_paths": len(suspicious_paths_seen),
            "top_scanner_ip": top_scanner_ip,
            "top_scanner_requests": top_scanner_requests,
            "parse_errors": parse_errors,
        }
    )
    return stats


def _summarize_access_lines(
    lines: List[str], interval_seconds: float, enabled: bool, readable_files: int
) -> Dict[str, object]:
    ip_counts: Dict[str, int] = {}
    ip_4xx_counts: Dict[str, int] = {}
    scanner_ip_counts: Dict[str, int] = {}
    suspicious_paths_seen = set()
    requests_count = 0
    status_4xx = 0
    status_5xx = 0
    parse_errors = 0
    web_scan_patterns = [
        item.strip().lower()
        for item in os.getenv(
            "SECURITY_WEB_SCAN_PATTERNS",
            ".env,.git,wp-login,wp-admin,phpmyadmin,actuator,server-status,cgi-bin,vendor/phpunit,etc/passwd,boaform,hnap1",
        ).split(",")
        if item.strip()
    ]
    for line in lines[-20000:]:
        event = _parse_access_log_line(line)
        if not event:
            parse_errors += 1
            continue
        requests_count += 1
        ip = str(event.get("ip") or "")
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        status = int(event.get("status") or 0)
        if 400 <= status < 500:
            status_4xx += 1
            if ip and status in (401, 403, 429):
                ip_4xx_counts[ip] = ip_4xx_counts.get(ip, 0) + 1
        elif status >= 500:
            status_5xx += 1
        uri = str(event.get("uri") or "")
        uri_lower = uri.lower()
        if uri_lower and any(pattern in uri_lower for pattern in web_scan_patterns):
            suspicious_paths_seen.add(uri.split("?", 1)[0][:500])
            if ip:
                scanner_ip_counts[ip] = scanner_ip_counts.get(ip, 0) + 1

    top_ip, top_ip_requests = max(ip_counts.items(), key=lambda item: item[1], default=("", 0))
    top_ip_4xx, top_ip_4xx_requests = max(ip_4xx_counts.items(), key=lambda item: item[1], default=("", 0))
    top_scanner_ip, top_scanner_requests = max(
        scanner_ip_counts.items(), key=lambda item: item[1], default=("", 0)
    )
    interval = max(1.0, float(interval_seconds))
    return {
        "enabled": enabled,
        "readable_files": readable_files,
        "requests": requests_count,
        "requests_per_second": requests_count / interval,
        "unique_ips": len(ip_counts),
        "top_ip": top_ip,
        "top_ip_requests": top_ip_requests,
        "top_ip_requests_per_second": top_ip_requests / interval,
        "status_4xx": status_4xx,
        "status_5xx": status_5xx,
        "top_ip_4xx": top_ip_4xx,
        "top_ip_4xx_requests": top_ip_4xx_requests,
        "suspicious_requests": sum(scanner_ip_counts.values()),
        "suspicious_unique_paths": len(suspicious_paths_seen),
        "top_scanner_ip": top_scanner_ip,
        "top_scanner_requests": top_scanner_requests,
        "parse_errors": parse_errors,
    }


def _collect_container_access_log_stats(
    container: Dict[str, str], interval_seconds: float
) -> Dict[str, object]:
    raw_paths = os.getenv(
        "SECURITY_CONTAINER_ACCESS_LOG_PATHS",
        "/var/log/nginx/access.log,/var/log/caddy/access.log",
    ).strip()
    paths = [path.strip() for path in raw_paths.split(",") if re.fullmatch(r"/[A-Za-z0-9_./-]+", path.strip())]
    if not paths:
        return _summarize_access_lines([], interval_seconds, False, 0)

    runtime = container.get("runtime_bin", "") or get_container_bin()
    name = container.get("name", "")
    project = container.get("project", "")
    runtime_name = container.get("runtime", "") or _runtime_kind(runtime)
    if not runtime or not name:
        return _summarize_access_lines([], interval_seconds, True, 0)
    max_bytes = max(65536, int(os.getenv("SECURITY_ACCESS_LOG_MAX_BYTES", "1048576")))
    readable_files = 0
    collected_lines: List[str] = []
    for path in paths:
        quoted_path = shlex.quote(path)
        size_out = run(
            _runtime_exec_cmd(
                runtime,
                name,
                f"if [ -r {quoted_path} ]; then wc -c < {quoted_path}; fi",
                project,
            )
        ).strip()
        if not size_out.isdigit():
            continue
        size = int(size_out)
        readable_files += 1
        key = f"container-log:{runtime_name}:{project}:{name}:{path}"
        state = _access_log_states.get(key)
        if not state:
            _access_log_states[key] = {"inode": 0, "offset": size}
            continue
        previous_offset = int(state.get("offset", 0) or 0)
        if previous_offset > size:
            previous_offset = 0
        start = max(previous_offset, size - max_bytes)
        output = run(
            _runtime_exec_cmd(
                runtime,
                name,
                f"tail -c +{start + 1} {quoted_path} 2>/dev/null | tail -c {max_bytes}",
                project,
            )
        )
        _access_log_states[key] = {"inode": 0, "offset": size}
        if start > previous_offset and "\n" in output:
            output = output.split("\n", 1)[1]
        collected_lines.extend(output.splitlines())
    return _summarize_access_lines(collected_lines, interval_seconds, True, readable_files)


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _security_alert(
    alert_type: str,
    severity: str,
    title: str,
    message: str,
    value: float,
    threshold: float,
    container: Dict[str, object] | None = None,
) -> Dict[str, object]:
    container = container or {}
    return {
        "type": alert_type,
        "severity": severity,
        "title": title,
        "message": message,
        "value": value,
        "threshold": threshold,
        "runtime": str(container.get("runtime") or ""),
        "project": str(container.get("project") or ""),
        "container_name": str(container.get("name") or ""),
    }


def _http_security_alerts(
    access: Dict[str, object], container: Dict[str, object] | None = None
) -> List[Dict[str, object]]:
    alerts: List[Dict[str, object]] = []
    http_rps = _env_float("ALERT_CC_TOTAL_RPS", 100)
    http_ip_rps = _env_float("ALERT_CC_IP_RPS", 30)
    http_4xx_rate = _env_float("ALERT_CC_4XX_RATE", 0.5)
    http_min_requests = _env_float("ALERT_CC_MIN_REQUESTS", 50)
    web_scan_requests = _env_float("ALERT_WEB_SCAN_REQUESTS", 10)
    auth_failures_per_ip = _env_float("ALERT_AUTH_FAILURES_PER_IP", 20)
    scope = "容器访问日志" if container else "主机访问日志"
    requests_count = int(access.get("requests") or 0)
    total_rps = float(access.get("requests_per_second") or 0)
    top_ip_rps = float(access.get("top_ip_requests_per_second") or 0)
    if total_rps >= http_rps:
        alerts.append(
            _security_alert(
                "cc_total_rps",
                "critical" if total_rps >= http_rps * 2 else "warning",
                "疑似 HTTP/CC 攻击",
                f"{scope}请求速率 {total_rps:.1f} req/s 超过阈值 {http_rps:.1f} req/s",
                total_rps,
                http_rps,
                container,
            )
        )
    if top_ip_rps >= http_ip_rps:
        top_ip = str(access.get("top_ip") or "unknown")
        alerts.append(
            _security_alert(
                "cc_single_ip",
                "warning",
                "单 IP 请求洪泛",
                f"来源 {top_ip} 请求速率 {top_ip_rps:.1f} req/s 超过阈值 {http_ip_rps:.1f} req/s",
                top_ip_rps,
                http_ip_rps,
                container,
            )
        )
    if requests_count >= http_min_requests:
        bad_rate = float(int(access.get("status_4xx") or 0)) / max(1, requests_count)
        if bad_rate >= http_4xx_rate:
            alerts.append(
                _security_alert(
                    "cc_4xx_ratio",
                    "warning",
                    "HTTP 异常请求比例过高",
                    f"4xx 比例 {bad_rate:.1%} 超过阈值 {http_4xx_rate:.1%}",
                    bad_rate,
                    http_4xx_rate,
                    container,
                )
            )
    suspicious_requests = int(access.get("suspicious_requests") or 0)
    if suspicious_requests >= web_scan_requests:
        scanner_ip = str(access.get("top_scanner_ip") or "unknown")
        suspicious_unique_paths = int(access.get("suspicious_unique_paths") or 0)
        alerts.append(
            _security_alert(
                "web_scan",
                "warning",
                "疑似 Web 路径扫描",
                f"来源 {scanner_ip} 命中 {suspicious_requests} 次敏感路径规则，涉及 {suspicious_unique_paths} 个路径",
                suspicious_requests,
                web_scan_requests,
                container,
            )
        )
    top_ip_4xx_requests = int(access.get("top_ip_4xx_requests") or 0)
    if top_ip_4xx_requests >= auth_failures_per_ip:
        top_ip_4xx = str(access.get("top_ip_4xx") or "unknown")
        alerts.append(
            _security_alert(
                "http_abuse",
                "warning",
                "疑似登录或接口滥用",
                f"来源 {top_ip_4xx} 在采样周期产生 {top_ip_4xx_requests} 次 4xx 响应",
                top_ip_4xx_requests,
                auth_failures_per_ip,
                container,
            )
        )
    return alerts


def collect_security_summary(containers: List[Dict[str, object]], interval_seconds: float) -> Dict[str, object]:
    enabled = os.getenv("SECURITY_MONITOR_ENABLED", "true").strip().lower() not in ("0", "false", "no", "off")
    access = _collect_access_log_stats(interval_seconds) if enabled else {"enabled": False, "readable_files": 0}
    summary: Dict[str, object] = {
        "enabled": enabled,
        "interval_seconds": round(max(1.0, interval_seconds), 3),
        "total_rx_bps": 0.0,
        "total_tx_bps": 0.0,
        "total_rx_pps": 0.0,
        "total_tx_pps": 0.0,
        "syn_recv_count": 0,
        "access_log": access,
        "alerts": [],
    }
    if not enabled:
        return summary

    ddos_rx_bps = _env_float("ALERT_DDOS_RX_BPS", 100_000_000)
    ddos_rx_pps = _env_float("ALERT_DDOS_RX_PPS", 50_000)
    ddos_syn = _env_float("ALERT_DDOS_SYN_RECV", 200)
    scan_ports = _env_float("ALERT_SCAN_UNIQUE_PORTS", 20)
    abuse_unique_ips = _env_float("ALERT_ABUSE_OUTBOUND_UNIQUE_IPS", 200)
    abuse_suspicious = _env_float("ALERT_ABUSE_SUSPICIOUS_CONNECTIONS", 20)
    abuse_tx_bps = _env_float("ALERT_ABUSE_TX_BPS", 100_000_000)
    abuse_tx_pps = _env_float("ALERT_ABUSE_TX_PPS", 50_000)
    abuse_tcp_opens = _env_float("ALERT_ABUSE_TCP_OPENS_PER_SEC", 200)
    abuse_tcp_fails = _env_float("ALERT_ABUSE_TCP_FAILS_PER_SEC", 50)
    abuse_udp_out = _env_float("ALERT_ABUSE_UDP_OUT_PER_SEC", 10_000)
    abuse_processes = _env_float("ALERT_ABUSE_PROCESS_COUNT", 500)
    config_audit_enabled = os.getenv("SECURITY_CONFIG_AUDIT_ENABLED", "true").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )
    panel_detection_enabled = os.getenv("SECURITY_PANEL_PAIRING_DETECTION_ENABLED", "true").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )
    alerts: List[Dict[str, object]] = []

    for container in containers:
        if container.get("runtime") == "docker" and container.get("monitor_mode") == "notice":
            alerts.append(
                _security_alert(
                    "docker_container_notice",
                    "info",
                    "发现 Docker 容器（仅提醒）",
                    f"Docker 容器 {container.get('name') or 'unknown'} 已发现；默认不执行深度采集或安全扫描",
                    1,
                    1,
                    container,
                )
            )
            continue
        security = container.get("security") if isinstance(container.get("security"), dict) else {}
        rx_bps = float(container.get("net_rx_bps") or 0)
        tx_bps = float(container.get("net_tx_bps") or 0)
        rx_pps = float(security.get("net_rx_pps") or 0)
        tx_pps = float(security.get("net_tx_pps") or 0)
        syn_recv = int(security.get("syn_recv_count") or 0)
        summary["total_rx_bps"] = float(summary["total_rx_bps"]) + rx_bps
        summary["total_tx_bps"] = float(summary["total_tx_bps"]) + tx_bps
        summary["total_rx_pps"] = float(summary["total_rx_pps"]) + rx_pps
        summary["total_tx_pps"] = float(summary["total_tx_pps"]) + tx_pps
        summary["syn_recv_count"] = int(summary["syn_recv_count"]) + syn_recv

        if rx_bps >= ddos_rx_bps:
            alerts.append(
                _security_alert(
                    "ddos_bandwidth",
                    "critical" if rx_bps >= ddos_rx_bps * 2 else "warning",
                    "疑似流量型 DDoS",
                    f"容器入站速率 {rx_bps:.0f} B/s 超过阈值 {ddos_rx_bps:.0f} B/s",
                    rx_bps,
                    ddos_rx_bps,
                    container,
                )
            )
        if rx_pps >= ddos_rx_pps:
            alerts.append(
                _security_alert(
                    "ddos_packets",
                    "critical" if rx_pps >= ddos_rx_pps * 2 else "warning",
                    "疑似高包速率 DDoS",
                    f"容器入站包速率 {rx_pps:.0f} pps 超过阈值 {ddos_rx_pps:.0f} pps",
                    rx_pps,
                    ddos_rx_pps,
                    container,
                )
            )
        if syn_recv >= ddos_syn:
            alerts.append(
                _security_alert(
                    "ddos_syn",
                    "critical" if syn_recv >= ddos_syn * 2 else "warning",
                    "疑似 SYN Flood",
                    f"SYN_RECV 连接数 {syn_recv} 超过阈值 {int(ddos_syn)}",
                    syn_recv,
                    ddos_syn,
                    container,
                )
            )
        scan_count = int(security.get("scan_unique_ports_max") or 0)
        if scan_count >= scan_ports:
            source_ip = str(security.get("scan_source_ip") or "unknown")
            alerts.append(
                _security_alert(
                    "port_scan",
                    "warning",
                    "疑似端口扫描",
                    f"来源 {source_ip} 同时探测 {scan_count} 个本地端口",
                    scan_count,
                    scan_ports,
                    container,
                )
            )
        unique_ips = int(security.get("outbound_unique_ips") or 0)
        suspicious_connections = int(security.get("suspicious_outbound_connections") or 0)
        if unique_ips >= abuse_unique_ips:
            alerts.append(
                _security_alert(
                    "outbound_fanout",
                    "warning",
                    "疑似出站滥用",
                    f"容器同时连接 {unique_ips} 个外部 IP，可能存在代理滥用或扫描",
                    unique_ips,
                    abuse_unique_ips,
                    container,
                )
            )
        if suspicious_connections >= abuse_suspicious:
            alerts.append(
                _security_alert(
                    "outbound_sensitive_ports",
                    "critical",
                    "敏感端口出站连接异常",
                    f"敏感出站端口连接数 {suspicious_connections} 超过阈值 {int(abuse_suspicious)}",
                    suspicious_connections,
                    abuse_suspicious,
                    container,
                )
            )
        if tx_bps >= abuse_tx_bps:
            alerts.append(
                _security_alert(
                    "outbound_bandwidth_abuse",
                    "critical" if tx_bps >= abuse_tx_bps * 2 else "warning",
                    "异常大流量出站",
                    f"容器出站速率 {tx_bps:.0f} B/s 超过阈值 {abuse_tx_bps:.0f} B/s",
                    tx_bps,
                    abuse_tx_bps,
                    container,
                )
            )
        if tx_pps >= abuse_tx_pps:
            alerts.append(
                _security_alert(
                    "outbound_packet_abuse",
                    "critical" if tx_pps >= abuse_tx_pps * 2 else "warning",
                    "异常高包速率出站",
                    f"容器出站包速率 {tx_pps:.0f} pps 超过阈值 {abuse_tx_pps:.0f} pps",
                    tx_pps,
                    abuse_tx_pps,
                    container,
                )
            )
        protocol_rates = security.get("protocol_rates") if isinstance(security.get("protocol_rates"), dict) else {}
        tcp_open_rate = float(protocol_rates.get("Tcp_ActiveOpens_per_second") or 0)
        tcp_fail_rate = float(protocol_rates.get("Tcp_AttemptFails_per_second") or 0)
        udp_out_rate = float(protocol_rates.get("Udp_OutDatagrams_per_second") or 0)
        if tcp_open_rate >= abuse_tcp_opens:
            alerts.append(
                _security_alert(
                    "outbound_connection_churn",
                    "warning",
                    "异常 TCP 建连速率",
                    f"容器主动 TCP 建连速率 {tcp_open_rate:.1f}/s 超过阈值 {abuse_tcp_opens:.1f}/s",
                    tcp_open_rate,
                    abuse_tcp_opens,
                    container,
                )
            )
        if tcp_fail_rate >= abuse_tcp_fails:
            alerts.append(
                _security_alert(
                    "outbound_connection_failures",
                    "critical" if tcp_fail_rate >= abuse_tcp_fails * 2 else "warning",
                    "异常 TCP 连接失败速率",
                    f"容器 TCP 连接失败速率 {tcp_fail_rate:.1f}/s 超过阈值 {abuse_tcp_fails:.1f}/s，可能存在扫描或僵尸网络活动",
                    tcp_fail_rate,
                    abuse_tcp_fails,
                    container,
                )
            )
        if udp_out_rate >= abuse_udp_out:
            alerts.append(
                _security_alert(
                    "udp_outbound_flood",
                    "critical" if udp_out_rate >= abuse_udp_out * 2 else "warning",
                    "异常 UDP 出站速率",
                    f"容器 UDP 出站数据报速率 {udp_out_rate:.1f}/s 超过阈值 {abuse_udp_out:.1f}/s",
                    udp_out_rate,
                    abuse_udp_out,
                    container,
                )
            )
        process_count = int(security.get("process_count") or 0)
        if process_count >= abuse_processes:
            alerts.append(
                _security_alert(
                    "process_fanout_abuse",
                    "critical" if process_count >= abuse_processes * 2 else "warning",
                    "容器进程数量异常",
                    f"容器进程数量 {process_count} 超过阈值 {int(abuse_processes)}，可能存在 fork bomb 或任务滥用",
                    process_count,
                    abuse_processes,
                    container,
                )
            )
        suspicious_processes = security.get("suspicious_processes")
        if isinstance(suspicious_processes, list) and suspicious_processes:
            first_process = suspicious_processes[0] if isinstance(suspicious_processes[0], dict) else {}
            alerts.append(
                _security_alert(
                    "malicious_process",
                    "critical",
                    "疑似恶意程序",
                    f"命中 {len(suspicious_processes)} 个可疑进程特征；首个特征 {first_process.get('pattern') or 'unknown'}，PID {first_process.get('pid') or 0}",
                    len(suspicious_processes),
                    1,
                    container,
                )
            )
        configuration_risks = security.get("configuration_risks")
        if config_audit_enabled and isinstance(configuration_risks, list) and configuration_risks:
            risk_items = [item for item in configuration_risks if isinstance(item, dict)]
            severity = "critical" if any(item.get("severity") == "critical" for item in risk_items) else "warning"
            alerts.append(
                _security_alert(
                    "container_security_risk",
                    severity,
                    "容器隔离配置风险",
                    "；".join(str(item.get("message") or item.get("code") or "unknown") for item in risk_items[:5]),
                    len(risk_items),
                    1,
                    container,
                )
            )
        panel_pairing = security.get("panel_pairing") if isinstance(security.get("panel_pairing"), dict) else {}
        panel_domains = panel_pairing.get("panel_domains") if isinstance(panel_pairing.get("panel_domains"), list) else []
        unapproved_domains = (
            panel_pairing.get("unapproved_domains") if isinstance(panel_pairing.get("unapproved_domains"), list) else []
        )
        allowlist_configured = bool(os.getenv("SECURITY_ALLOWED_PANEL_DOMAINS", "").strip())
        pairing_is_allowed = allowlist_configured and bool(panel_domains) and not unapproved_domains
        if panel_detection_enabled and panel_pairing.get("detected") and not pairing_is_allowed:
            process_patterns = (
                panel_pairing.get("process_patterns") if isinstance(panel_pairing.get("process_patterns"), list) else []
            )
            config_files = panel_pairing.get("config_files") if isinstance(panel_pairing.get("config_files"), list) else []
            evidence = []
            if unapproved_domains:
                evidence.append(f"未授权面板域名 {','.join(str(item) for item in unapproved_domains[:5])}")
            if process_patterns:
                evidence.append(f"节点程序特征 {','.join(str(item) for item in process_patterns[:5])}")
            if config_files:
                evidence.append(f"配置文件 {','.join(str(item) for item in config_files[:3])}")
            listening_ports = security.get("listening_ports") if isinstance(security.get("listening_ports"), list) else []
            if listening_ports:
                evidence.append(f"容器内部监听端口 {','.join(str(item) for item in listening_ports[:10])}")
            if not evidence:
                evidence.append("发现 ApiHost/ApiKey/NodeID 等面板对接配置特征")
            alerts.append(
                _security_alert(
                    "unauthorized_panel_pairing",
                    "critical" if unapproved_domains else "warning",
                    "疑似对接第三方机场面板",
                    "；".join(evidence),
                    len(unapproved_domains) or len(process_patterns) or len(config_files) or 1,
                    1,
                    container,
                )
            )
        container_access = security.get("access_log")
        if isinstance(container_access, dict):
            alerts.extend(_http_security_alerts(container_access, container))

    total_rx_bps = float(summary["total_rx_bps"])
    total_rx_pps = float(summary["total_rx_pps"])
    total_syn_recv = int(summary["syn_recv_count"])
    alert_types = {str(item.get("type") or "") for item in alerts}
    if total_rx_bps >= ddos_rx_bps and "ddos_bandwidth" not in alert_types:
        alerts.append(
            _security_alert(
                "ddos_host_bandwidth",
                "critical" if total_rx_bps >= ddos_rx_bps * 2 else "warning",
                "主机疑似流量型 DDoS",
                f"主机容器合计入站速率 {total_rx_bps:.0f} B/s 超过阈值 {ddos_rx_bps:.0f} B/s",
                total_rx_bps,
                ddos_rx_bps,
            )
        )
    if total_rx_pps >= ddos_rx_pps and "ddos_packets" not in alert_types:
        alerts.append(
            _security_alert(
                "ddos_host_packets",
                "critical" if total_rx_pps >= ddos_rx_pps * 2 else "warning",
                "主机疑似高包速率 DDoS",
                f"主机容器合计入站包速率 {total_rx_pps:.0f} pps 超过阈值 {ddos_rx_pps:.0f} pps",
                total_rx_pps,
                ddos_rx_pps,
            )
        )
    if total_syn_recv >= ddos_syn and "ddos_syn" not in alert_types:
        alerts.append(
            _security_alert(
                "ddos_host_syn",
                "critical" if total_syn_recv >= ddos_syn * 2 else "warning",
                "主机疑似 SYN Flood",
                f"主机容器合计 SYN_RECV {total_syn_recv} 超过阈值 {int(ddos_syn)}",
                total_syn_recv,
                ddos_syn,
            )
        )

    alerts.extend(_http_security_alerts(access))

    summary["alerts"] = alerts
    return summary


def collect_top_cpu_process(name: str, runtime: str = "", project: str = "") -> Dict[str, object]:
    runtime = runtime or get_container_bin()
    if not runtime:
        return {"pid": 0, "cpu_percent": 0.0, "command": ""}

    kind = _runtime_kind(runtime)
    top_cmd = [runtime, "top", name, "pcpu,pid,comm,args"]
    if kind == "docker":
        top_cmd = [runtime, "top", name, "-eo", "pcpu,pid,comm,args"]
    elif kind == "incus":
        top_cmd = _runtime_base(runtime, project) + ["exec", name, "--", "ps", "-eo", "pcpu,pid,comm,args"]
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


def collect_suspicious_processes(name: str, runtime: str = "", project: str = "") -> List[Dict[str, object]]:
    runtime = runtime or get_container_bin()
    if not runtime:
        return []
    patterns = [
        pattern.strip().lower()
        for pattern in os.getenv(
            "SECURITY_SUSPICIOUS_PROCESS_PATTERNS",
            "xmrig,kinsing,kdevtmpfsi,watchbog,cryptonight,minerd,pwnrig,teamtnt,stratum+tcp,stratum+ssl,/dev/tcp/,nc -e,ncat -e,socat exec:,mkfifo /tmp",
        ).split(",")
        if pattern.strip()
    ]
    if not patterns:
        return []
    output = run(_runtime_exec_cmd(runtime, name, "ps -eo pid,pcpu,comm,args 2>/dev/null", project))
    matches: List[Dict[str, object]] = []
    for line in output.splitlines():
        text = line.strip()
        if not text or text.lower().startswith("pid"):
            continue
        lowered = text.lower()
        matched_pattern = next((pattern for pattern in patterns if pattern in lowered), "")
        if not matched_pattern:
            continue
        parts = text.split(None, 3)
        try:
            pid = int(parts[0])
        except (IndexError, ValueError):
            pid = 0
        try:
            cpu_percent = float(parts[1])
        except (IndexError, ValueError):
            cpu_percent = 0.0
        matches.append(
            {
                "pid": pid,
                "cpu_percent": cpu_percent,
                "pattern": matched_pattern,
                "command": (parts[3] if len(parts) > 3 else text)[:500],
            }
        )
        if len(matches) >= 20:
            break
    return matches


def _panel_domain_allowed(domain: str, allowed_domains: List[str]) -> bool:
    candidate = domain.strip().lower().rstrip(".")
    for raw in allowed_domains:
        allowed = raw.strip().lower().lstrip("*.").rstrip(".")
        if allowed and (candidate == allowed or candidate.endswith(f".{allowed}")):
            return True
    return False


def collect_panel_pairing_indicators(
    name: str, runtime: str = "", project: str = "", image: str = ""
) -> Dict[str, object]:
    runtime = runtime or get_container_bin()
    result: Dict[str, object] = {
        "detected": False,
        "process_patterns": [],
        "config_files": [],
        "credential_markers": [],
        "panel_domains": [],
        "unapproved_domains": [],
        "approved": False,
    }
    if not runtime:
        return result
    patterns = [
        pattern.strip().lower()
        for pattern in os.getenv(
            "SECURITY_PANEL_PROCESS_PATTERNS",
            "xboard-node,xrayr,v2bx,soga,sspanel-uim-node",
        ).split(",")
        if pattern.strip()
    ]
    process_output = run(_runtime_exec_cmd(runtime, name, "ps -eo comm,args 2>/dev/null", project)).lower()
    combined_identity = f"{name} {image}".lower()
    process_patterns = sorted(
        {pattern for pattern in patterns if pattern in process_output or pattern in combined_identity}
    )

    raw_paths = os.getenv(
        "SECURITY_PANEL_CONFIG_PATHS",
        "/etc/XrayR/config.yml,/etc/V2bX/config.json,/etc/xboard-node/config.yml,/etc/xboard-node/config.yaml,/opt/xboard-node/config.yml,/app/config/config.yml,/etc/soga/soga.conf,/etc/soga/config.yml",
    )
    paths = [path.strip() for path in raw_paths.split(",") if re.fullmatch(r"/[A-Za-z0-9_./-]+", path.strip())]
    quoted_paths = " ".join(shlex.quote(path) for path in paths)
    evidence_output = ""
    if quoted_paths:
        shell_command = (
            f"for p in {quoted_paths}; do "
            "if [ -r \"$p\" ]; then "
            "echo \"@@FILE:$p\"; "
            "grep -Eio 'https?://[^\"[:space:],}]+' \"$p\" 2>/dev/null | head -n 20; "
            "grep -Eio 'ApiHost|ApiKey|NodeID|MachineToken|machine_token|panel[.]url|api_host' \"$p\" 2>/dev/null "
            "| sort -u | sed 's/^/@@KEY:/'; "
            "fi; done; echo '@@ENV'; "
            "for f in /proc/[0-9]*/environ; do "
            "[ -r \"$f\" ] || continue; "
            "tr '\\000' '\\n' < \"$f\" 2>/dev/null "
            "| grep -Ei '^(apiHost|API_HOST|PANEL_URL|webapi)=https?://' | head -n 20; "
            "tr '\\000' '\\n' < \"$f\" 2>/dev/null "
            "| grep -Eio '^(apiKey|API_KEY|MACHINE_TOKEN|nodeID|NODE_ID)=' "
            "| cut -d= -f1 | sed 's/^/@@KEY:/'; "
            "done"
        )
        evidence_output = run(_runtime_exec_cmd(runtime, name, shell_command, project))

    config_files = set()
    credential_markers = set()
    domains = set()
    current_file = ""
    for line in evidence_output.splitlines():
        text = line.strip()
        if text.startswith("@@FILE:"):
            current_file = text.removeprefix("@@FILE:")[:300]
        elif text == "@@ENV":
            current_file = ""
        elif text.startswith("@@KEY:"):
            credential_markers.add(text.removeprefix("@@KEY:")[:80])
            if current_file:
                config_files.add(current_file)
        else:
            found_url = False
            for url in re.findall(r"https?://[^\s\"',}]+", text, flags=re.IGNORECASE):
                try:
                    hostname = urlparse(url).hostname
                except ValueError:
                    hostname = None
                if hostname:
                    domains.add(hostname.lower().rstrip("."))
                    found_url = True
            if current_file and found_url:
                config_files.add(current_file)
    allowed_domains = [item.strip() for item in os.getenv("SECURITY_ALLOWED_PANEL_DOMAINS", "").split(",") if item.strip()]
    unapproved_domains = sorted(domain for domain in domains if not _panel_domain_allowed(domain, allowed_domains))
    detected = bool(process_patterns or config_files or credential_markers or domains)
    result.update(
        {
            "detected": detected,
            "process_patterns": process_patterns,
            "config_files": sorted(config_files),
            "credential_markers": sorted(credential_markers),
            "panel_domains": sorted(domains),
            "unapproved_domains": unapproved_domains,
            "approved": bool(allowed_domains and domains and not unapproved_domains),
        }
    )
    return result


def _image_matches(image: str, patterns: List[str]) -> bool:
    if not patterns:
        return False
    val = image.strip().lower()
    for p in patterns:
        token = p.strip().lower()
        if not token:
            continue
        if token == "*":
            return True
        if token in val:
            return True
    return False


def _oci_containers(runtime_name: str, runtime: str, patterns: List[str]) -> List[Dict[str, str]]:
    out = run([runtime, "ps", "--format", "{{.ID}}|{{.Names}}|{{.Image}}"])
    items: List[Dict[str, str]] = []
    for line in out.splitlines():
        parts = line.strip().split("|", 2)
        if len(parts) != 3:
            continue
        container_id, name, image = (x.strip() for x in parts)
        if not _image_matches(image, patterns):
            continue
        items.append({"id": container_id, "name": name, "image": image, "runtime": runtime_name, "runtime_bin": runtime})
    return items


def _incus_security_risks(item: Dict[str, object]) -> List[Dict[str, str]]:
    config: Dict[str, object] = {}
    for key in ("config", "expanded_config"):
        value = item.get(key)
        if isinstance(value, dict):
            config.update(value)
    risks: List[Dict[str, str]] = []
    if str(config.get("security.privileged") or "").lower() == "true":
        risks.append({"code": "incus_privileged", "severity": "critical", "message": "Incus 容器启用了 security.privileged"})
    if str(config.get("security.nesting") or "").lower() == "true":
        risks.append({"code": "incus_nesting", "severity": "warning", "message": "Incus 容器启用了 security.nesting"})
    for key in ("raw.lxc", "raw.apparmor", "raw.seccomp", "raw.idmap"):
        if str(config.get(key) or "").strip():
            risks.append({"code": f"incus_{key.replace('.', '_')}", "severity": "warning", "message": f"Incus 容器设置了 {key}"})
    devices = item.get("expanded_devices") if isinstance(item.get("expanded_devices"), dict) else {}
    for device_name, raw_device in devices.items():
        if not isinstance(raw_device, dict):
            continue
        device_type = str(raw_device.get("type") or "")
        source = str(raw_device.get("source") or "")
        if device_type in ("unix-char", "unix-block"):
            risks.append(
                {
                    "code": "incus_host_device",
                    "severity": "warning",
                    "message": f"Incus 设备 {device_name} 暴露宿主机设备 {source or device_type}",
                }
            )
        if device_type == "disk" and source in ("/", "/proc", "/sys", "/dev", "/run"):
            risks.append(
                {
                    "code": "incus_sensitive_mount",
                    "severity": "critical",
                    "message": f"Incus 设备 {device_name} 挂载宿主机敏感路径 {source}",
                }
            )
    return risks


def _incus_network_exposure(item: Dict[str, object]) -> List[Dict[str, str]]:
    devices = item.get("expanded_devices") if isinstance(item.get("expanded_devices"), dict) else {}
    mappings: List[Dict[str, str]] = []
    for device_name, raw_device in devices.items():
        if not isinstance(raw_device, dict) or str(raw_device.get("type") or "") != "proxy":
            continue
        mappings.append(
            {
                "source": "incus-proxy",
                "device": str(device_name),
                "listen": str(raw_device.get("listen") or ""),
                "target": str(raw_device.get("connect") or ""),
                "nat": str(raw_device.get("nat") or "false"),
            }
        )
    return mappings


def _oci_security_risks(inspect_data: Dict[str, object]) -> List[Dict[str, str]]:
    host_config = inspect_data.get("HostConfig") if isinstance(inspect_data.get("HostConfig"), dict) else {}
    risks: List[Dict[str, str]] = []
    if bool(host_config.get("Privileged")):
        risks.append({"code": "oci_privileged", "severity": "critical", "message": "容器以 privileged 模式运行"})
    raw_capabilities = host_config.get("CapAdd") or []
    if not isinstance(raw_capabilities, list):
        raw_capabilities = [raw_capabilities]
    capabilities = {str(item).upper() for item in raw_capabilities}
    dangerous_capabilities = sorted(capabilities & {"SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "NET_ADMIN", "DAC_READ_SEARCH"})
    if dangerous_capabilities:
        risks.append(
            {
                "code": "oci_dangerous_capabilities",
                "severity": "warning",
                "message": f"容器增加高风险 capabilities: {','.join(dangerous_capabilities)}",
            }
        )
    for field, label in (("NetworkMode", "network"), ("PidMode", "PID"), ("IpcMode", "IPC")):
        if str(host_config.get(field) or "").lower() == "host":
            risks.append({"code": f"oci_host_{label.lower()}", "severity": "warning", "message": f"容器共享宿主机 {label} 命名空间"})
    raw_security_options = host_config.get("SecurityOpt") or []
    if not isinstance(raw_security_options, list):
        raw_security_options = [raw_security_options]
    security_options = " ".join(str(item).lower() for item in raw_security_options)
    if any(value in security_options for value in ("seccomp=unconfined", "apparmor=unconfined", "label=disable")):
        risks.append({"code": "oci_isolation_disabled", "severity": "warning", "message": "容器关闭了部分 seccomp/AppArmor/SELinux 隔离"})
    mounts = inspect_data.get("Mounts") if isinstance(inspect_data.get("Mounts"), list) else []
    for mount in mounts:
        if not isinstance(mount, dict):
            continue
        source = str(mount.get("Source") or "")
        if source in ("/", "/proc", "/sys", "/dev", "/run", "/var/run/podman/podman.sock"):
            risks.append(
                {
                    "code": "oci_sensitive_mount",
                    "severity": "critical" if source in ("/", "/var/run/podman/podman.sock") else "warning",
                    "message": f"容器挂载宿主机敏感路径 {source}",
                }
            )
    return risks


def _oci_network_exposure(inspect_data: Dict[str, object]) -> List[Dict[str, str]]:
    network_settings = (
        inspect_data.get("NetworkSettings") if isinstance(inspect_data.get("NetworkSettings"), dict) else {}
    )
    ports = network_settings.get("Ports") if isinstance(network_settings.get("Ports"), dict) else {}
    if not ports:
        host_config = inspect_data.get("HostConfig") if isinstance(inspect_data.get("HostConfig"), dict) else {}
        ports = host_config.get("PortBindings") if isinstance(host_config.get("PortBindings"), dict) else {}
    mappings: List[Dict[str, str]] = []
    for container_port, bindings in ports.items():
        if not isinstance(bindings, list):
            continue
        for binding in bindings:
            if not isinstance(binding, dict):
                continue
            host_ip = str(binding.get("HostIp") or "0.0.0.0")
            host_port = str(binding.get("HostPort") or "")
            mappings.append(
                {
                    "source": "podman-publish",
                    "listen": f"{host_ip}:{host_port}" if host_port else host_ip,
                    "target": str(container_port),
                }
            )
    return mappings


def _incus_containers(runtime: str) -> List[Dict[str, str]]:
    project = os.getenv("INCUS_PROJECT", "").strip()
    cmd = _runtime_base(runtime, project) + ["list", "type=container", "status=running", "--format=json"]
    output = run(cmd)
    try:
        payload = json.loads(output) if output else []
    except Exception:
        payload = []
    patterns_env = os.getenv("MONITORED_INCUS_PATTERNS", "*")
    patterns = [x.strip() for x in patterns_env.split(",") if x.strip()]
    items: List[Dict[str, str]] = []
    for item in payload if isinstance(payload, list) else []:
        if not isinstance(item, dict):
            continue
        if str(item.get("type") or "container").lower() not in ("container", ""):
            continue
        if str(item.get("status") or "running").lower() != "running":
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        config = item.get("config") if isinstance(item.get("config"), dict) else {}
        expanded_config = item.get("expanded_config") if isinstance(item.get("expanded_config"), dict) else {}
        image = str(
            config.get("image.description")
            or expanded_config.get("image.description")
            or config.get("image.os")
            or expanded_config.get("image.os")
            or config.get("volatile.base_image")
            or "incus-container"
        )
        if not _image_matches(f"{name} {image}", patterns):
            continue
        item_project = project or str(item.get("project") or "default")
        state = item.get("state") if isinstance(item.get("state"), dict) else {}
        items.append(
            {
                "id": name,
                "name": name,
                "image": image,
                "runtime": "incus",
                "runtime_bin": runtime,
                "project": item_project,
                "pid": str(state.get("pid") or ""),
                "security_risks": _incus_security_risks(item),
                "network_exposure": _incus_network_exposure(item),
            }
        )
    return items


def list_containers() -> List[Dict[str, str]]:
    patterns_env = os.getenv(
        "MONITORED_IMAGE_PATTERNS",
        "*",
    )
    patterns = [x.strip() for x in patterns_env.split(",") if x.strip()]
    items: List[Dict[str, str]] = []
    for runtime_name, runtime in get_runtime_bins().items():
        if runtime_name == "docker" and _docker_monitor_mode() == "off":
            continue
        if runtime_name == "incus":
            items.extend(_incus_containers(runtime))
        else:
            items.extend(_oci_containers(runtime_name, runtime, patterns))
    return items


def collect_docker_notice(container: Dict[str, str]) -> Dict[str, object]:
    return {
        "id": container.get("id", ""),
        "name": container.get("name", "unknown"),
        "image": container.get("image", ""),
        "runtime": "docker",
        "project": "",
        "monitor_mode": "notice",
        "cpu_percent": 0.0,
        "mem_bytes": 0,
        "mem_percent": 0.0,
        "net_rx_bps": 0.0,
        "net_tx_bps": 0.0,
        "conn_count": 0,
        "tcp_country_stats": [],
        "udp_country_stats": [],
        "disk": collect_disk_alert(),
        "container_disk": {"rw_bytes": 0, "rootfs_bytes": 0, "fs": {}},
        "top_cpu_process": {"pid": 0, "cpu_percent": 0.0, "command": ""},
        "security": {"notice_only": True},
    }


def podman_containers() -> List[Dict[str, str]]:
    """Backward-compatible alias for callers using the old function name."""
    return list_containers()




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


def collect_container_disk_usage(name: str, runtime: str = "", project: str = "") -> Dict[str, Dict[str, int] | int]:
    runtime = runtime or get_container_bin()
    if not runtime:
        return {
            "rw_bytes": 0,
            "rootfs_bytes": 0,
            "fs": {"root": {"total_bytes": 0, "avail_bytes": 0}, "data": {"total_bytes": 0, "avail_bytes": 0}},
        }

    rw_bytes = 0
    rootfs_bytes = 0
    if _runtime_kind(runtime) != "incus":
        inspect = run([runtime, "container", "inspect", "--size", name])
        if inspect:
            try:
                item = json.loads(inspect)[0]
                rw_bytes = int(item.get("SizeRw") or 0)
                rootfs_bytes = int(item.get("SizeRootFs") or 0)
            except Exception:
                pass

    fs_df = run(_runtime_exec_cmd(runtime, name, "df -P / /data 2>/dev/null || true", project))
    fs = {
        "root": _parse_df_target(fs_df, "/"),
        "data": _parse_df_target(fs_df, "/data"),
    }
    return {"rw_bytes": rw_bytes, "rootfs_bytes": rootfs_bytes, "fs": fs}


def _incus_instance_pid(runtime: str, name: str, project: str = "") -> int:
    path = f"/1.0/instances/{quote(name, safe='')}/state"
    output = run(_runtime_base(runtime, project) + ["query", path])
    if not output:
        return 0
    try:
        payload = json.loads(output)
        state = payload.get("metadata", payload) if isinstance(payload, dict) else {}
        return int(state.get("pid", 0) or 0) if isinstance(state, dict) else 0
    except Exception:
        return 0


def _incus_stats(runtime: str, name: str, project: str) -> Dict[str, float | int]:
    metrics = _get_incus_metrics(runtime).get((project or "default", name), {})
    cpu_seconds = float(metrics.get("cpu_seconds", 0.0) or 0.0)
    container_key = f"incus:{project or 'default'}:{name}"
    cpu_percent = _derive_cpu_percent(container_key, cpu_seconds)
    mem_bytes = int(metrics.get("mem_bytes", 0.0) or 0)
    mem_percent = 0.0
    mem_limit_out = run(
        _runtime_exec_cmd(
            runtime,
            name,
            "awk '/^MemTotal:/{print $2 * 1024; exit}' /proc/meminfo 2>/dev/null",
            project,
        )
    ).strip()
    try:
        mem_limit = int(float(mem_limit_out))
    except ValueError:
        mem_limit = 0
    if mem_limit > 0 and mem_bytes > 0:
        mem_percent = (float(mem_bytes) / float(mem_limit)) * 100.0
    return {
        "cpu_percent": cpu_percent,
        "mem_bytes": mem_bytes,
        "mem_percent": mem_percent,
        "net_rx_total_bytes": int(metrics.get("net_rx_total_bytes", 0.0) or 0),
        "net_tx_total_bytes": int(metrics.get("net_tx_total_bytes", 0.0) or 0),
        "net_rx_total_packets": int(metrics.get("net_rx_total_packets", 0.0) or 0),
        "net_tx_total_packets": int(metrics.get("net_tx_total_packets", 0.0) or 0),
    }


def collect_container(
    name: str,
    container_id: str = "",
    runtime: str = "",
    runtime_name: str = "",
    project: str = "",
    pid_hint: int = 0,
    precomputed_security_risks: List[Dict[str, str]] | None = None,
    precomputed_network_exposure: List[Dict[str, str]] | None = None,
    image: str = "",
) -> Dict:
    runtime = runtime or get_container_bin()
    runtime_name = runtime_name or _runtime_kind(runtime)
    if not runtime:
        return {
            "id": container_id,
            "name": name,
            "cpu_percent": 0.0,
            "mem_bytes": 0,
            "mem_percent": 0.0,
            "net_rx_bps": 0.0,
            "net_tx_bps": 0.0,
            "conn_count": 0,
            "tcp_country_stats": [],
            "udp_country_stats": [],
            "disk": collect_disk_alert(),
            "container_disk": {"rw_bytes": 0, "rootfs_bytes": 0},
        }

    cpu_percent = 0.0
    mem = 0
    mem_percent = 0.0
    rx_total = 0
    tx_total = 0
    net_rx = 0.0
    net_tx = 0.0
    rx_packet_total = 0
    tx_packet_total = 0

    stats_json = ""
    stats_tpl = ""
    stats_compact = ""
    if runtime_name == "incus":
        parsed_stats = _incus_stats(runtime, name, project)
        parsed_tpl = _parse_stats_template("")
        parsed_compact = _parse_stats_compact("")
    else:
        stats_json = run([runtime, "stats", "--no-stream", "--format", "json", name])
        parsed_stats = _parse_stats_json(stats_json)
        stats_tpl = run_first_success(
            [
                [runtime, "stats", "--no-stream", "--format", "{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}", name],
                [runtime, "stats", "--no-stream", "--format", "{{.CPU}}|{{.MemUsage}}|{{.NetIO}}", name],
            ]
        )
        parsed_tpl = _parse_stats_template(stats_tpl)
        stats_compact = run_first_success(
            [
                [runtime, "stats", "--no-stream", "--format", "{{.CPU}}|{{.MemUsageBytes}}|{{.NetIO}}", name],
                [runtime, "stats", "--no-stream", "--format", "{{.CPU}}|{{.MemUsage}}|{{.NetIO}}", name],
            ]
        )
        parsed_compact = _parse_stats_compact(stats_compact)

    cpu_candidates = [parsed_stats["cpu_percent"], parsed_tpl["cpu_percent"], parsed_compact["cpu_percent"]]
    mem_candidates = [parsed_stats["mem_bytes"], parsed_tpl["mem_bytes"], parsed_compact["mem_bytes"]]
    mem_percent_candidates = [parsed_stats["mem_percent"], parsed_tpl["mem_percent"], parsed_compact["mem_percent"]]
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
    for mp in mem_percent_candidates:
        if float(mp) > 0:
            mem_percent = float(mp)
            break
    for rx_c, tx_c in net_candidates:
        if int(rx_c) > 0 or int(tx_c) > 0:
            rx_total = int(rx_c)
            tx_total = int(tx_c)
            break
    rx_packet_total = int(parsed_stats.get("net_rx_total_packets", 0) or 0)
    tx_packet_total = int(parsed_stats.get("net_tx_total_packets", 0) or 0)

    conn_count = 0
    pid = int(pid_hint or 0)
    inspect = ""
    configuration_risks = list(precomputed_security_risks or [])
    network_exposure = list(precomputed_network_exposure or [])
    if runtime_name == "incus":
        if pid <= 0:
            pid = _incus_instance_pid(runtime, name, project)
    else:
        inspect = run([runtime, "inspect", name])
    if inspect:
        try:
            d = json.loads(inspect)[0]
            pid = int(d.get("State", {}).get("Pid", 0) or 0)
            configuration_risks = _oci_security_risks(d)
            network_exposure = _oci_network_exposure(d)
        except Exception:
            pass
    if pid:
        conn_count = _count_connections_from_pid(pid)
        if conn_count <= 0:
            conn_out = run(["sh", "-lc", f"ss -Hantup | grep -c 'pid={pid},'"])
            conn_count = int(conn_out.strip() or 0)

    if pid > 0:
        proc_rx, proc_tx, proc_rx_packets, proc_tx_packets = _read_net_stats_from_pid(pid)
        if proc_rx > 0 or proc_tx > 0:
            if rx_total <= 0 and tx_total <= 0:
                rx_total = proc_rx
                tx_total = proc_tx
        if rx_packet_total <= 0 and tx_packet_total <= 0:
            rx_packet_total = proc_rx_packets
            tx_packet_total = proc_tx_packets

    container_key = f"{runtime_name}:{project}:{container_id or name}"
    net_rx, net_tx = _derive_net_bps(container_key, rx_total, tx_total)
    net_rx_pps, net_tx_pps = _derive_packet_rates(container_key, rx_packet_total, tx_packet_total)
    protocol_rates = _derive_protocol_rates(container_key, _read_protocol_counters(pid)) if pid > 0 else {}
    process_count = _read_process_count_from_pid(pid)

    if runtime_name != "incus" and stats_json.strip() == "" and stats_tpl.strip() == "" and stats_compact.strip() == "":
        warn_key = f"{runtime}:stats-empty"
        if warn_key not in _warned_parse_paths:
            _warned_parse_paths.add(warn_key)
            print(f"warn: '{runtime} stats' returned empty output; CPU/内存/网络将显示为 0。")
    if conn_count <= 0:
        conn_count = _count_connections_from_exec(runtime, name, project)
    tcp_ip_counter = _collect_tcp_remote_ips(pid)
    udp_ip_counter = _collect_udp_remote_ips(pid)
    if not tcp_ip_counter:
        tcp_ip_counter = _collect_remote_ips_from_exec(runtime, name, "tcp", project)
    if not udp_ip_counter:
        udp_ip_counter = _collect_remote_ips_from_exec(runtime, name, "udp", project)
    tcp_country_stats = _geoip_country_batch(tcp_ip_counter)
    udp_country_stats = _geoip_country_batch(udp_ip_counter)

    if (mem <= 0 or mem_percent <= 0) and pid > 0:
        pid_mem_bytes, pid_mem_percent = _read_mem_usage_from_pid(pid)
        if mem <= 0 and pid_mem_bytes > 0:
            mem = pid_mem_bytes
        if mem_percent <= 0 and pid_mem_percent > 0:
            mem_percent = pid_mem_percent

    disk = collect_disk_alert()
    container_disk = collect_container_disk_usage(name, runtime, project)
    top_cpu_process = collect_top_cpu_process(name, runtime, project)
    suspicious_processes = collect_suspicious_processes(name, runtime, project)
    panel_pairing = collect_panel_pairing_indicators(name, runtime, project, image)
    socket_security = _collect_socket_security(pid)
    socket_security.update(
        {
            "net_rx_pps": net_rx_pps,
            "net_tx_pps": net_tx_pps,
            "net_rx_total_packets": rx_packet_total,
            "net_tx_total_packets": tx_packet_total,
            "suspicious_processes": suspicious_processes,
            "configuration_risks": configuration_risks,
            "protocol_rates": protocol_rates,
            "process_count": process_count,
            "panel_pairing": panel_pairing,
            "network_exposure": network_exposure,
        }
    )
    if cpu_percent <= 0 and float(top_cpu_process.get("cpu_percent") or 0) > 0:
        cpu_percent = float(top_cpu_process.get("cpu_percent") or 0)
    return {
        "id": container_id,
        "name": name,
        "image": image,
        "runtime": runtime_name,
        "project": project,
        "cpu_percent": cpu_percent,
        "mem_bytes": mem,
        "mem_percent": mem_percent,
        "net_rx_bps": net_rx,
        "net_tx_bps": net_tx,
        "conn_count": conn_count,
        "tcp_country_stats": tcp_country_stats,
        "udp_country_stats": udp_country_stats,
        "disk": disk,
        "container_disk": container_disk,
        "top_cpu_process": top_cpu_process,
        "security": socket_security,
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


def network_health(containers: List[Dict[str, str]] | None = None) -> Tuple[bool, bool]:
    containers = containers if containers is not None else list_containers()
    if not containers:
        return False, False

    v4_ok = False
    v6_ok = False
    for item in containers:
        name = item.get("name", "")
        if not name:
            continue
        runtime = item.get("runtime_bin", "") or get_container_bin()
        runtime_name = item.get("runtime", "") or _runtime_kind(runtime)
        project = item.get("project", "")
        try:
            pid = int(item.get("pid", "") or 0)
        except ValueError:
            pid = 0
        if runtime_name == "incus":
            if pid <= 0:
                pid = _incus_instance_pid(runtime, name, project)
        else:
            inspect = run([runtime, "inspect", name])
            try:
                detail = json.loads(inspect)[0]
                pid = int(detail.get("State", {}).get("Pid", 0) or 0)
            except Exception:
                pid = 0

        if pid > 0:
            if not v4_ok:
                v4_ok = bool(
                    run(
                        [
                            "sh",
                            "-lc",
                            f"nsenter -t {pid} -n sh -lc 'curl -4 -s --max-time 5 ip.sb >/dev/null && echo ok'",
                        ]
                    ).strip()
                )
            if not v6_ok:
                v6_ok = bool(
                    run(
                        [
                            "sh",
                            "-lc",
                            f"nsenter -t {pid} -n sh -lc 'curl -6 -s --max-time 5 ip.sb >/dev/null && echo ok'",
                        ]
                    ).strip()
                )
        else:
            if not v4_ok:
                v4_ok = bool(
                    run(_runtime_exec_cmd(runtime, name, "curl -4 -s --max-time 5 ip.sb >/dev/null && echo ok", project)).strip()
                )
            if not v6_ok:
                v6_ok = bool(
                    run(_runtime_exec_cmd(runtime, name, "curl -6 -s --max-time 5 ip.sb >/dev/null && echo ok", project)).strip()
                )

        if v4_ok and v6_ok:
            break
    return v4_ok, v6_ok


def sign(body: bytes, secret: str, ts: int) -> str:
    return hmac.new(secret.encode(), body + str(ts).encode(), hashlib.sha256).hexdigest()


def normalize_server_url(server: str) -> str:
    cleaned = (server or "").strip()
    if not cleaned:
        return "https://127.0.0.1:8080"
    if not urlparse(cleaned).scheme:
        cleaned = f"https://{cleaned}"
    return cleaned


def server_tls_verify() -> bool | str:
    ca_file = os.getenv("SERVER_TLS_CA_FILE", "").strip()
    if not ca_file:
        return True
    if not os.path.isfile(ca_file):
        raise RuntimeError(f"SERVER_TLS_CA_FILE does not exist: {ca_file}")
    return ca_file


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
        verify=server_tls_verify(),
    )
    r.raise_for_status()


def main() -> None:
    global _security_last_sample_ts
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default=os.getenv("SERVER_URL", "https://127.0.0.1:8080"))
    parser.add_argument("--secret", default=os.getenv("SHARED_SECRET", "change-me"))
    parser.add_argument("--interval", type=int, default=int(os.getenv("REPORT_INTERVAL", "300")))
    parser.add_argument("--host-id", default=os.getenv("HOST_ID", socket.gethostname()))
    args = parser.parse_args()

    while True:
        containers = list_containers()
        docker_mode = _docker_monitor_mode()
        monitored_containers = [
            item for item in containers if item.get("runtime") != "docker" or docker_mode == "full"
        ]
        v4, v6 = network_health(monitored_containers) if monitored_containers else (True, True)
        sample_now = float(time.time())
        security_interval = sample_now - _security_last_sample_ts if _security_last_sample_ts > 0 else float(max(60, args.interval))
        _security_last_sample_ts = sample_now
        security_enabled = os.getenv("SECURITY_MONITOR_ENABLED", "true").strip().lower() not in (
            "0",
            "false",
            "no",
            "off",
        )
        collected = []
        for c in containers:
            if c.get("runtime") == "docker" and docker_mode == "notice":
                collected.append(collect_docker_notice(c))
                continue
            try:
                pid_hint = int(c.get("pid", "") or 0)
            except ValueError:
                pid_hint = 0
            container_report = collect_container(
                    c["name"],
                    c.get("id", ""),
                    c.get("runtime_bin", ""),
                    c.get("runtime", ""),
                    c.get("project", ""),
                    pid_hint,
                    c.get("security_risks") if isinstance(c.get("security_risks"), list) else None,
                    c.get("network_exposure") if isinstance(c.get("network_exposure"), list) else None,
                    c.get("image", ""),
                )
            container_security = container_report.get("security")
            if security_enabled and isinstance(container_security, dict):
                container_security["access_log"] = _collect_container_access_log_stats(c, security_interval)
            collected.append(container_report)
        security = collect_security_summary(collected, security_interval)
        payload = {
            "host_id": args.host_id,
            "timestamp": int(time.time()),
            "container_network": {"ipv4_ok": v4, "ipv6_ok": v6},
            "podman_network": {"ipv4_ok": v4, "ipv6_ok": v6},
            "containers": collected,
            "security": security,
        }
        try:
            push(args.server, args.secret, payload)
            print(f"reported {len(containers)} containers and {len(security.get('alerts', []))} security alerts to {args.server}")
        except Exception as e:
            print(f"report failed: {e}")
        time.sleep(max(60, args.interval))


if __name__ == "__main__":
    main()
