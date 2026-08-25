import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

DB_PATH = os.getenv("DB_PATH", "/data/monitor.db")
SHARED_SECRET = os.getenv("SHARED_SECRET", "change-me")
ALERT_DISK_THRESHOLD_PERCENT = int(os.getenv("ALERT_DISK_THRESHOLD_PERCENT", "80"))
ALERT_CPU_THRESHOLD_PERCENT = float(os.getenv("ALERT_CPU_THRESHOLD_PERCENT", "80"))
ALERT_CONN_THRESHOLD = int(os.getenv("ALERT_CONN_THRESHOLD", "500"))
STALE_SECONDS = int(os.getenv("STALE_SECONDS", "900"))
OFFLINE_HIDE_SECONDS = int(os.getenv("OFFLINE_HIDE_SECONDS", str(24 * 3600)))
PURGE_SECONDS = int(os.getenv("PURGE_SECONDS", str(30 * 24 * 3600)))
ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "").strip()
ALERT_WEBHOOK_MIN_SEVERITY = os.getenv("ALERT_WEBHOOK_MIN_SEVERITY", "warning").strip().lower()
TLS_CA_CERT_PATH = os.getenv("TLS_CA_CERT_PATH", "/tls-ca/root.crt")
DASHBOARD_USERNAME = os.getenv("DASHBOARD_USERNAME", "").strip()
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "")
UTC8 = timezone(timedelta(hours=8))


def format_utc8(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=UTC8).strftime("%Y-%m-%d %H:%M:%S")


app = FastAPI(title="Narwhal Container Monitor")

_AGENT_ONLY_PATHS = {
    "/api/v1/report",
    "/api/v1/tls/ca",
    "/api/v1/actions/poll",
    "/api/v1/actions/result",
}


def dashboard_user_from_authorization(authorization: str) -> str | None:
    if not DASHBOARD_USERNAME or not DASHBOARD_PASSWORD or not authorization.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(authorization[6:].strip(), validate=True).decode("utf-8")
        username, password = decoded.split(":", 1)
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None
    user_ok = hmac.compare_digest(username, DASHBOARD_USERNAME)
    password_ok = hmac.compare_digest(password, DASHBOARD_PASSWORD)
    return username if user_ok and password_ok else None


@app.middleware("http")
async def dashboard_basic_auth(request: Request, call_next):
    if request.url.path in _AGENT_ONLY_PATHS:
        return await call_next(request)
    username = dashboard_user_from_authorization(request.headers.get("authorization", ""))
    if username is None:
        return JSONResponse(
            status_code=401,
            content={"detail": "dashboard authentication required"},
            headers={"WWW-Authenticate": 'Basic realm="Narwhal Monitor", charset="UTF-8"'},
        )
    request.state.dashboard_user = username
    return await call_next(request)


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id TEXT NOT NULL,
            container_name TEXT NOT NULL,
            runtime TEXT NOT NULL DEFAULT 'podman',
            project TEXT NOT NULL DEFAULT '',
            cpu_percent REAL NOT NULL,
            mem_bytes INTEGER NOT NULL,
            mem_percent REAL NOT NULL DEFAULT 0,
            net_rx_bps REAL NOT NULL,
            net_tx_bps REAL NOT NULL,
            conn_count INTEGER NOT NULL,
            disk_file TEXT,
            disk_size_bytes INTEGER,
            disk_used_percent REAL,
            podman_network_ok_v4 INTEGER NOT NULL,
            podman_network_ok_v6 INTEGER NOT NULL,
            ts INTEGER NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_reports_host_ts ON reports(host_id, ts);
        CREATE INDEX IF NOT EXISTS idx_reports_host_container_ts ON reports(host_id, container_name, ts);
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL UNIQUE,
            host_id TEXT NOT NULL,
            runtime TEXT NOT NULL DEFAULT '',
            project TEXT NOT NULL DEFAULT '',
            container_name TEXT NOT NULL DEFAULT '',
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            value REAL NOT NULL DEFAULT 0,
            threshold REAL NOT NULL DEFAULT 0,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            occurrence_count INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'active',
            details_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_security_alerts_status_last_seen
            ON security_alerts(status, last_seen);
        CREATE INDEX IF NOT EXISTS idx_security_alerts_host_last_seen
            ON security_alerts(host_id, last_seen);
        CREATE TABLE IF NOT EXISTS host_security (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id TEXT NOT NULL,
            ts INTEGER NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_host_security_host_ts ON host_security(host_id, ts);
        CREATE TABLE IF NOT EXISTS security_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL,
            host_id TEXT NOT NULL,
            runtime TEXT NOT NULL,
            project TEXT NOT NULL DEFAULT '',
            container_name TEXT NOT NULL,
            action_type TEXT NOT NULL,
            params_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'queued',
            requested_by TEXT NOT NULL,
            result_message TEXT NOT NULL DEFAULT '',
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_security_actions_host_status_updated
            ON security_actions(host_id, status, updated_at);
        CREATE INDEX IF NOT EXISTS idx_security_actions_alert_created
            ON security_actions(alert_id, created_at);
        CREATE TABLE IF NOT EXISTS security_alert_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL UNIQUE,
            mode TEXT NOT NULL DEFAULT 'allow_silent',
            requested_by TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS security_alert_decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL,
            fingerprint TEXT NOT NULL,
            decision TEXT NOT NULL,
            requested_by TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_security_alert_decisions_alert_created
            ON security_alert_decisions(alert_id, created_at);
        """
    )
    cols = conn.execute("PRAGMA table_info(reports)").fetchall()
    col_names = {str(c["name"]) for c in cols}
    if "mem_percent" not in col_names:
        conn.execute("ALTER TABLE reports ADD COLUMN mem_percent REAL NOT NULL DEFAULT 0")
    if "runtime" not in col_names:
        conn.execute("ALTER TABLE reports ADD COLUMN runtime TEXT NOT NULL DEFAULT 'podman'")
    if "project" not in col_names:
        conn.execute("ALTER TABLE reports ADD COLUMN project TEXT NOT NULL DEFAULT ''")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_reports_host_runtime_project_container_ts "
        "ON reports(host_id, runtime, project, container_name, ts)"
    )
    conn.commit()
    conn.close()


@app.on_event("startup")
def startup() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    init_db()
    cleanup_old_reports()


def cleanup_old_reports(now_ts: int | None = None) -> int:
    now = now_ts or int(time.time())
    cutoff = now - PURGE_SECONDS
    conn = db()
    cur = conn.execute("DELETE FROM reports WHERE ts < ?", (cutoff,))
    conn.execute("DELETE FROM security_alerts WHERE status='resolved' AND last_seen < ?", (cutoff,))
    conn.execute("DELETE FROM host_security WHERE ts < ?", (cutoff,))
    conn.execute("DELETE FROM security_actions WHERE updated_at < ?", (cutoff,))
    conn.execute("DELETE FROM security_alert_decisions WHERE created_at < ?", (cutoff,))
    conn.commit()
    deleted = int(cur.rowcount or 0)
    conn.close()
    return deleted


def verify_signature(body: bytes, x_timestamp: str, x_signature: str) -> None:
    if not x_timestamp or not x_signature:
        raise HTTPException(status_code=401, detail="missing auth headers")
    try:
        ts = int(x_timestamp)
    except ValueError:
        raise HTTPException(status_code=401, detail="bad timestamp")
    now = int(time.time())
    if abs(now - ts) > 300:
        raise HTTPException(status_code=401, detail="stale timestamp")

    digest = hmac.new(SHARED_SECRET.encode(), body + x_timestamp.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(digest, x_signature):
        raise HTTPException(status_code=401, detail="bad signature")


def signed_json_response(payload: Dict[str, Any], request_timestamp: str, status_code: int = 200) -> Response:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    signature = hmac.new(
        SHARED_SECRET.encode(), body + request_timestamp.encode(), hashlib.sha256
    ).hexdigest()
    return Response(
        content=body,
        status_code=status_code,
        media_type="application/json",
        headers={"X-Narwhal-Response-Signature": signature, "Cache-Control": "no-store"},
    )


@app.get("/api/v1/tls/ca")
def tls_ca(
    x_timestamp: str = Header(default=""),
    x_signature: str = Header(default=""),
) -> Response:
    """Return the public internal-CA certificate with an authenticated response."""
    verify_signature(b"", x_timestamp, x_signature)
    try:
        with open(TLS_CA_CERT_PATH, "rb") as ca_file:
            certificate = ca_file.read(65537)
    except OSError:
        raise HTTPException(status_code=503, detail="internal TLS CA is not available")
    if len(certificate) > 65536 or not certificate.startswith(b"-----BEGIN CERTIFICATE-----"):
        raise HTTPException(status_code=500, detail="invalid internal TLS CA certificate")
    response_signature = hmac.new(
        SHARED_SECRET.encode(), certificate + x_timestamp.encode(), hashlib.sha256
    ).hexdigest()
    return Response(
        content=certificate,
        media_type="application/x-pem-file",
        headers={
            "Cache-Control": "no-store",
            "X-Narwhal-CA-Signature": response_signature,
        },
    )


_SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}


def _alert_fingerprint(host_id: str, alert: Dict[str, Any]) -> str:
    parts = [
        host_id,
        str(alert.get("runtime") or ""),
        str(alert.get("project") or ""),
        str(alert.get("container_name") or ""),
        str(alert.get("type") or "unknown"),
    ]
    if str(alert.get("type") or "") == "unauthorized_panel_pairing":
        domains = alert.get("unapproved_domains")
        domain_values = [
            str(item).strip().lower().rstrip(".")
            for item in domains if isinstance(item, str) and item.strip()
        ] if isinstance(domains, list) else []
        if not domain_values:
            match = re.search(r"未授权面板域名\s*([^；;]+)", str(alert.get("message") or ""))
            domain_values = [
                item.strip().lower().rstrip(".")
                for item in (match.group(1).split(",") if match else []) if item.strip()
            ]
        parts.append(",".join(sorted(set(domain_values))))
    identity = "|".join(parts)
    return hashlib.sha256(identity.encode()).hexdigest()


def process_security_alerts(
    conn: sqlite3.Connection,
    host_id: str,
    ts: int,
    alerts: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    active_fingerprints: List[str] = []
    notifications: List[Dict[str, Any]] = []
    for raw_alert in alerts:
        if not isinstance(raw_alert, dict):
            continue
        alert_type = str(raw_alert.get("type") or "unknown")[:80]
        severity = str(raw_alert.get("severity") or "warning").lower()
        if severity not in _SEVERITY_RANK:
            severity = "warning"
        normalized = {
            "host_id": host_id,
            "runtime": str(raw_alert.get("runtime") or "")[:40],
            "project": str(raw_alert.get("project") or "")[:100],
            "container_name": str(raw_alert.get("container_name") or "")[:200],
            "type": alert_type,
            "severity": severity,
            "title": str(raw_alert.get("title") or alert_type)[:200],
            "message": str(raw_alert.get("message") or "")[:2000],
            "value": float(raw_alert.get("value") or 0),
            "threshold": float(raw_alert.get("threshold") or 0),
        }
        fingerprint_source = dict(normalized)
        fingerprint_source["unapproved_domains"] = raw_alert.get("unapproved_domains")
        fingerprint = _alert_fingerprint(host_id, fingerprint_source)
        active_fingerprints.append(fingerprint)
        existing = conn.execute(
            "SELECT status, severity, occurrence_count FROM security_alerts WHERE fingerprint=?",
            (fingerprint,),
        ).fetchone()
        allow_policy = conn.execute(
            "SELECT 1 FROM security_alert_policies WHERE fingerprint=? AND mode='allow_silent'",
            (fingerprint,),
        ).fetchone() is not None
        next_status = "suppressed" if allow_policy else "active"
        should_notify = existing is None and not allow_policy
        if existing is not None:
            previous_status = str(existing["status"])
            if allow_policy:
                should_notify = False
            elif previous_status == "dismissed":
                next_status = "dismissed"
                should_notify = False
            else:
                should_notify = previous_status == "resolved" or _SEVERITY_RANK[severity] > _SEVERITY_RANK.get(str(existing["severity"]), 0)
            conn.execute(
                """
                UPDATE security_alerts
                SET severity=?, title=?, message=?, value=?, threshold=?, last_seen=?,
                    occurrence_count=occurrence_count+1, status=?, details_json=?
                WHERE fingerprint=?
                """,
                (
                    severity,
                    normalized["title"],
                    normalized["message"],
                    normalized["value"],
                    normalized["threshold"],
                    ts,
                    next_status,
                    json.dumps(raw_alert, ensure_ascii=False),
                    fingerprint,
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO security_alerts(
                    fingerprint, host_id, runtime, project, container_name, alert_type,
                    severity, title, message, value, threshold, first_seen, last_seen,
                    occurrence_count, status, details_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)
                """,
                (
                    fingerprint,
                    host_id,
                    normalized["runtime"],
                    normalized["project"],
                    normalized["container_name"],
                    alert_type,
                    severity,
                    normalized["title"],
                    normalized["message"],
                    normalized["value"],
                    normalized["threshold"],
                    ts,
                    ts,
                    next_status,
                    json.dumps(raw_alert, ensure_ascii=False),
                ),
            )
        if should_notify:
            notifications.append(normalized)

    if active_fingerprints:
        placeholders = ",".join("?" for _ in active_fingerprints)
        conn.execute(
            f"UPDATE security_alerts SET status='resolved', last_seen=? "
            f"WHERE host_id=? AND status IN ('active','dismissed') AND fingerprint NOT IN ({placeholders})",
            (ts, host_id, *active_fingerprints),
        )
    else:
        conn.execute(
            "UPDATE security_alerts SET status='resolved', last_seen=? WHERE host_id=? AND status IN ('active','dismissed')",
            (ts, host_id),
        )
    return notifications


def send_alert_webhook(alert: Dict[str, Any]) -> None:
    if not ALERT_WEBHOOK_URL:
        return
    severity = str(alert.get("severity") or "warning")
    if _SEVERITY_RANK.get(severity, 0) < _SEVERITY_RANK.get(ALERT_WEBHOOK_MIN_SEVERITY, 1):
        return
    payload = json.dumps({"event": "narwhal.security_alert", "alert": alert}, ensure_ascii=False).encode()
    request = urllib.request.Request(
        ALERT_WEBHOOK_URL,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "Narwhal-Container-Monitor/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            response.read(1)
    except Exception as exc:
        print(f"alert webhook failed: {exc}")


@app.post("/api/v1/report")
async def report(
    request: Request,
    x_timestamp: str = Header(default=""),
    x_signature: str = Header(default=""),
) -> Dict[str, Any]:
    cleanup_old_reports()
    body = await request.body()
    verify_signature(body, x_timestamp, x_signature)
    data = json.loads(body)

    host_id = data.get("host_id", "unknown")
    ts = int(data.get("timestamp", time.time()))
    network_status = data.get("container_network") or data.get("podman_network") or {}
    podman_v4 = 1 if network_status.get("ipv4_ok") else 0
    podman_v6 = 1 if network_status.get("ipv6_ok") else 0

    containers: List[Dict[str, Any]] = data.get("containers", [])
    conn = db()
    for c in containers:
        conn.execute(
            """
            INSERT INTO reports(
                host_id, container_name, runtime, project, cpu_percent, mem_bytes, mem_percent, net_rx_bps, net_tx_bps,
                conn_count, disk_file, disk_size_bytes, disk_used_percent,
                podman_network_ok_v4, podman_network_ok_v6, ts, payload_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                host_id,
                c.get("name", "unknown"),
                c.get("runtime", "podman"),
                c.get("project", ""),
                float(c.get("cpu_percent", 0)),
                int(c.get("mem_bytes", 0)),
                float(c.get("mem_percent", 0)),
                float(c.get("net_rx_bps", 0)),
                float(c.get("net_tx_bps", 0)),
                int(c.get("conn_count", 0)),
                c.get("disk", {}).get("file"),
                c.get("disk", {}).get("size_bytes"),
                c.get("disk", {}).get("used_percent"),
                podman_v4,
                podman_v6,
                ts,
                json.dumps(c, ensure_ascii=False),
            ),
        )
    notifications: List[Dict[str, Any]] = []
    security = data.get("security")
    if isinstance(security, dict):
        security_alerts = security.get("alerts") if isinstance(security.get("alerts"), list) else []
        notifications = process_security_alerts(conn, host_id, ts, security_alerts)
        conn.execute(
            "INSERT INTO host_security(host_id, ts, payload_json) VALUES(?,?,?)",
            (host_id, ts, json.dumps(security, ensure_ascii=False)),
        )
    conn.commit()
    conn.close()
    for alert in notifications:
        send_alert_webhook(alert)
    return {"ok": True, "records": len(containers), "new_alerts": len(notifications)}


@app.get("/api/v1/latest")
def latest(include_stale: bool = False) -> JSONResponse:
    cleanup_old_reports()
    conn = db()
    rows = conn.execute(
        """
        SELECT r.* FROM reports r
        JOIN (
            SELECT host_id, runtime, project, container_name, MAX(ts) AS max_ts
            FROM reports
            GROUP BY host_id, runtime, project, container_name
        ) m ON r.host_id=m.host_id AND r.runtime=m.runtime AND r.project=m.project
            AND r.container_name=m.container_name AND r.ts=m.max_ts
        ORDER BY r.host_id, r.runtime, r.project, r.container_name
        """
    ).fetchall()

    host_rows = conn.execute(
        """
        SELECT r.host_id, r.payload_json, r.ts
        FROM reports r
        JOIN (
            SELECT host_id, MAX(ts) AS max_ts
            FROM reports
            GROUP BY host_id
        ) m ON r.host_id=m.host_id AND r.ts=m.max_ts
        """
    ).fetchall()

    conn.close()

    host_disk_map: Dict[str, Dict[str, Any]] = {}
    for h in host_rows:
        payload = json.loads(h["payload_json"]) if h["payload_json"] else {}
        host_disk_map[h["host_id"]] = payload.get("disk", {})

    now = int(time.time())
    out = []
    for r in rows:
        payload = json.loads(r["payload_json"]) if r["payload_json"] else {}
        disk = payload.get("disk", {})
        host_disk = host_disk_map.get(r["host_id"], {})
        alert_disk = (r["disk_used_percent"] or 0) >= ALERT_DISK_THRESHOLD_PERCENT
        alert_cpu = float(r["cpu_percent"] or 0) >= ALERT_CPU_THRESHOLD_PERCENT
        alert_conn = int(r["conn_count"] or 0) >= ALERT_CONN_THRESHOLD
        stale_seconds = max(0, now - r["ts"])
        stale = stale_seconds > STALE_SECONDS
        hidden_offline = stale_seconds > OFFLINE_HIDE_SECONDS
        if hidden_offline and not include_stale:
            continue
        container_disk = payload.get("container_disk", {})
        top_cpu_process = payload.get("top_cpu_process", {})
        offline_hours = stale_seconds // 3600
        out.append({
            "host_id": r["host_id"],
            "container_id": payload.get("id", ""),
            "container_name": r["container_name"],
            "runtime": r["runtime"],
            "project": r["project"],
            "monitor_mode": str(payload.get("monitor_mode") or "full"),
            "cpu_percent": r["cpu_percent"],
            "mem_bytes": r["mem_bytes"],
            "mem_percent": float(r["mem_percent"] or 0),
            "net_rx_bps": r["net_rx_bps"],
            "net_tx_bps": r["net_tx_bps"],
            "conn_count": int(r["conn_count"]),
            "tcp_country_stats": payload.get("tcp_country_stats", []),
            "udp_country_stats": payload.get("udp_country_stats", []),
            "security": payload.get("security", {}),
            "disk_file": r["disk_file"],
            "disk_used_percent": r["disk_used_percent"],
            "disk_root_device": host_disk.get("root_device") or disk.get("root_device", ""),
            "disk_root_total_bytes": host_disk.get("root_total_bytes") or disk.get("root_total_bytes", 0),
            "disk_root_avail_bytes": host_disk.get("root_avail_bytes") or disk.get("root_avail_bytes", 0),
            "disk_data_total_bytes": host_disk.get("data_total_bytes") or disk.get("data_total_bytes", 0),
            "disk_data_avail_bytes": host_disk.get("data_avail_bytes") or disk.get("data_avail_bytes", 0),
            "disk_data_requested_path": host_disk.get("data_requested_path") or disk.get("data_requested_path", "/"),
            "disk_data_mountpoint": host_disk.get("data_mountpoint") or disk.get("data_mountpoint", "/"),
            "container_disk_rw_bytes": container_disk.get("rw_bytes", 0),
            "container_disk_rootfs_bytes": container_disk.get("rootfs_bytes", 0),
            "container_fs_root_total_bytes": container_disk.get("fs", {}).get("root", {}).get("total_bytes", 0),
            "container_fs_root_avail_bytes": container_disk.get("fs", {}).get("root", {}).get("avail_bytes", 0),
            "container_fs_data_total_bytes": container_disk.get("fs", {}).get("data", {}).get("total_bytes", 0),
            "container_fs_data_avail_bytes": container_disk.get("fs", {}).get("data", {}).get("avail_bytes", 0),
            "top_cpu_process_pid": int(top_cpu_process.get("pid") or 0),
            "top_cpu_process_cpu_percent": float(top_cpu_process.get("cpu_percent") or 0),
            "top_cpu_process_command": str(top_cpu_process.get("command") or ""),
            "podman_network_ok_v4": bool(r["podman_network_ok_v4"]),
            "podman_network_ok_v6": bool(r["podman_network_ok_v6"]),
            "container_network_ok_v4": bool(r["podman_network_ok_v4"]),
            "container_network_ok_v6": bool(r["podman_network_ok_v6"]),
            "timestamp": r["ts"],
            "timestamp_iso": datetime.fromtimestamp(r["ts"], tz=timezone.utc).isoformat(),
            "timestamp_iso_utc8": format_utc8(r["ts"]),
            "offline_seconds": stale_seconds,
            "offline_hours": offline_hours,
            "alerts": {
                "disk": alert_disk,
                "cpu": alert_cpu,
                "conn": alert_conn,
                "stale": stale,
                "hidden_offline": hidden_offline,
                "network": (not r["podman_network_ok_v4"]) or (not r["podman_network_ok_v6"]),
            },
        })
    return JSONResponse(content={"items": out})


@app.get("/api/v1/history")
def history(host_id: str, container_name: str, runtime: str = "", project: str = "", minutes: int = 720) -> JSONResponse:
    minutes = max(5, min(minutes, 1440))
    start_ts = int(time.time()) - (minutes * 60)
    conn = db()
    if runtime:
        rows = conn.execute(
            """
            SELECT ts, cpu_percent, mem_percent, net_rx_bps, net_tx_bps, conn_count
            FROM reports
            WHERE host_id=? AND runtime=? AND project=? AND container_name=? AND ts>=?
            ORDER BY ts ASC
            """,
            (host_id, runtime, project, container_name, start_ts),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT ts, cpu_percent, mem_percent, net_rx_bps, net_tx_bps, conn_count
            FROM reports
            WHERE host_id=? AND container_name=? AND ts>=?
            ORDER BY ts ASC
            """,
            (host_id, container_name, start_ts),
        ).fetchall()
    conn.close()
    return JSONResponse(
        content={
            "items": [
                {
                    "timestamp": r["ts"],
                    "timestamp_iso_utc8": format_utc8(r["ts"]),
                    "cpu_percent": r["cpu_percent"],
                    "mem_percent": r["mem_percent"],
                    "net_rx_bps": r["net_rx_bps"],
                    "net_tx_bps": r["net_tx_bps"],
                    "conn_count": r["conn_count"],
                }
                for r in rows
            ]
        }
    )


def _action_item(row: sqlite3.Row) -> Dict[str, Any]:
    try:
        params = json.loads(row["params_json"] or "{}")
    except (TypeError, ValueError):
        params = {}
    return {
        "id": int(row["id"]),
        "alert_id": int(row["alert_id"]),
        "host_id": row["host_id"],
        "runtime": row["runtime"],
        "project": row["project"],
        "container_name": row["container_name"],
        "action_type": row["action_type"],
        "params": params,
        "status": row["status"],
        "requested_by": row["requested_by"],
        "result_message": row["result_message"],
        "attempts": int(row["attempts"]),
        "created_at": int(row["created_at"]),
        "created_at_utc8": format_utc8(int(row["created_at"])),
        "updated_at": int(row["updated_at"]),
        "updated_at_utc8": format_utc8(int(row["updated_at"])),
    }


def _remediation_changed(message: str) -> bool:
    counts = {
        key: int(value)
        for key, value in re.findall(
            r"\b(killed_processes|removed_services|removed_configs|cleanup_errors)=(\d+)\b",
            message,
        )
    }
    return counts.get("cleanup_errors", 0) == 0 and sum(
        counts.get(key, 0)
        for key in ("killed_processes", "removed_services", "removed_configs")
    ) > 0


def _alert_details(raw: str) -> Dict[str, Any]:
    try:
        value = json.loads(raw or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def _alert_action_evidence(alert: sqlite3.Row) -> Dict[str, Any]:
    """Return structured evidence, including alerts reported by older agents."""
    details = _alert_details(alert["details_json"])
    message = str(alert["message"] or "")

    def clean(items: Any, *, domains: bool = False) -> List[str]:
        if not isinstance(items, list):
            return []
        values = []
        for item in items:
            if not isinstance(item, str) or not item.strip():
                continue
            value = item.strip()
            if domains:
                value = value.lower().rstrip(".")
            values.append(value)
        return sorted(set(values))

    domains = clean(details.get("unapproved_domains"), domains=True)
    process_patterns = clean(details.get("process_patterns"))
    config_files = clean(details.get("config_files"))
    process_pids = sorted(
        {
            int(item)
            for item in details.get("process_pids", [])
            if isinstance(item, int) and 1 < item <= 4194304
        }
    ) if isinstance(details.get("process_pids"), list) else []
    if not domains:
        match = re.search(r"未授权面板域名\s*([^；;]+)", message)
        domains = clean(match.group(1).split(",") if match else [], domains=True)
    if not process_patterns:
        match = re.search(r"节点程序特征\s*([^；;]+)", message)
        process_patterns = clean(match.group(1).split(",") if match else [])
    if not config_files:
        match = re.search(r"配置文件\s*([^；;]+)", message)
        config_files = clean(match.group(1).split(",") if match else [])
    details["unapproved_domains"] = domains
    details["process_patterns"] = process_patterns
    details["process_pids"] = process_pids
    details["config_files"] = config_files
    return details


def _queue_security_action_row(
    conn: sqlite3.Connection,
    alert: sqlite3.Row,
    action_type: str,
    params: Dict[str, Any],
    requested_by: str,
) -> tuple[sqlite3.Row, bool]:
    existing = conn.execute(
        """
        SELECT * FROM security_actions
        WHERE alert_id=? AND action_type=? AND status IN ('queued','dispatched')
        ORDER BY id DESC LIMIT 1
        """,
        (alert["id"], action_type),
    ).fetchone()
    if existing is not None:
        return existing, False
    now = int(time.time())
    cur = conn.execute(
        """
        INSERT INTO security_actions(
            alert_id, host_id, runtime, project, container_name, action_type, params_json,
            status, requested_by, created_at, updated_at
        ) VALUES(?,?,?,?,?,?,?,'queued',?,?,?)
        """,
        (
            alert["id"], alert["host_id"], alert["runtime"], alert["project"],
            alert["container_name"], action_type, json.dumps(params, ensure_ascii=False),
            requested_by[:100], now, now,
        ),
    )
    row = conn.execute("SELECT * FROM security_actions WHERE id=?", (cur.lastrowid,)).fetchone()
    return row, True


@app.post("/api/v1/security/alerts/{alert_id}/actions")
async def queue_security_action(alert_id: int, request: Request) -> JSONResponse:
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")
    requested_action = str(payload.get("action") or "").strip().lower()
    action_type = {"remediate": "remediate_panel_pairing", "allow": "allow_panel_domains"}.get(
        requested_action
    )
    if not action_type:
        raise HTTPException(status_code=400, detail="action must be remediate or allow")

    conn = db()
    conn.execute("BEGIN IMMEDIATE")
    alert = conn.execute("SELECT * FROM security_alerts WHERE id=?", (alert_id,)).fetchone()
    if alert is None:
        conn.close()
        raise HTTPException(status_code=404, detail="alert not found")
    if alert["status"] != "active":
        conn.close()
        raise HTTPException(status_code=409, detail="alert is no longer active")
    if alert["alert_type"] != "unauthorized_panel_pairing":
        conn.close()
        raise HTTPException(status_code=400, detail="this action only supports panel-pairing alerts")
    if alert["runtime"] not in ("podman", "incus"):
        conn.close()
        raise HTTPException(status_code=400, detail="Docker and unknown runtimes are notice-only")
    if not alert["container_name"]:
        conn.close()
        raise HTTPException(status_code=400, detail="alert has no container target")

    details = _alert_action_evidence(alert)
    unapproved_domains = [
        str(item).strip().lower().rstrip(".")
        for item in details.get("unapproved_domains", [])
        if isinstance(item, str) and item.strip()
    ]
    process_patterns = [
        str(item).strip().lower()
        for item in details.get("process_patterns", [])
        if isinstance(item, str) and item.strip()
    ]
    config_files = [
        str(item).strip()
        for item in details.get("config_files", [])
        if isinstance(item, str) and item.strip()
    ]
    process_pids = details.get("process_pids") or []
    if action_type == "allow_panel_domains":
        if not unapproved_domains:
            conn.close()
            raise HTTPException(status_code=400, detail="alert has no exact domains to allow")
        params = {"domains": sorted(set(unapproved_domains))}
    else:
        if not process_patterns and not config_files:
            conn.close()
            raise HTTPException(status_code=400, detail="alert has no safe remediation evidence")
        params = {
            "domains": sorted(set(unapproved_domains)),
            "process_patterns": sorted(set(process_patterns)),
            "process_pids": process_pids,
            "config_files": sorted(set(config_files)),
        }

    requested_by = str(getattr(request.state, "dashboard_user", DASHBOARD_USERNAME or "dashboard"))[:100]
    row, queued = _queue_security_action_row(conn, alert, action_type, params, requested_by)
    conn.commit()
    conn.close()
    return JSONResponse(
        status_code=202 if queued else 200,
        content={"ok": True, "queued": queued, "action": _action_item(row)},
    )


@app.post("/api/v1/security/alerts/{alert_id}/disposition")
async def set_security_alert_disposition(alert_id: int, request: Request) -> JSONResponse:
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")
    decision = str(payload.get("decision") or "").strip().lower()
    if decision not in ("deny", "allow_silent", "dismiss_once"):
        raise HTTPException(
            status_code=400,
            detail="decision must be deny, allow_silent or dismiss_once",
        )

    conn = db()
    conn.execute("BEGIN IMMEDIATE")
    alert = conn.execute("SELECT * FROM security_alerts WHERE id=?", (alert_id,)).fetchone()
    if alert is None:
        conn.close()
        raise HTTPException(status_code=404, detail="alert not found")
    if alert["status"] != "active":
        conn.close()
        raise HTTPException(status_code=409, detail="alert is no longer active")

    requested_by = str(
        getattr(request.state, "dashboard_user", DASHBOARD_USERNAME or "dashboard")
    )[:100]
    now = int(time.time())
    action = None
    queued = False
    if decision == "deny":
        if alert["alert_type"] != "unauthorized_panel_pairing":
            conn.close()
            raise HTTPException(status_code=400, detail="deny currently supports panel-pairing alerts")
        if alert["runtime"] not in ("podman", "incus"):
            conn.close()
            raise HTTPException(status_code=400, detail="Docker is notice-only and cannot be denied")
        if not alert["container_name"]:
            conn.close()
            raise HTTPException(status_code=400, detail="alert has no container target")
        details = _alert_action_evidence(alert)
        process_patterns = details.get("process_patterns") or []
        process_pids = details.get("process_pids") or []
        config_files = details.get("config_files") or []
        if not process_patterns and not config_files:
            conn.close()
            raise HTTPException(status_code=400, detail="alert has no safe remediation evidence")
        params = {
            "domains": details.get("unapproved_domains") or [],
            "process_patterns": process_patterns,
            "process_pids": process_pids,
            "config_files": config_files,
        }
        action, queued = _queue_security_action_row(
            conn, alert, "remediate_panel_pairing", params, requested_by
        )
    elif decision == "allow_silent":
        conn.execute(
            """
            INSERT INTO security_alert_policies(
                fingerprint, mode, requested_by, created_at, updated_at
            ) VALUES(?,'allow_silent',?,?,?)
            ON CONFLICT(fingerprint) DO UPDATE SET
                mode='allow_silent', requested_by=excluded.requested_by,
                updated_at=excluded.updated_at
            """,
            (alert["fingerprint"], requested_by, now, now),
        )
        conn.execute("UPDATE security_alerts SET status='suppressed' WHERE id=?", (alert_id,))
        if alert["alert_type"] == "unauthorized_panel_pairing" and alert["runtime"] in ("podman", "incus"):
            details = _alert_action_evidence(alert)
            domains = details.get("unapproved_domains") or []
            if domains:
                action, queued = _queue_security_action_row(
                    conn, alert, "allow_panel_domains", {"domains": domains}, requested_by
                )
    else:
        conn.execute("UPDATE security_alerts SET status='dismissed' WHERE id=?", (alert_id,))

    conn.execute(
        """
        INSERT INTO security_alert_decisions(
            alert_id, fingerprint, decision, requested_by, created_at
        ) VALUES(?,?,?,?,?)
        """,
        (alert_id, alert["fingerprint"], decision, requested_by, now),
    )
    conn.commit()
    conn.close()
    return JSONResponse(
        status_code=202 if action is not None and queued else 200,
        content={
            "ok": True,
            "decision": decision,
            "queued": queued,
            "action": _action_item(action) if action is not None else None,
        },
    )


@app.post("/api/v1/actions/poll")
async def poll_security_actions(
    request: Request,
    x_timestamp: str = Header(default=""),
    x_signature: str = Header(default=""),
) -> Response:
    body = await request.body()
    verify_signature(body, x_timestamp, x_signature)
    try:
        payload = json.loads(body)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="invalid JSON body")
    host_id = str(payload.get("host_id") or "")[:200]
    if not host_id:
        raise HTTPException(status_code=400, detail="host_id is required")
    now = int(time.time())
    conn = db()
    conn.execute("BEGIN IMMEDIATE")
    conn.execute(
        """
        UPDATE security_actions
        SET status='failed', result_message='agent did not confirm action after 3 attempts', updated_at=?
        WHERE host_id=? AND status='dispatched' AND attempts>=3 AND updated_at < ?
        """,
        (now, host_id, now - 120),
    )
    rows = conn.execute(
        """
        SELECT * FROM security_actions
        WHERE host_id=? AND attempts < 3
          AND (status='queued' OR (status='dispatched' AND updated_at < ?))
        ORDER BY id LIMIT 10
        """,
        (host_id, now - 120),
    ).fetchall()
    actions = []
    for row in rows:
        conn.execute(
            "UPDATE security_actions SET status='dispatched', attempts=attempts+1, updated_at=? WHERE id=?",
            (now, row["id"]),
        )
        action = _action_item(row)
        action["status"] = "dispatched"
        action["attempts"] += 1
        actions.append(action)
    conn.commit()
    conn.close()
    return signed_json_response({"ok": True, "actions": actions}, x_timestamp)


@app.post("/api/v1/actions/result")
async def security_action_result(
    request: Request,
    x_timestamp: str = Header(default=""),
    x_signature: str = Header(default=""),
) -> Response:
    body = await request.body()
    verify_signature(body, x_timestamp, x_signature)
    try:
        payload = json.loads(body)
        action_id = int(payload.get("action_id"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="invalid action result")
    host_id = str(payload.get("host_id") or "")[:200]
    status = str(payload.get("status") or "").lower()
    if status not in ("succeeded", "failed"):
        raise HTTPException(status_code=400, detail="status must be succeeded or failed")
    message = str(payload.get("message") or "")[:2000]
    now = int(time.time())
    conn = db()
    row = conn.execute(
        "SELECT host_id, status, action_type, alert_id FROM security_actions WHERE id=?",
        (action_id,),
    ).fetchone()
    if row is None or row["host_id"] != host_id:
        conn.close()
        raise HTTPException(status_code=404, detail="action not found for host")
    if status == "succeeded" and row["action_type"] == "remediate_panel_pairing" and not _remediation_changed(message):
        status = "failed"
        message = f"no matching process, service or config was removed; {message}"[:2000]
    if row["status"] not in ("succeeded", "failed"):
        conn.execute(
            "UPDATE security_actions SET status=?, result_message=?, updated_at=? WHERE id=?",
            (status, message, now, action_id),
        )
        if status == "succeeded" and row["action_type"] == "remediate_panel_pairing":
            conn.execute(
                "UPDATE security_alerts SET status='remediated' WHERE id=? AND status='active'",
                (row["alert_id"],),
            )
        conn.commit()
    conn.close()
    return signed_json_response({"ok": True, "action_id": action_id}, x_timestamp)


@app.get("/api/v1/security/actions")
def security_actions(limit: int = 200) -> JSONResponse:
    limit = max(1, min(limit, 1000))
    conn = db()
    rows = conn.execute("SELECT * FROM security_actions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return JSONResponse(content={"items": [_action_item(row) for row in rows]})


@app.get("/api/v1/security/alerts")
def security_alerts(active_only: bool = True, limit: int = 200) -> JSONResponse:
    limit = max(1, min(limit, 1000))
    conn = db()
    if active_only:
        rows = conn.execute(
            "SELECT * FROM security_alerts WHERE status='active' ORDER BY last_seen DESC LIMIT ?",
            (limit,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM security_alerts ORDER BY last_seen DESC LIMIT ?",
            (limit,),
        ).fetchall()
    items = []
    for row in rows:
        latest_action = conn.execute(
            "SELECT * FROM security_actions WHERE alert_id=? ORDER BY id DESC LIMIT 1", (row["id"],)
        ).fetchone()
        items.append(
            {
                "id": int(row["id"]),
                "host_id": row["host_id"],
                "runtime": row["runtime"],
                "project": row["project"],
                "container_name": row["container_name"],
                "type": row["alert_type"],
                "severity": row["severity"],
                "title": row["title"],
                "message": row["message"],
                "value": float(row["value"] or 0),
                "threshold": float(row["threshold"] or 0),
                "first_seen": int(row["first_seen"]),
                "first_seen_utc8": format_utc8(int(row["first_seen"])),
                "last_seen": int(row["last_seen"]),
                "last_seen_utc8": format_utc8(int(row["last_seen"])),
                "occurrence_count": int(row["occurrence_count"]),
                "status": row["status"],
                "details": _alert_action_evidence(row),
                "latest_action": _action_item(latest_action) if latest_action is not None else None,
            }
        )
    conn.close()
    active_count = sum(1 for item in items if item["status"] == "active") if not active_only else len(items)
    return JSONResponse(content={"items": items, "active_count": active_count})


@app.get("/api/v1/security/status")
def security_status() -> JSONResponse:
    conn = db()
    rows = conn.execute(
        """
        SELECT h.host_id, h.ts, h.payload_json
        FROM host_security h
        JOIN (
            SELECT host_id, MAX(id) AS max_id
            FROM host_security
            GROUP BY host_id
        ) latest ON h.id=latest.max_id
        ORDER BY h.host_id
        """
    ).fetchall()
    conn.close()
    items = []
    for row in rows:
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except Exception:
            payload = {}
        items.append(
            {
                "host_id": row["host_id"],
                "timestamp": int(row["ts"]),
                "timestamp_utc8": format_utc8(int(row["ts"])),
                "enabled": bool(payload.get("enabled")),
                "total_rx_bps": float(payload.get("total_rx_bps") or 0),
                "total_tx_bps": float(payload.get("total_tx_bps") or 0),
                "total_rx_pps": float(payload.get("total_rx_pps") or 0),
                "total_tx_pps": float(payload.get("total_tx_pps") or 0),
                "syn_recv_count": int(payload.get("syn_recv_count") or 0),
                "access_log": payload.get("access_log") if isinstance(payload.get("access_log"), dict) else {},
                "active_alerts_in_sample": len(payload.get("alerts") or []),
            }
        )
    return JSONResponse(content={"items": items})


@app.get("/api/v1/stats")
def stats(minutes: int = 720) -> JSONResponse:
    minutes = max(5, min(minutes, 10080))
    start_ts = int(time.time()) - (minutes * 60)
    conn = db()
    rows = conn.execute(
        """
        SELECT host_id, runtime, project, container_name, ts, cpu_percent, mem_bytes, mem_percent, net_rx_bps, net_tx_bps, conn_count
        FROM reports
        WHERE ts>=?
        ORDER BY host_id, runtime, project, container_name, ts ASC
        """,
        (start_ts,),
    ).fetchall()
    conn.close()

    grouped: Dict[tuple[str, str, str, str], List[sqlite3.Row]] = {}
    for row in rows:
        key = (str(row["host_id"]), str(row["runtime"]), str(row["project"]), str(row["container_name"]))
        grouped.setdefault(key, []).append(row)

    items: List[Dict[str, Any]] = []
    host_totals: Dict[str, Dict[str, float]] = {}
    total_samples = 0
    for (host_id, runtime, project, container_name), series in grouped.items():
        if not series:
            continue
        cpu_values = [float(x["cpu_percent"] or 0) for x in series]
        mem_values = [int(x["mem_bytes"] or 0) for x in series]
        mem_percent_values = [float(x["mem_percent"] or 0) for x in series]
        conn_values = [int(x["conn_count"] or 0) for x in series]
        rx_values = [float(x["net_rx_bps"] or 0) for x in series]
        tx_values = [float(x["net_tx_bps"] or 0) for x in series]
        timestamps = [int(x["ts"]) for x in series]
        intervals = [max(1, timestamps[i] - timestamps[i - 1]) for i in range(1, len(timestamps))]
        estimated_interval = round(sum(intervals) / len(intervals), 2) if intervals else 0

        rx_bytes = 0.0
        tx_bytes = 0.0
        for i, row in enumerate(series):
            step = 0
            if i > 0:
                step = max(1, int(row["ts"]) - int(series[i - 1]["ts"]))
            elif estimated_interval > 0:
                step = max(1, int(round(estimated_interval)))
            rx_bytes += float(row["net_rx_bps"] or 0) * step
            tx_bytes += float(row["net_tx_bps"] or 0) * step

        latest = series[-1]
        item = {
            "host_id": host_id,
            "runtime": runtime,
            "project": project,
            "container_name": container_name,
            "samples": len(series),
            "estimated_interval_seconds": estimated_interval,
            "latest": {
                "timestamp": int(latest["ts"]),
                "cpu_percent": float(latest["cpu_percent"] or 0),
                "mem_bytes": int(latest["mem_bytes"] or 0),
                "mem_percent": float(latest["mem_percent"] or 0),
                "net_rx_bps": float(latest["net_rx_bps"] or 0),
                "net_tx_bps": float(latest["net_tx_bps"] or 0),
                "conn_count": int(latest["conn_count"] or 0),
            },
            "avg": {
                "cpu_percent": round(sum(cpu_values) / len(cpu_values), 4),
                "mem_bytes": int(sum(mem_values) / len(mem_values)),
                "mem_percent": round(sum(mem_percent_values) / len(mem_percent_values), 4),
                "net_rx_bps": round(sum(rx_values) / len(rx_values), 4),
                "net_tx_bps": round(sum(tx_values) / len(tx_values), 4),
                "conn_count": round(sum(conn_values) / len(conn_values), 2),
            },
            "max": {
                "cpu_percent": max(cpu_values),
                "mem_bytes": max(mem_values),
                "mem_percent": max(mem_percent_values),
                "net_rx_bps": max(rx_values),
                "net_tx_bps": max(tx_values),
                "conn_count": max(conn_values),
            },
            "traffic_bytes": {
                "rx": int(rx_bytes),
                "tx": int(tx_bytes),
                "total": int(rx_bytes + tx_bytes),
            },
        }
        items.append(item)

        host_total = host_totals.setdefault(host_id, {"rx": 0.0, "tx": 0.0, "samples": 0.0})
        host_total["rx"] += rx_bytes
        host_total["tx"] += tx_bytes
        host_total["samples"] += len(series)
        total_samples += len(series)

    rank_cpu = sorted(items, key=lambda x: x["avg"]["cpu_percent"], reverse=True)[:10]
    rank_conn = sorted(items, key=lambda x: x["avg"]["conn_count"], reverse=True)[:10]
    rank_traffic = sorted(items, key=lambda x: x["traffic_bytes"]["total"], reverse=True)[:10]
    host_summary = [
        {
            "host_id": host,
            "traffic_rx_bytes": int(vals["rx"]),
            "traffic_tx_bytes": int(vals["tx"]),
            "traffic_total_bytes": int(vals["rx"] + vals["tx"]),
            "samples": int(vals["samples"]),
        }
        for host, vals in host_totals.items()
    ]
    host_summary.sort(key=lambda x: x["traffic_total_bytes"], reverse=True)
    return JSONResponse(
        content={
            "window_minutes": minutes,
            "container_count": len(items),
            "samples": total_samples,
            "containers": items,
            "ranks": {
                "avg_cpu_top10": rank_cpu,
                "avg_conn_top10": rank_conn,
                "traffic_top10": rank_traffic,
            },
            "hosts": host_summary,
            "recommendation": {
                "suggested_interval_seconds": 60,
                "reason": "当前容器 CPU 使用率整体低，建议从 300 秒降低到 60 秒，兼顾实时性与开销。",
            },
        }
    )


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return """
<!doctype html>
<html><head><meta charset='utf-8'><title>Narwhal Container Monitor</title>
<style>
body{font-family:sans-serif;margin:1rem;background:#0f1a2e;color:#dbe7ff}
table{border-collapse:collapse;width:100%;background:#13213b;color:#dbe7ff}
th,td{border:1px solid #233b61;padding:8px;vertical-align:middle;text-align:center}
th{background:#1a2c4e}
.bad{color:#b00020;font-weight:bold}
.ok{color:#0a8f08}
.severity-critical{color:#ff5f6d;font-weight:bold}
.severity-warning{color:#ffbf4b;font-weight:bold}
.btn{border:1px solid #4b6fa8;padding:4px 8px;border-radius:6px;background:#1a2c4e;color:#dbe7ff;cursor:pointer}
.btn-danger{background:#7c2330;border-color:#d94b61;margin-right:6px}
.btn-allow{background:#185d4a;border-color:#36a77f;margin-right:6px}
.btn-dismiss{background:#34445e;border-color:#6e85a8}
.btn:disabled{opacity:.55;cursor:not-allowed}
.action-status{font-size:12px;margin-top:5px;color:#a9bddc;max-width:260px}
#modal{position:fixed;inset:0;background:rgba(0,0,0,.35);display:none;align-items:center;justify-content:center}
#card{background:#0d1730;border-radius:12px;padding:16px;width:min(1380px,96vw)}
.legend{display:flex;gap:14px;align-items:center;margin:8px 0 4px 0;font-size:14px}
.legend-item{display:flex;align-items:center;gap:6px}
.dot{width:10px;height:10px;border-radius:50%}
.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.panel{background:#13213b;border:1px solid #233b61;border-radius:10px;padding:10px}
.panel h4{margin:0 0 6px 0}
svg{width:100%;height:220px;border-top:1px solid #28436c}
#traffic{height:280px}
.snapshot-grid{display:grid;grid-template-columns:repeat(3,minmax(220px,1fr));gap:10px;margin-top:12px}
.snapshot-list{margin:6px 0 0 18px;padding:0;text-align:left;max-height:180px;overflow:auto}
</style>
</head><body>
<h2>Narwhal Container Monitor Dashboard</h2>
<p>每 15 秒自动刷新。CPU/内存使用率/连接数/网速展示采集到的原始上报值，服务端不再做 5 分钟平均。红色表示预警（CPU ≥ {ALERT_CPU_THRESHOLD_PERCENT:.2f}% 或连接数 ≥ {ALERT_CONN_THRESHOLD}）。离线容器默认保留 1 天并显示离线时长（按小时刷新），超过 1 天隐藏，超过 30 天自动清理。<a href='/stats' style='color:#8cc7ff'>查看统计页</a></p>
<h3>安全告警（活动：<span id='active-alert-count'>0</span>）</h3>
<table id='security-alerts'><thead><tr><th>级别</th><th>主机</th><th>运行时/项目</th><th>容器</th><th>类型</th><th>说明</th><th>最近出现</th><th>次数</th><th>操作</th></tr></thead><tbody></tbody></table>
<h3>主机安全遥测</h3>
<table id='security-status'><thead><tr><th>主机</th><th>RX Mbps</th><th>RX pps</th><th>SYN_RECV</th><th>HTTP RPS</th><th>最高单IP RPS</th><th>访问日志</th><th>采样时间</th></tr></thead><tbody></tbody></table>
<h3>容器状态</h3>
  <table id='t'><thead><tr><th>主机</th><th>运行时</th><th>容器ID</th><th>容器名</th><th>CPU%</th><th>内存%</th><th>连接数</th><th>进程数</th><th>RX pps</th><th>SYN_RECV</th><th>出站IP</th><th>监听端口</th><th>NAT/代理映射</th><th>TCP建连/s</th><th>TCP失败/s</th><th>可疑进程</th><th>配置风险</th><th>面板对接</th><th>国家Top3(TCP/UDP)</th><th>RX Mbps</th><th>TX Mbps</th><th>容器根盘(/ 总量/可用)</th><th>宿主机主盘(挂载点/总量/可用)</th><th>IPv4</th><th>IPv6</th><th>上报时间(UTC+8)</th><th>详情</th></tr></thead><tbody></tbody></table>
<div id='modal'><div id='card'>
  <h3 id='detail-title'></h3>
  <div class='detail-grid'>
    <div class='panel'>
      <h4>负载详情</h4>
      <div class='legend'>
        <span class='legend-item'><span class='dot' style='background:#4a90e2'></span>CPU%</span>
        <span class='legend-item'><span class='dot' style='background:#16a085'></span>内存%</span>
        <span class='legend-item'><span class='dot' style='background:#9b59b6'></span>连接数</span>
        <span class='legend-item'><span class='dot' style='background:#f39c12'></span>总网速 Mbps</span>
      </div>
      <svg id='chart' viewBox='0 0 900 220' preserveAspectRatio='none'></svg>
    </div>
    <div class='panel'>
      <h4>带宽监控</h4>
      <div class='legend'>
        <span class='legend-item'><span class='dot' style='background:#2ecc71'></span>下行 RX Mbps</span>
        <span class='legend-item'><span class='dot' style='background:#4a90e2'></span>上行 TX Mbps</span>
      </div>
      <svg id='bandwidth' viewBox='0 0 900 220' preserveAspectRatio='none'></svg>
    </div>
  </div>
  <div class='snapshot-grid'>
    <div class='panel'><h4>当前速率与资源</h4><div id='detail-current'></div></div>
    <div class='panel'><h4>进程排查</h4><div id='detail-processes'></div></div>
    <div class='panel'><h4>安全与暴露面</h4><div id='detail-risks'></div></div>
  </div>
  <div class='panel' style='margin-top:12px'>
    <h4>流量统计（累计字节）</h4>
    <svg id='traffic' viewBox='0 0 1200 280' preserveAspectRatio='none'></svg>
  </div>
  <p><button class='btn' onclick='closeDetail()'>关闭</button></p>
</div></div>
<script>
function fmtBytes(n){
  const x = Number(n||0); if (x<=0) return '0 B';
  const units=['B','KB','MB','GB','TB']; let i=0; let v=x;
  while(v>=1024 && i<units.length-1){v/=1024;i++;}
  return `${v.toFixed(v>=100?0:1)}${units[i]}`;
}
function bpsToMbps(v){
  return (Number(v||0) * 8) / 1000 / 1000;
}
function formatSmallNumber(v, digits=2){
  const n = Number(v||0);
  if (!Number.isFinite(n)) return '0.00';
  const threshold = 1 / Math.pow(10, digits);
  if (n > 0 && n < threshold) return `<${threshold.toFixed(digits)}`;
  return n.toFixed(digits);
}
function formatCountryLine(protocol, stats){
  const arr = Array.isArray(stats) ? stats : [];
  if(!arr.length) return `${protocol} - -`;
  const top3 = arr.slice(0,3).map(x=>`${x.country||'UN'} (${Number(x.connections||0)})`).join('  ');
  return `${protocol} - ${top3}`;
}
function formatCountryStats(tcpStats, udpStats){
  return `${formatCountryLine('TCP', tcpStats)}<br/>${formatCountryLine('UDP', udpStats)}`;
}
function formatCapacity(total, avail){
  return Number(total||0)>0 ? `${fmtBytes(total)} / ${fmtBytes(avail)}` : '采集不可用';
}
function escapeHtml(value){
  return String(value??'').replace(/[&<>'"]/g, ch=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
}
const alertsById=new Map();
function remediationChanged(action){
  if(!action||action.action_type!=='remediate_panel_pairing'||action.status!=='succeeded')return false;
  const text=String(action.result_message||'');
  const values=[...text.matchAll(/\\b(?:killed_processes|removed_services|removed_configs)=(\\d+)\\b/g)].map(x=>Number(x[1]||0));
  return values.some(x=>x>0)&&!/\\bcleanup_errors=[1-9]\\d*\\b/.test(text);
}
function actionStatusText(action){
  if(!action)return '';
  if(action.action_type==='remediate_panel_pairing'&&action.status==='succeeded'&&!remediationChanged(action)){
    return `未清理到目标：${action.result_message||'节点未找到匹配的进程、服务或配置'}`;
  }
  const labels={queued:'等待节点',dispatched:'节点处理中',succeeded:'已完成',failed:'失败'};
  const result=action.result_message?`：${action.result_message}`:'';
  return `${labels[action.status]||action.status}${result}`;
}
async function setAlertDisposition(alertId, decision){
  const alert=alertsById.get(Number(alertId)); if(!alert)return;
  const details=alert.details||{};
  let promptText='';
  if(decision==='deny'){
    const processes=(details.process_patterns||[]).join(', ')||'无';
    const files=(details.config_files||[]).join(', ')||'无';
    promptText=`确认禁止并清理 ${alert.host_id} / ${alert.runtime} / ${alert.container_name} 内的机场对接组件？\n\n将终止进程特征：${processes}\n停用并删除对应服务，删除配置：${files}\n容器本身不会停止。成功后同一面板域名再次出现会自动清理且不再提醒。`;
  }else if(decision==='allow_silent'){
    promptText=`确认允许此告警且以后不再提醒？\n\n该告警指纹会被永久抑制；机场面板域名还会同步加入节点放行名单。`;
  }else{
    promptText=`确认仅取消本次提醒？\n\n当前连续出现期间不再显示；事件消失后如果再次出现，仍会重新告警。`;
  }
  if(!confirm(promptText))return;
  try{
    const response=await fetch(`/api/v1/security/alerts/${Number(alertId)}/disposition`,{
      method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({decision})
    });
    const result=await response.json();
    if(!response.ok)throw new Error(result.detail||`HTTP ${response.status}`);
    await loadAlerts();
  }catch(error){window.alert(`操作提交失败：${error.message||error}`);}
}
async function loadAlerts(){
  const response=await fetch('/api/v1/security/alerts?active_only=true&limit=100');
  const data=await response.json();
  document.getElementById('active-alert-count').innerText=Number(data.active_count||0);
  const body=document.querySelector('#security-alerts tbody'); body.innerHTML='';
  alertsById.clear();
  for(const alert of (data.items||[])){
    alertsById.set(Number(alert.id),alert);
    const tr=document.createElement('tr');
    const runtime=alert.project?`${alert.runtime}/${alert.project}`:(alert.runtime||'-');
    const supportedRuntime=alert.runtime==='podman'||alert.runtime==='incus';
    const canRemediate=supportedRuntime&&alert.type==='unauthorized_panel_pairing'&&((alert.details?.process_patterns||[]).length>0||(alert.details?.config_files||[]).length>0);
    const pending=alert.latest_action&&(alert.latest_action.status==='queued'||alert.latest_action.status==='dispatched');
    const lastRemediation=alert.latest_action?.action_type==='remediate_panel_pairing'?alert.latest_action:null;
    const changed=remediationChanged(lastRemediation);
    const recurred=changed&&Number(alert.last_seen||0)>Number(lastRemediation?.updated_at||0);
    const denyLabel=pending?'禁止处理中':((lastRemediation&&(lastRemediation.status==='failed'||!changed))?'重试禁止':(recurred?'再次禁止':'禁止'));
    const denyControl=canRemediate?(changed&&!recurred?`<span class='ok'>已禁止，等待复检</span>`:`<button class='btn btn-danger' ${pending?'disabled':''} onclick="setAlertDisposition(${Number(alert.id)},'deny')">${denyLabel}</button>`):'';
    const actions=denyControl+
      `<button class='btn btn-allow' ${pending?'disabled':''} onclick="setAlertDisposition(${Number(alert.id)},'allow_silent')">允许且不再提醒</button>`+
      `<button class='btn btn-dismiss' ${pending?'disabled':''} onclick="setAlertDisposition(${Number(alert.id)},'dismiss_once')">本次取消提醒</button>`;
    tr.innerHTML=`<td class='severity-${escapeHtml(alert.severity)}'>${escapeHtml(alert.severity)}</td>`+
      `<td>${escapeHtml(alert.host_id)}</td><td>${escapeHtml(runtime)}</td>`+
      `<td>${escapeHtml(alert.container_name||'-')}</td><td>${escapeHtml(alert.type)}</td>`+
      `<td>${escapeHtml(alert.message)}</td><td>${escapeHtml(alert.last_seen_utc8)}</td>`+
      `<td>${Number(alert.occurrence_count||0)}</td><td>${actions}<div class='action-status'>${escapeHtml(actionStatusText(alert.latest_action))}</div></td>`;
    body.appendChild(tr);
  }
  const statusResponse=await fetch('/api/v1/security/status');
  const statusData=await statusResponse.json();
  const statusBody=document.querySelector('#security-status tbody'); statusBody.innerHTML='';
  for(const item of (statusData.items||[])){
    const access=item.access_log||{};
    const logState=!access.enabled?'未配置':(Number(access.readable_files||0)>0?'正常':'不可读');
    const tr=document.createElement('tr');
    tr.innerHTML=`<td>${escapeHtml(item.host_id)}</td>`+
      `<td>${formatSmallNumber(bpsToMbps(item.total_rx_bps),2)}</td>`+
      `<td>${formatSmallNumber(item.total_rx_pps,1)}</td><td>${Number(item.syn_recv_count||0)}</td>`+
      `<td>${formatSmallNumber(access.requests_per_second,1)}</td>`+
      `<td>${formatSmallNumber(access.top_ip_requests_per_second,1)} ${escapeHtml(access.top_ip||'')}</td>`+
      `<td class='${logState==='正常'?'ok':'bad'}'>${logState}</td><td>${escapeHtml(item.timestamp_utc8)}</td>`;
    statusBody.appendChild(tr);
  }
}
function groupByHost(items){
  const m=new Map();
  for(const x of items){
    if(!m.has(x.host_id))m.set(x.host_id,[]);
    m.get(x.host_id).push(x);
  }
  return [...m.entries()];
}
async function load(){
  const r=await fetch('/api/v1/latest'); const d=await r.json();
  const b=document.querySelector('#t tbody'); b.innerHTML='';
  for(const [host, rows] of groupByHost(d.items)){
    rows.sort((a,b)=>a.container_name.localeCompare(b.container_name));
    rows.forEach((x,idx)=>{
      const tr=document.createElement('tr');
      const cpuCls=x.alerts.cpu?'bad':'';
      const connCls=x.alerts.conn?'bad':'';
      const hostMount=x.disk_data_mountpoint||x.disk_data_requested_path||'/';
      const hostDiskText = `${hostMount}: ${formatCapacity(x.disk_data_total_bytes, x.disk_data_avail_bytes)}`;
      const containerDiskText = formatCapacity(x.container_fs_root_total_bytes, x.container_fs_root_avail_bytes);
      let html='';
      if(idx===0){
        html += `<td rowspan='${rows.length}'>${host}</td>`;
      }
      const offlineTag = x.alerts.stale ? ` <span class='bad'>(离线 ${x.offline_hours} 小时)</span>` : '';
      const runtimeBase = x.project && x.runtime==='incus' ? `${x.runtime}/${x.project}` : (x.runtime||'podman');
      const runtimeText = x.monitor_mode==='notice' ? `${runtimeBase}（仅提醒）` : runtimeBase;
      const security=x.security||{};
      const protocolRates=security.protocol_rates||{};
      const panelPairing=security.panel_pairing||{};
      const pairingText=panelPairing.detected?(panelPairing.approved?'白名单':((panelPairing.unapproved_domains||[]).join(',')||'发现特征')):'-';
      const listeningPorts=Array.isArray(security.listening_ports)?security.listening_ports.slice(0,8).join(','):'-';
      const exposureText=Array.isArray(security.network_exposure)&&security.network_exposure.length?security.network_exposure.slice(0,6).map(item=>`${item.listen||'?'}→${item.target||'?'}`).join(', '):'-';
      html += `<td>${runtimeText}</td><td>${x.container_id || '-'}</td><td>${x.container_name}${offlineTag}</td><td class='${cpuCls}'>${formatSmallNumber(x.cpu_percent, 2)}</td><td>${formatSmallNumber(x.mem_percent, 2)}</td><td class='${connCls}'>${x.conn_count}</td><td>${Number(security.process_count||0)}</td><td>${formatSmallNumber(security.net_rx_pps, 1)}</td><td>${Number(security.syn_recv_count||0)}</td><td>${Number(security.outbound_unique_ips||0)}</td><td>${escapeHtml(listeningPorts||'-')}</td><td>${escapeHtml(exposureText)}</td><td>${formatSmallNumber(protocolRates.Tcp_ActiveOpens_per_second,1)}</td><td>${formatSmallNumber(protocolRates.Tcp_AttemptFails_per_second,1)}</td><td>${Array.isArray(security.suspicious_processes)?security.suspicious_processes.length:0}</td><td>${Array.isArray(security.configuration_risks)?security.configuration_risks.length:0}</td><td class='${panelPairing.detected&&!panelPairing.approved?'bad':''}'>${escapeHtml(pairingText)}</td><td>${formatCountryStats(x.tcp_country_stats, x.udp_country_stats)}</td><td>${formatSmallNumber(bpsToMbps(x.net_rx_bps), 2)}</td><td>${formatSmallNumber(bpsToMbps(x.net_tx_bps), 2)}</td><td>${containerDiskText}</td>`;
      if(idx===0){
        html += `<td rowspan='${rows.length}' class='${x.alerts.disk?'bad':''}'>${hostDiskText}</td>`;
        html += `<td rowspan='${rows.length}' class='${x.container_network_ok_v4?'ok':'bad'}'>${x.container_network_ok_v4?'✅️':'❌️'}</td>`;
        html += `<td rowspan='${rows.length}' class='${x.container_network_ok_v6?'ok':'bad'}'>${x.container_network_ok_v6?'✅️':'❌️'}</td>`;
        html += `<td rowspan='${rows.length}' class='${x.alerts.stale?'bad':''}'>${x.timestamp_iso_utc8}</td>`;
      }
      html += `<td><button class='btn' onclick='openDetail(${JSON.stringify(host)}, ${JSON.stringify(x.runtime)}, ${JSON.stringify(x.project||'')}, ${JSON.stringify(x.container_name)})'>详情</button></td>`;
      tr.innerHTML=html;
      b.appendChild(tr);
    });
  }
}
function closeDetail(){ document.getElementById('modal').style.display='none'; }
function buildPolyline(vals,maxv,w,h,pad){
  const useMax=Math.max(1,maxv);
  return vals.map((v,i)=>`${i*(w/Math.max(1,vals.length-1))},${(h-pad)-((v/useMax)*(h-pad*2))}`).join(' ');
}
function drawAxes(svg,w,h){
  const lines=[];
  for(let i=0;i<=5;i++){
    const y=(h-20)-(i*((h-40)/5));
    lines.push(`<line x1='0' y1='${y}' x2='${w}' y2='${y}' stroke='#29466f' stroke-width='1' />`);
  }
  svg.innerHTML=lines.join('');
}
function estimateStepSeconds(points){
  if(!points || points.length < 2) return 0;
  const intervals=[];
  for(let i=1;i<points.length;i++){
    intervals.push(Math.max(1, Number(points[i].timestamp||0)-Number(points[i-1].timestamp||0)));
  }
  return intervals.reduce((a,b)=>a+b,0)/intervals.length;
}
async function openDetail(host, runtime, project, container){
  const latestRes=await fetch('/api/v1/latest');
  const latestData=await latestRes.json();
  const target=(latestData.items||[]).find(x=>x.host_id===host&&x.runtime===runtime&&(x.project||'')===project&&x.container_name===container);
  const countryTop=formatCountryStats(target?.tcp_country_stats||[], target?.udp_country_stats||[]);
  const res=await fetch(`/api/v1/history?host_id=${encodeURIComponent(host)}&runtime=${encodeURIComponent(runtime)}&project=${encodeURIComponent(project)}&container_name=${encodeURIComponent(container)}`);
  const data=await res.json();
  const runtimeLabel=project ? `${runtime}/${project}` : runtime;
  document.getElementById('detail-title').innerText=`${host} / ${runtimeLabel} / ${container} 历史数据（TCP国家：${countryTop.replaceAll('<br/>', ', ')}）`;
  const pts=data.items||[];
  const recent=pts.slice(-80);
  const svg=document.getElementById('chart');
  const bandwidthSvg=document.getElementById('bandwidth');
  const trafficSvg=document.getElementById('traffic');
  const security=target?.security||{};
  const rates=security.protocol_rates||{};
  const topProcess=target?.top_cpu_process_command?
    `PID ${Number(target.top_cpu_process_pid||0)} · CPU ${formatSmallNumber(target.top_cpu_process_cpu_percent,2)}% · ${escapeHtml(target.top_cpu_process_command)}`:'未采集到高 CPU 进程';
  const suspicious=Array.isArray(security.suspicious_processes)?security.suspicious_processes:[];
  const risks=Array.isArray(security.configuration_risks)?security.configuration_risks:[];
  const exposures=Array.isArray(security.network_exposure)?security.network_exposure:[];
  document.getElementById('detail-current').innerHTML=`CPU ${formatSmallNumber(target?.cpu_percent,2)}% · 内存 ${formatSmallNumber(target?.mem_percent,2)}%<br/>连接 ${Number(target?.conn_count||0)} · 进程 ${Number(security.process_count||0)}<br/>RX ${formatSmallNumber(bpsToMbps(target?.net_rx_bps),2)} Mbps / ${formatSmallNumber(security.net_rx_pps,1)} pps<br/>TX ${formatSmallNumber(bpsToMbps(target?.net_tx_bps),2)} Mbps<br/>TCP 建连 ${formatSmallNumber(rates.Tcp_ActiveOpens_per_second,1)}/s · 失败 ${formatSmallNumber(rates.Tcp_AttemptFails_per_second,1)}/s`;
  document.getElementById('detail-processes').innerHTML=`<div>${topProcess}</div>`+
    (suspicious.length?`<ul class='snapshot-list'>${suspicious.map(x=>`<li>PID ${Number(x.pid||0)} · ${escapeHtml(x.pattern||x.command||'可疑进程')}</li>`).join('')}</ul>`:'<div class="ok">未发现可疑进程特征</div>');
  document.getElementById('detail-risks').innerHTML=`监听端口：${escapeHtml((security.listening_ports||[]).join(', ')||'-')}<br/>`+
    `NAT/代理：${escapeHtml(exposures.map(x=>`${x.listen||'?'}→${x.target||'?'}`).join(', ')||'-')}`+
    (risks.length?`<ul class='snapshot-list'>${risks.map(x=>`<li>${escapeHtml(x.message||x.type||JSON.stringify(x))}</li>`).join('')}</ul>`:'<div class="ok">未发现配置风险</div>');
  if(!recent.length){
    svg.innerHTML = '';
    bandwidthSvg.innerHTML = '';
    trafficSvg.innerHTML = '';
    document.getElementById('modal').style.display='flex';
    return;
  }
  const cpuVals=recent.map(x=>Number(x.cpu_percent||0));
  const memVals=recent.map(x=>Number(x.mem_percent||0));
  const connVals=recent.map(x=>Number(x.conn_count||0));
  const rxMbpsVals=recent.map(x=>bpsToMbps(Number(x.net_rx_bps||0)));
  const txMbpsVals=recent.map(x=>bpsToMbps(Number(x.net_tx_bps||0)));
  const speedVals=rxMbpsVals.map((v,i)=>v+txMbpsVals[i]);
  const step=estimateStepSeconds(recent) || 300;
  let rxTotal=0; let txTotal=0;
  const rxBytesCum=recent.map((x,i)=>{
    const currentStep=i===0?step:Math.max(1, Number(recent[i].timestamp||0)-Number(recent[i-1].timestamp||0));
    rxTotal+=Number(x.net_rx_bps||0)*currentStep;
    return rxTotal;
  });
  const txBytesCum=recent.map((x,i)=>{
    const currentStep=i===0?step:Math.max(1, Number(recent[i].timestamp||0)-Number(recent[i-1].timestamp||0));
    txTotal+=Number(x.net_tx_bps||0)*currentStep;
    return txTotal;
  });

  drawAxes(svg,900,220);
  const cpuPoints=buildPolyline(cpuVals, Math.max(100, ...cpuVals, ...memVals), 900, 220, 20);
  const memPoints=buildPolyline(memVals, Math.max(100, ...cpuVals, ...memVals), 900, 220, 20);
  const connPoints=buildPolyline(connVals, Math.max(1, ...connVals), 900, 220, 20);
  const speedPoints=buildPolyline(speedVals, Math.max(1, ...speedVals), 900, 220, 20);
  svg.innerHTML += `
    <polyline fill='none' stroke='#4a90e2' stroke-width='2.5' points='${cpuPoints}' />
    <polyline fill='none' stroke='#16a085' stroke-width='2.5' points='${memPoints}' />
    <polyline fill='none' stroke='#9b59b6' stroke-width='2.5' points='${connPoints}' />
    <polyline fill='none' stroke='#f39c12' stroke-width='2.5' points='${speedPoints}' />
  `;

  drawAxes(bandwidthSvg,900,220);
  const rxPoints=buildPolyline(rxMbpsVals, Math.max(1, ...rxMbpsVals, ...txMbpsVals), 900, 220, 20);
  const txPoints=buildPolyline(txMbpsVals, Math.max(1, ...rxMbpsVals, ...txMbpsVals), 900, 220, 20);
  bandwidthSvg.innerHTML += `
    <polyline fill='none' stroke='#2ecc71' stroke-width='2.5' points='${rxPoints}' />
    <polyline fill='none' stroke='#4a90e2' stroke-width='2.5' points='${txPoints}' />
  `;

  drawAxes(trafficSvg,1200,280);
  const rxCumPoints=buildPolyline(rxBytesCum, Math.max(1, ...rxBytesCum, ...txBytesCum), 1200, 280, 20);
  const txCumPoints=buildPolyline(txBytesCum, Math.max(1, ...rxBytesCum, ...txBytesCum), 1200, 280, 20);
  trafficSvg.innerHTML += `
    <polyline fill='none' stroke='#2ecc71' stroke-width='2.5' points='${rxCumPoints}' />
    <polyline fill='none' stroke='#4a90e2' stroke-width='2.5' points='${txCumPoints}' />
  `;
  document.getElementById('modal').style.display='flex';
}
let openedFromUrl=false;
async function loadAndOpenRequestedDetail(){
  await load();
  if(openedFromUrl)return;
  const q=new URLSearchParams(location.search);
  if(q.get('detail')==='1'&&q.get('host')&&q.get('runtime')&&q.get('container')){
    openedFromUrl=true;
    await openDetail(q.get('host'),q.get('runtime'),q.get('project')||'',q.get('container'));
  }
}
loadAndOpenRequestedDetail(); loadAlerts(); setInterval(()=>{load();loadAlerts();}, 15000);
</script>
</body></html>
"""


@app.get("/stats", response_class=HTMLResponse)
def stats_page() -> str:
    return """
<!doctype html>
<html><head><meta charset='utf-8'><title>Container Stats</title>
<style>
body{font-family:sans-serif;margin:1rem;background:#0f1a2e;color:#dbe7ff}
.topbar{display:flex;gap:8px;align-items:center;margin-bottom:12px}
.card-grid{display:grid;grid-template-columns:repeat(4,minmax(120px,1fr));gap:10px;margin-bottom:12px}
.card{background:#13213b;border:1px solid #233b61;border-radius:10px;padding:10px}
.value{font-size:22px;font-weight:700;margin-top:6px}
table{border-collapse:collapse;width:100%;background:#13213b;color:#dbe7ff;margin-top:10px}
th,td{border:1px solid #233b61;padding:8px;text-align:center}
th{background:#1a2c4e}
a{color:#8cc7ff}
.detail-link{display:inline-block;border:1px solid #4b6fa8;border-radius:6px;padding:4px 8px;text-decoration:none;background:#1a2c4e}
</style>
</head><body>
<h2>数据统计页</h2>
<div class='topbar'>
  <label>统计窗口(分钟)：<input id='minutes' type='number' value='720' min='5' max='10080' /></label>
  <button onclick='loadStats()'>刷新</button>
  <a href='/'>返回总览</a>
</div>
<div class='card-grid'>
  <div class='card'><div>容器数</div><div class='value' id='kpi-containers'>0</div></div>
  <div class='card'><div>样本数</div><div class='value' id='kpi-samples'>0</div></div>
  <div class='card'><div>建议采样间隔</div><div class='value' id='kpi-interval'>--</div></div>
  <div class='card'><div>窗口</div><div class='value' id='kpi-window'>--</div></div>
</div>

<h3>Top10：平均 CPU</h3>
  <table id='cpu-top'><thead><tr><th>主机</th><th>运行时</th><th>容器</th><th>平均 CPU%</th><th>峰值 CPU%</th><th>估算间隔(秒)</th><th>排查</th></tr></thead><tbody></tbody></table>

<h3>Top10：平均连接数</h3>
  <table id='conn-top'><thead><tr><th>主机</th><th>运行时</th><th>容器</th><th>平均连接</th><th>峰值连接</th><th>样本数</th><th>排查</th></tr></thead><tbody></tbody></table>

<h3>Top10：累计流量</h3>
  <table id='traffic-top'><thead><tr><th>主机</th><th>运行时</th><th>容器</th><th>累计 RX</th><th>累计 TX</th><th>累计总流量</th><th>排查</th></tr></thead><tbody></tbody></table>

<h3>全部容器</h3>
<table id='all-containers'><thead><tr><th>主机</th><th>运行时</th><th>容器</th><th>当前 CPU%</th><th>当前内存%</th><th>当前 RX</th><th>当前 TX</th><th>当前连接</th><th>样本数</th><th>排查</th></tr></thead><tbody></tbody></table>

<h3>Host 汇总</h3>
<table id='host-summary'><thead><tr><th>主机</th><th>累计 RX</th><th>累计 TX</th><th>累计总流量</th><th>样本数</th></tr></thead><tbody></tbody></table>

<script>
function fmtBytes(n){
  const x = Number(n||0); if (x<=0) return '0 B';
  const units=['B','KB','MB','GB','TB']; let i=0; let v=x;
  while(v>=1024 && i<units.length-1){v/=1024;i++;}
  return `${v.toFixed(v>=100?0:1)} ${units[i]}`;
}
function escapeHtml(value){
  return String(value??'').replace(/[&<>'"]/g, ch=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
}
function detailHref(x){
  const q=new URLSearchParams({detail:'1',host:x.host_id,runtime:x.runtime,project:x.project||'',container:x.container_name});
  return `/?${q.toString()}`;
}
function detailCell(x){
  return `<a class='detail-link' href='${escapeHtml(detailHref(x))}'>容器详情</a>`;
}
function renderRows(id, rows, mapper){
  const tb=document.querySelector(`#${id} tbody`);
  tb.innerHTML='';
  for(const row of rows){
    const tr=document.createElement('tr');
    tr.innerHTML=mapper(row);
    tb.appendChild(tr);
  }
}
async function loadStats(){
  const minutes=Math.max(5, Math.min(10080, Number(document.getElementById('minutes').value||720)));
  const res=await fetch(`/api/v1/stats?minutes=${minutes}`);
  const data=await res.json();
  document.getElementById('kpi-containers').innerText=data.container_count||0;
  document.getElementById('kpi-samples').innerText=data.samples||0;
  document.getElementById('kpi-interval').innerText=(data.recommendation?.suggested_interval_seconds||'--') + 's';
  document.getElementById('kpi-window').innerText=(data.window_minutes||minutes)+'m';

  renderRows('cpu-top', data.ranks?.avg_cpu_top10||[], x=>`
    <td>${x.host_id}</td><td>${x.project?`${x.runtime}/${x.project}`:x.runtime}</td><td>${x.container_name}</td>
    <td>${Number(x.avg.cpu_percent||0).toFixed(2)}</td>
    <td>${Number(x.max.cpu_percent||0).toFixed(2)}</td>
    <td>${Number(x.estimated_interval_seconds||0).toFixed(2)}</td>
    <td>${detailCell(x)}</td>
  `);
  renderRows('conn-top', data.ranks?.avg_conn_top10||[], x=>`
    <td>${x.host_id}</td><td>${x.project?`${x.runtime}/${x.project}`:x.runtime}</td><td>${x.container_name}</td>
    <td>${Number(x.avg.conn_count||0).toFixed(2)}</td>
    <td>${Number(x.max.conn_count||0)}</td>
    <td>${x.samples||0}</td>
    <td>${detailCell(x)}</td>
  `);
  renderRows('traffic-top', data.ranks?.traffic_top10||[], x=>`
    <td>${x.host_id}</td><td>${x.project?`${x.runtime}/${x.project}`:x.runtime}</td><td>${x.container_name}</td>
    <td>${fmtBytes(x.traffic_bytes.rx)}</td>
    <td>${fmtBytes(x.traffic_bytes.tx)}</td>
    <td>${fmtBytes(x.traffic_bytes.total)}</td>
    <td>${detailCell(x)}</td>
  `);
  renderRows('all-containers', data.containers||[], x=>`
    <td>${escapeHtml(x.host_id)}</td><td>${escapeHtml(x.project?`${x.runtime}/${x.project}`:x.runtime)}</td><td>${escapeHtml(x.container_name)}</td>
    <td>${Number(x.latest?.cpu_percent||0).toFixed(2)}</td><td>${Number(x.latest?.mem_percent||0).toFixed(2)}</td>
    <td>${fmtBytes(x.latest?.net_rx_bps)}/s</td><td>${fmtBytes(x.latest?.net_tx_bps)}/s</td>
    <td>${Number(x.latest?.conn_count||0)}</td><td>${Number(x.samples||0)}</td><td>${detailCell(x)}</td>
  `);
  renderRows('host-summary', data.hosts||[], x=>`
    <td>${x.host_id}</td>
    <td>${fmtBytes(x.traffic_rx_bytes)}</td>
    <td>${fmtBytes(x.traffic_tx_bytes)}</td>
    <td>${fmtBytes(x.traffic_total_bytes)}</td>
    <td>${x.samples}</td>
  `);
}
loadStats();
</script>
</body></html>
"""
