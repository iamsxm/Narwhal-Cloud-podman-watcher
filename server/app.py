import hmac
import hashlib
import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

DB_PATH = os.getenv("DB_PATH", "/data/monitor.db")
SHARED_SECRET = os.getenv("SHARED_SECRET", "change-me")
ALERT_DISK_THRESHOLD_PERCENT = int(os.getenv("ALERT_DISK_THRESHOLD_PERCENT", "80"))
STALE_SECONDS = int(os.getenv("STALE_SECONDS", "900"))

app = FastAPI(title="Narwhal Podman Monitor")


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
            cpu_percent REAL NOT NULL,
            mem_bytes INTEGER NOT NULL,
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
        """
    )
    conn.commit()
    conn.close()


@app.on_event("startup")
def startup() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    init_db()


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


@app.post("/api/v1/report")
async def report(
    request: Request,
    x_timestamp: str = Header(default=""),
    x_signature: str = Header(default=""),
) -> Dict[str, Any]:
    body = await request.body()
    verify_signature(body, x_timestamp, x_signature)
    data = json.loads(body)

    host_id = data.get("host_id", "unknown")
    ts = int(data.get("timestamp", time.time()))
    podman_v4 = 1 if data.get("podman_network", {}).get("ipv4_ok") else 0
    podman_v6 = 1 if data.get("podman_network", {}).get("ipv6_ok") else 0

    containers: List[Dict[str, Any]] = data.get("containers", [])
    conn = db()
    for c in containers:
        conn.execute(
            """
            INSERT INTO reports(
                host_id, container_name, cpu_percent, mem_bytes, net_rx_bps, net_tx_bps,
                conn_count, disk_file, disk_size_bytes, disk_used_percent,
                podman_network_ok_v4, podman_network_ok_v6, ts, payload_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                host_id,
                c.get("name", "unknown"),
                float(c.get("cpu_percent", 0)),
                int(c.get("mem_bytes", 0)),
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
    conn.commit()
    conn.close()
    return {"ok": True, "records": len(containers)}


@app.get("/api/v1/latest")
def latest() -> JSONResponse:
    conn = db()
    rows = conn.execute(
        """
        SELECT r.* FROM reports r
        JOIN (
            SELECT host_id, container_name, MAX(ts) AS max_ts
            FROM reports
            GROUP BY host_id, container_name
        ) m ON r.host_id=m.host_id AND r.container_name=m.container_name AND r.ts=m.max_ts
        ORDER BY r.host_id, r.container_name
        """
    ).fetchall()
    conn.close()

    now = int(time.time())
    out = []
    for r in rows:
        alert_disk = (r["disk_used_percent"] or 0) >= ALERT_DISK_THRESHOLD_PERCENT
        stale = (now - r["ts"]) > STALE_SECONDS
        out.append({
            "host_id": r["host_id"],
            "container_name": r["container_name"],
            "cpu_percent": r["cpu_percent"],
            "mem_bytes": r["mem_bytes"],
            "net_rx_bps": r["net_rx_bps"],
            "net_tx_bps": r["net_tx_bps"],
            "conn_count": r["conn_count"],
            "disk_file": r["disk_file"],
            "disk_used_percent": r["disk_used_percent"],
            "podman_network_ok_v4": bool(r["podman_network_ok_v4"]),
            "podman_network_ok_v6": bool(r["podman_network_ok_v6"]),
            "timestamp": r["ts"],
            "timestamp_iso": datetime.fromtimestamp(r["ts"], tz=timezone.utc).isoformat(),
            "alerts": {
                "disk": alert_disk,
                "stale": stale,
                "network": (not r["podman_network_ok_v4"]) or (not r["podman_network_ok_v6"]),
            },
        })
    return JSONResponse(content={"items": out})


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return """
<!doctype html>
<html><head><meta charset='utf-8'><title>Podman Monitor</title>
<style>body{font-family:sans-serif;margin:1rem}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:6px}.bad{color:#b00020;font-weight:bold}</style>
</head><body>
<h2>Podman Monitor Dashboard</h2>
<p>每 15 秒自动刷新。红色表示预警。</p>
<table id='t'><thead><tr><th>主机</th><th>容器</th><th>CPU%</th><th>连接数</th><th>RX B/s</th><th>TX B/s</th><th>磁盘%</th><th>IPv4</th><th>IPv6</th><th>上报时间(UTC)</th></tr></thead><tbody></tbody></table>
<script>
async function load(){
  const r=await fetch('/api/v1/latest'); const d=await r.json();
  const b=document.querySelector('#t tbody'); b.innerHTML='';
  for(const x of d.items){
    const tr=document.createElement('tr');
    const cls=(x.alerts.disk||x.alerts.stale||x.alerts.network)?'bad':'';
    tr.innerHTML=`<td>${x.host_id}</td><td>${x.container_name}</td><td class='${cls}'>${x.cpu_percent.toFixed(2)}</td><td>${x.conn_count}</td><td>${x.net_rx_bps.toFixed(0)}</td><td>${x.net_tx_bps.toFixed(0)}</td><td class='${x.alerts.disk?'bad':''}'>${(x.disk_used_percent||0).toFixed(1)}</td><td class='${x.podman_network_ok_v4?'':'bad'}'>${x.podman_network_ok_v4}</td><td class='${x.podman_network_ok_v6?'':'bad'}'>${x.podman_network_ok_v6}</td><td class='${x.alerts.stale?'bad':''}'>${x.timestamp_iso}</td>`;
    b.appendChild(tr);
  }
}
load(); setInterval(load, 15000);
</script>
</body></html>
"""
