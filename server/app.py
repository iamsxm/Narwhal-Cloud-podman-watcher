import hmac
import hashlib
import json
import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

DB_PATH = os.getenv("DB_PATH", "/data/monitor.db")
SHARED_SECRET = os.getenv("SHARED_SECRET", "change-me")
ALERT_DISK_THRESHOLD_PERCENT = int(os.getenv("ALERT_DISK_THRESHOLD_PERCENT", "80"))
ALERT_CPU_THRESHOLD_PERCENT = float(os.getenv("ALERT_CPU_THRESHOLD_PERCENT", "80"))
ALERT_CONN_THRESHOLD = int(os.getenv("ALERT_CONN_THRESHOLD", "500"))
STALE_SECONDS = int(os.getenv("STALE_SECONDS", "900"))
OFFLINE_HIDE_SECONDS = int(os.getenv("OFFLINE_HIDE_SECONDS", str(24 * 3600)))
PURGE_SECONDS = int(os.getenv("PURGE_SECONDS", str(30 * 24 * 3600)))
UTC8 = timezone(timedelta(hours=8))


def format_utc8(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=UTC8).strftime("%Y-%m-%d %H:%M:%S")


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
        """
    )
    cols = conn.execute("PRAGMA table_info(reports)").fetchall()
    col_names = {str(c["name"]) for c in cols}
    if "mem_percent" not in col_names:
        conn.execute("ALTER TABLE reports ADD COLUMN mem_percent REAL NOT NULL DEFAULT 0")
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
    podman_v4 = 1 if data.get("podman_network", {}).get("ipv4_ok") else 0
    podman_v6 = 1 if data.get("podman_network", {}).get("ipv6_ok") else 0

    containers: List[Dict[str, Any]] = data.get("containers", [])
    conn = db()
    for c in containers:
        conn.execute(
            """
            INSERT INTO reports(
                host_id, container_name, cpu_percent, mem_bytes, mem_percent, net_rx_bps, net_tx_bps,
                conn_count, disk_file, disk_size_bytes, disk_used_percent,
                podman_network_ok_v4, podman_network_ok_v6, ts, payload_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                host_id,
                c.get("name", "unknown"),
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
    conn.commit()
    conn.close()
    return {"ok": True, "records": len(containers)}


@app.get("/api/v1/latest")
def latest(include_stale: bool = False) -> JSONResponse:
    cleanup_old_reports()
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
            "cpu_percent": r["cpu_percent"],
            "mem_bytes": r["mem_bytes"],
            "mem_percent": float(r["mem_percent"] or 0),
            "net_rx_bps": r["net_rx_bps"],
            "net_tx_bps": r["net_tx_bps"],
            "conn_count": int(r["conn_count"]),
            "tcp_country_stats": payload.get("tcp_country_stats", []),
            "udp_country_stats": payload.get("udp_country_stats", []),
            "disk_file": r["disk_file"],
            "disk_used_percent": r["disk_used_percent"],
            "disk_root_device": host_disk.get("root_device") or disk.get("root_device", ""),
            "disk_root_total_bytes": host_disk.get("root_total_bytes") or disk.get("root_total_bytes", 0),
            "disk_root_avail_bytes": host_disk.get("root_avail_bytes") or disk.get("root_avail_bytes", 0),
            "disk_data_total_bytes": host_disk.get("data_total_bytes") or disk.get("data_total_bytes", 0),
            "disk_data_avail_bytes": host_disk.get("data_avail_bytes") or disk.get("data_avail_bytes", 0),
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
def history(host_id: str, container_name: str, minutes: int = 720) -> JSONResponse:
    minutes = max(5, min(minutes, 1440))
    start_ts = int(time.time()) - (minutes * 60)
    conn = db()
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


@app.get("/api/v1/stats")
def stats(minutes: int = 720) -> JSONResponse:
    minutes = max(5, min(minutes, 10080))
    start_ts = int(time.time()) - (minutes * 60)
    conn = db()
    rows = conn.execute(
        """
        SELECT host_id, container_name, ts, cpu_percent, mem_bytes, mem_percent, net_rx_bps, net_tx_bps, conn_count
        FROM reports
        WHERE ts>=?
        ORDER BY host_id, container_name, ts ASC
        """,
        (start_ts,),
    ).fetchall()
    conn.close()

    grouped: Dict[tuple[str, str], List[sqlite3.Row]] = {}
    for row in rows:
        key = (str(row["host_id"]), str(row["container_name"]))
        grouped.setdefault(key, []).append(row)

    items: List[Dict[str, Any]] = []
    host_totals: Dict[str, Dict[str, float]] = {}
    total_samples = 0
    for (host_id, container_name), series in grouped.items():
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
<html><head><meta charset='utf-8'><title>Podman Monitor</title>
<style>
body{font-family:sans-serif;margin:1rem;background:#0f1a2e;color:#dbe7ff}
table{border-collapse:collapse;width:100%;background:#13213b;color:#dbe7ff}
th,td{border:1px solid #233b61;padding:8px;vertical-align:middle;text-align:center}
th{background:#1a2c4e}
.bad{color:#b00020;font-weight:bold}
.ok{color:#0a8f08}
.btn{border:1px solid #4b6fa8;padding:4px 8px;border-radius:6px;background:#1a2c4e;color:#dbe7ff;cursor:pointer}
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
</style>
</head><body>
<h2>Podman Monitor Dashboard</h2>
<p>每 15 秒自动刷新。CPU/内存使用率/连接数/网速展示采集到的原始上报值，服务端不再做 5 分钟平均。红色表示预警（CPU ≥ {ALERT_CPU_THRESHOLD_PERCENT:.2f}% 或连接数 ≥ {ALERT_CONN_THRESHOLD}）。离线容器默认保留 1 天并显示离线时长（按小时刷新），超过 1 天隐藏，超过 30 天自动清理。<a href='/stats' style='color:#8cc7ff'>查看统计页</a></p>
<table id='t'><thead><tr><th>主机</th><th>容器ID</th><th>容器名</th><th>CPU%</th><th>内存%</th><th>连接数</th><th>国家Top3(TCP/UDP)</th><th>RX Mbps</th><th>TX Mbps</th><th>总容量/可用</th><th>主盘(/data 总量/可用)</th><th>IPv4</th><th>IPv6</th><th>上报时间(UTC+8)</th><th>详情</th></tr></thead><tbody></tbody></table>
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
      const hostDiskText = `/data: ${fmtBytes(x.disk_data_total_bytes)} / ${fmtBytes(x.disk_data_avail_bytes)}`;
      const containerDiskText = `${fmtBytes(x.container_fs_root_total_bytes)} / ${fmtBytes(x.container_fs_root_avail_bytes)}`;
      let html='';
      if(idx===0){
        html += `<td rowspan='${rows.length}'>${host}</td>`;
      }
      const offlineTag = x.alerts.stale ? ` <span class='bad'>(离线 ${x.offline_hours} 小时)</span>` : '';
      html += `<td>${x.container_id || '-'}</td><td>${x.container_name}${offlineTag}</td><td class='${cpuCls}'>${formatSmallNumber(x.cpu_percent, 2)}</td><td>${formatSmallNumber(x.mem_percent, 2)}</td><td class='${connCls}'>${x.conn_count}</td><td>${formatCountryStats(x.tcp_country_stats, x.udp_country_stats)}</td><td>${formatSmallNumber(bpsToMbps(x.net_rx_bps), 2)}</td><td>${formatSmallNumber(bpsToMbps(x.net_tx_bps), 2)}</td><td>${containerDiskText}</td>`;
      if(idx===0){
        html += `<td rowspan='${rows.length}' class='${x.alerts.disk?'bad':''}'>${hostDiskText}</td>`;
        html += `<td rowspan='${rows.length}' class='${x.podman_network_ok_v4?'ok':'bad'}'>${x.podman_network_ok_v4?'✅️':'❌️'}</td>`;
        html += `<td rowspan='${rows.length}' class='${x.podman_network_ok_v6?'ok':'bad'}'>${x.podman_network_ok_v6?'✅️':'❌️'}</td>`;
        html += `<td rowspan='${rows.length}' class='${x.alerts.stale?'bad':''}'>${x.timestamp_iso_utc8}</td>`;
      }
      html += `<td><button class='btn' onclick='openDetail(${JSON.stringify(host)}, ${JSON.stringify(x.container_name)})'>详情</button></td>`;
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
async function openDetail(host, container){
  const latestRes=await fetch('/api/v1/latest');
  const latestData=await latestRes.json();
  const target=(latestData.items||[]).find(x=>x.host_id===host&&x.container_name===container);
  const countryTop=formatCountryStats(target?.tcp_country_stats||[], target?.udp_country_stats||[]);
  const res=await fetch(`/api/v1/history?host_id=${encodeURIComponent(host)}&container_name=${encodeURIComponent(container)}`);
  const data=await res.json();
  document.getElementById('detail-title').innerText=`${host} / ${container} 历史数据（TCP国家：${countryTop.replaceAll('<br/>', ', ')}）`;
  const pts=data.items||[];
  const recent=pts.slice(-80);
  const svg=document.getElementById('chart');
  const bandwidthSvg=document.getElementById('bandwidth');
  const trafficSvg=document.getElementById('traffic');
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
load(); setInterval(load, 15000);
</script>
</body></html>
"""


@app.get("/stats", response_class=HTMLResponse)
def stats_page() -> str:
    return """
<!doctype html>
<html><head><meta charset='utf-8'><title>Podman Stats</title>
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
<table id='cpu-top'><thead><tr><th>主机</th><th>容器</th><th>平均 CPU%</th><th>峰值 CPU%</th><th>估算间隔(秒)</th></tr></thead><tbody></tbody></table>

<h3>Top10：平均连接数</h3>
<table id='conn-top'><thead><tr><th>主机</th><th>容器</th><th>平均连接</th><th>峰值连接</th><th>样本数</th></tr></thead><tbody></tbody></table>

<h3>Top10：累计流量</h3>
<table id='traffic-top'><thead><tr><th>主机</th><th>容器</th><th>累计 RX</th><th>累计 TX</th><th>累计总流量</th></tr></thead><tbody></tbody></table>

<h3>Host 汇总</h3>
<table id='host-summary'><thead><tr><th>主机</th><th>累计 RX</th><th>累计 TX</th><th>累计总流量</th><th>样本数</th></tr></thead><tbody></tbody></table>

<script>
function fmtBytes(n){
  const x = Number(n||0); if (x<=0) return '0 B';
  const units=['B','KB','MB','GB','TB']; let i=0; let v=x;
  while(v>=1024 && i<units.length-1){v/=1024;i++;}
  return `${v.toFixed(v>=100?0:1)} ${units[i]}`;
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
    <td>${x.host_id}</td><td>${x.container_name}</td>
    <td>${Number(x.avg.cpu_percent||0).toFixed(2)}</td>
    <td>${Number(x.max.cpu_percent||0).toFixed(2)}</td>
    <td>${Number(x.estimated_interval_seconds||0).toFixed(2)}</td>
  `);
  renderRows('conn-top', data.ranks?.avg_conn_top10||[], x=>`
    <td>${x.host_id}</td><td>${x.container_name}</td>
    <td>${Number(x.avg.conn_count||0).toFixed(2)}</td>
    <td>${Number(x.max.conn_count||0)}</td>
    <td>${x.samples||0}</td>
  `);
  renderRows('traffic-top', data.ranks?.traffic_top10||[], x=>`
    <td>${x.host_id}</td><td>${x.container_name}</td>
    <td>${fmtBytes(x.traffic_bytes.rx)}</td>
    <td>${fmtBytes(x.traffic_bytes.tx)}</td>
    <td>${fmtBytes(x.traffic_bytes.total)}</td>
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
