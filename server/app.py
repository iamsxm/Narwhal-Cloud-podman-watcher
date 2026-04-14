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
STALE_SECONDS = int(os.getenv("STALE_SECONDS", "900"))
UTC8 = timezone(timedelta(hours=8))

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
def latest(include_stale: bool = False) -> JSONResponse:
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

    avg_rows = conn.execute(
        """
        SELECT host_id, container_name,
               AVG(cpu_percent) AS cpu_avg,
               AVG(net_rx_bps) AS rx_avg,
               AVG(net_tx_bps) AS tx_avg,
               AVG(conn_count) AS conn_avg
        FROM reports
        WHERE ts >= ?
        GROUP BY host_id, container_name
        """,
        (int(time.time()) - 300,),
    ).fetchall()
    conn.close()
    avg_map = {(x["host_id"], x["container_name"]): x for x in avg_rows}

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
        avg = avg_map.get((r["host_id"], r["container_name"]))
        alert_disk = (r["disk_used_percent"] or 0) >= ALERT_DISK_THRESHOLD_PERCENT
        stale = (now - r["ts"]) > STALE_SECONDS
        if stale and not include_stale:
            continue
        container_disk = payload.get("container_disk", {})
        out.append({
            "host_id": r["host_id"],
            "container_id": payload.get("id", ""),
            "container_name": r["container_name"],
            "cpu_percent": (avg["cpu_avg"] if avg else r["cpu_percent"]),
            "mem_bytes": r["mem_bytes"],
            "net_rx_bps": (avg["rx_avg"] if avg else r["net_rx_bps"]),
            "net_tx_bps": (avg["tx_avg"] if avg else r["net_tx_bps"]),
            "conn_count": int(avg["conn_avg"] if avg else r["conn_count"]),
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
            "podman_network_ok_v4": bool(r["podman_network_ok_v4"]),
            "podman_network_ok_v6": bool(r["podman_network_ok_v6"]),
            "timestamp": r["ts"],
            "timestamp_iso": datetime.fromtimestamp(r["ts"], tz=timezone.utc).isoformat(),
            "timestamp_iso_utc8": datetime.fromtimestamp(r["ts"], tz=UTC8).isoformat(),
            "alerts": {
                "disk": alert_disk,
                "stale": stale,
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
        SELECT ts, cpu_percent, net_rx_bps, net_tx_bps, conn_count
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
                    "timestamp_iso_utc8": datetime.fromtimestamp(r["ts"], tz=UTC8).isoformat(),
                    "cpu_percent": r["cpu_percent"],
                    "net_rx_bps": r["net_rx_bps"],
                    "net_tx_bps": r["net_tx_bps"],
                    "conn_count": r["conn_count"],
                }
                for r in rows
            ]
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
<p>每 15 秒自动刷新。CPU/连接数/网速展示最近 5 分钟平均值。红色表示预警。默认隐藏超时未上报容器（疑似历史数据）。</p>
<table id='t'><thead><tr><th>主机</th><th>容器ID</th><th>容器名</th><th>CPU%</th><th>连接数</th><th>RX Mbps</th><th>TX Mbps</th><th>Agent磁盘(容器内)</th><th>主盘(/data 总量/可用)</th><th>IPv4</th><th>IPv6</th><th>上报时间(UTC+8)</th><th>详情</th></tr></thead><tbody></tbody></table>
<div id='modal'><div id='card'>
  <h3 id='detail-title'></h3>
  <div class='detail-grid'>
    <div class='panel'>
      <h4>负载详情</h4>
      <div class='legend'>
        <span class='legend-item'><span class='dot' style='background:#4a90e2'></span>CPU%</span>
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
  return `${v.toFixed(v>=100?0:1)} ${units[i]}`;
}
function bpsToMbps(v){
  return (Number(v||0) * 8) / 1000 / 1000;
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
      const cls=(x.alerts.disk||x.alerts.stale||x.alerts.network)?'bad':'';
      const hostDiskText = `/data: ${fmtBytes(x.disk_data_total_bytes)} / ${fmtBytes(x.disk_data_avail_bytes)}`;
      const containerDiskText = `/: ${fmtBytes(x.container_fs_root_total_bytes)} / ${fmtBytes(x.container_fs_root_avail_bytes)}<br>/data: ${fmtBytes(x.container_fs_data_total_bytes)} / ${fmtBytes(x.container_fs_data_avail_bytes)}`;
      let html='';
      if(idx===0){
        html += `<td rowspan='${rows.length}'>${host}</td>`;
      }
      html += `<td>${x.container_id || '-'}</td><td>${x.container_name}</td><td class='${cls}'>${Number(x.cpu_percent||0).toFixed(2)}</td><td>${x.conn_count}</td><td>${bpsToMbps(x.net_rx_bps).toFixed(2)}</td><td>${bpsToMbps(x.net_tx_bps).toFixed(2)}</td><td>${containerDiskText}</td>`;
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
async function openDetail(host, container){
  const res=await fetch(`/api/v1/history?host_id=${encodeURIComponent(host)}&container_name=${encodeURIComponent(container)}`);
  const data=await res.json();
  document.getElementById('detail-title').innerText=`${host} / ${container} 历史数据`;
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
  const connVals=recent.map(x=>Number(x.conn_count||0));
  const rxMbpsVals=recent.map(x=>bpsToMbps(Number(x.net_rx_bps||0)));
  const txMbpsVals=recent.map(x=>bpsToMbps(Number(x.net_tx_bps||0)));
  const speedVals=rxMbpsVals.map((v,i)=>v+txMbpsVals[i]);
  let rxTotal=0; let txTotal=0;
  const rxBytesCum=recent.map(x=>{rxTotal+=Number(x.net_rx_bps||0)*300; return rxTotal;});
  const txBytesCum=recent.map(x=>{txTotal+=Number(x.net_tx_bps||0)*300; return txTotal;});

  drawAxes(svg,900,220);
  const cpuPoints=buildPolyline(cpuVals, Math.max(100, ...cpuVals), 900, 220, 20);
  const connPoints=buildPolyline(connVals, Math.max(1, ...connVals), 900, 220, 20);
  const speedPoints=buildPolyline(speedVals, Math.max(1, ...speedVals), 900, 220, 20);
  svg.innerHTML += `
    <polyline fill='none' stroke='#4a90e2' stroke-width='2.5' points='${cpuPoints}' />
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
