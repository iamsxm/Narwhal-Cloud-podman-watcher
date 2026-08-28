use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::process::Command;
use std::sync::Mutex;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct HostDiskInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    pub root_device: String,
    pub root_total_bytes: u64,
    pub root_avail_bytes: u64,
    pub data_mountpoint: String,
    pub data_total_bytes: u64,
    pub data_avail_bytes: u64,
    pub data_requested_path: String,
    pub size_bytes: u64,
    pub used_percent: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct FsUsage {
    pub total_bytes: u64,
    pub avail_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ContainerFs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<FsUsage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<FsUsage>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ContainerDiskPayload {
    pub rw_bytes: u64,
    pub rootfs_bytes: u64,
    pub fs: ContainerFs,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TopCpuProcess {
    pub pid: i64,
    pub cpu_percent: f64,
    pub command: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ContainerSecurity {
    pub inbound_unique_ips: u64,
    pub syn_recv_count: u64,
    pub inbound_connections: u64,
    pub outbound_connections: u64,
    pub unique_outbound_ips: u64,
    pub net_rx_pps: f64,
    pub net_tx_pps: f64,
    pub tcp_opens_per_sec: f64,
    pub tcp_fails_per_sec: f64,
    pub process_count: u64,
    pub suspicious_processes: Vec<serde_json::Value>,
    pub configuration_risks: Vec<serde_json::Value>,
    pub ports: Vec<serde_json::Value>,
    pub proxy_mappings: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub runtime: String,
    pub project: String,
    pub cpu_percent: f64,
    pub cpu_effective_cpus: f64,
    pub mem_bytes: u64,
    pub mem_limit_bytes: u64,
    pub mem_percent: f64,
    pub net_rx_bps: f64,
    pub net_tx_bps: f64,
    pub conn_count: u64,
    pub tcp_country_stats: Vec<serde_json::Value>,
    pub udp_country_stats: Vec<serde_json::Value>,
    pub disk: HostDiskInfo,
    pub container_disk: ContainerDiskPayload,
    pub top_cpu_process: TopCpuProcess,
    pub security: ContainerSecurity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct NetworkStatus {
    pub ipv4_ok: bool,
    pub ipv6_ok: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SecurityAlert {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub host_id: String,
    pub runtime: String,
    pub project: String,
    pub container_name: String,
    #[serde(rename = "type")]
    pub alert_type: String,
    pub severity: String,
    pub message: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SecurityStatus {
    pub enabled: bool,
    pub alerts: Vec<SecurityAlert>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ReportPayload {
    pub host_id: String,
    pub agent_version: String,
    pub timestamp: i64,
    pub container_network: NetworkStatus,
    pub containers: Vec<ContainerInfo>,
    pub security: SecurityStatus,
}

pub struct Collector {
    has_docker: bool,
    has_podman: bool,
    has_incus: bool,
    prev_net_io: Mutex<HashMap<String, (u64, u64, i64)>>, // name -> (rx_bytes, tx_bytes, timestamp)
}

impl Collector {
    pub fn new() -> Self {
        let has_cmd = |bin: &str| -> bool {
            Command::new("which")
                .arg(bin)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        };

        Self {
            has_docker: has_cmd("docker"),
            has_podman: has_cmd("podman"),
            has_incus: has_cmd("incus"),
            prev_net_io: Mutex::new(HashMap::new()),
        }
    }

    pub fn collect(&self, host_id: &str, version: &str, runtimes_config: &str, docker_mode: &str) -> ReportPayload {
        let now = chrono::Utc::now().timestamp();
        let mut containers = Vec::new();
        let host_disk = self.collect_host_disk();

        let allowed_runtimes = runtimes_config.to_lowercase();
        let auto = allowed_runtimes == "auto";

        if self.has_podman && (auto || allowed_runtimes.contains("podman")) {
            self.collect_podman_containers(&mut containers, &host_disk, now);
        }

        if self.has_docker && (auto || allowed_runtimes.contains("docker")) && docker_mode != "off" {
            self.collect_docker_containers(&mut containers, &host_disk, docker_mode == "full", now);
        }

        if self.has_incus && (auto || allowed_runtimes.contains("incus")) {
            self.collect_incus_containers(&mut containers, &host_disk);
        }

        let network_status = self.check_network();

        ReportPayload {
            host_id: host_id.to_string(),
            agent_version: version.to_string(),
            timestamp: now,
            container_network: network_status,
            containers,
            security: SecurityStatus {
                enabled: true,
                alerts: Vec::new(),
            },
        }
    }

    fn collect_host_disk(&self) -> HostDiskInfo {
        let mut info = HostDiskInfo {
            file: None,
            root_device: "/dev/root".to_string(),
            root_total_bytes: 0,
            root_avail_bytes: 0,
            data_mountpoint: "/".to_string(),
            data_total_bytes: 0,
            data_avail_bytes: 0,
            data_requested_path: "/".to_string(),
            size_bytes: 0,
            used_percent: 0.0,
        };

        if let Ok(out) = Command::new("df").args(["-P", "/"]).output() {
            if out.status.success() {
                let txt = String::from_utf8_lossy(&out.stdout);
                for line in txt.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 {
                        info.root_device = parts[0].to_string();
                        let total_kb: u64 = parts[1].parse().unwrap_or(0);
                        let avail_kb: u64 = parts[3].parse().unwrap_or(0);
                        let used_perc: f64 = parts[4].trim_end_matches('%').parse().unwrap_or(0.0);
                        info.root_total_bytes = total_kb * 1024;
                        info.root_avail_bytes = avail_kb * 1024;
                        info.data_total_bytes = info.root_total_bytes;
                        info.data_avail_bytes = info.root_avail_bytes;
                        info.size_bytes = info.root_total_bytes;
                        info.used_percent = used_perc;
                        break;
                    }
                }
            }
        }
        info
    }

    fn calculate_net_rates(&self, key: &str, cur_rx: u64, cur_tx: u64, now: i64) -> (f64, f64) {
        let mut map = self.prev_net_io.lock().unwrap();
        if let Some((prev_rx, prev_tx, prev_ts)) = map.get(key).copied() {
            let dt = (now - prev_ts).max(1) as f64;
            let rx_diff = cur_rx.saturating_sub(prev_rx) as f64;
            let tx_diff = cur_tx.saturating_sub(prev_tx) as f64;
            map.insert(key.to_string(), (cur_rx, cur_tx, now));
            (rx_diff / dt, tx_diff / dt)
        } else {
            map.insert(key.to_string(), (cur_rx, cur_tx, now));
            (0.0, 0.0)
        }
    }

    fn check_network(&self) -> NetworkStatus {
        let ipv4_ok = Command::new("curl")
            .args(["-4", "-s", "--max-time", "3", "https://ip.sb"])
            .output()
            .map(|o| o.status.success() && !o.stdout.is_empty())
            .unwrap_or(true);

        let ipv6_ok = Command::new("curl")
            .args(["-6", "-s", "--max-time", "3", "https://ip.sb"])
            .output()
            .map(|o| o.status.success() && !o.stdout.is_empty())
            .unwrap_or(false);

        NetworkStatus { ipv4_ok, ipv6_ok }
    }

    fn collect_docker_containers(&self, out: &mut Vec<ContainerInfo>, host_disk: &HostDiskInfo, is_full: bool, now: i64) {
        let output = match Command::new("docker")
            .args(["ps", "--format", "{{json .}}"])
            .output()
        {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => return,
        };

        let mut stats_map = HashMap::new();
        if is_full {
            if let Ok(stats_out) = Command::new("docker")
                .args(["stats", "--no-stream", "--format", "{{json .}}"])
                .output()
            {
                if stats_out.status.success() {
                    for line in String::from_utf8_lossy(&stats_out.stdout).lines() {
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
                            if let Some(name) = val.get("Name").and_then(|n| n.as_str()) {
                                stats_map.insert(name.to_string(), val);
                            }
                        }
                    }
                }
            }
        }

        for line in output.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
                let name = val.get("Names")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown")
                    .trim_start_matches('/')
                    .to_string();

                let id = val.get("ID").and_then(|i| i.as_str()).unwrap_or("").to_string();
                let image = val.get("Image").and_then(|i| i.as_str()).unwrap_or("").to_string();
                let status = val.get("Status").and_then(|s| s.as_str()).map(|s| s.to_string());

                let mut cpu_perc = 0.0;
                let mut mem_bytes = 0;
                let mut mem_limit_bytes = 0;
                let mut mem_perc = 0.0;
                let mut rx_bps = 0.0;
                let mut tx_bps = 0.0;
                let mut pids = 0;

                if let Some(stats) = stats_map.get(&name) {
                    if let Some(cpu_str) = stats.get("CPUPerc").and_then(|c| c.as_str()) {
                        cpu_perc = cpu_str.trim_end_matches('%').parse().unwrap_or(0.0);
                    }
                    if let Some(mem_str) = stats.get("MemPerc").and_then(|m| m.as_str()) {
                        mem_perc = mem_str.trim_end_matches('%').parse().unwrap_or(0.0);
                    }
                    if let Some(mem_usage) = stats.get("MemUsage").and_then(|m| m.as_str()) {
                        if let Some((used_part, total_part)) = mem_usage.split_once('/') {
                            mem_bytes = parse_size_bytes(used_part.trim());
                            mem_limit_bytes = parse_size_bytes(total_part.trim());
                            if mem_perc <= 0.0 && mem_limit_bytes > 0 {
                                mem_perc = (mem_bytes as f64 / mem_limit_bytes as f64) * 100.0;
                            }
                        }
                    }
                    if let Some(net_io) = stats.get("NetIO").and_then(|n| n.as_str()) {
                        if let Some((rx_part, tx_part)) = net_io.split_once('/') {
                            let total_rx = parse_size_bytes(rx_part.trim());
                            let total_tx = parse_size_bytes(tx_part.trim());
                            let (r_bps, t_bps) = self.calculate_net_rates(&format!("docker:{}", name), total_rx, total_tx, now);
                            rx_bps = r_bps;
                            tx_bps = t_bps;
                        }
                    }
                    if let Some(pids_str) = stats.get("PIDs").and_then(|p| p.as_str()) {
                        pids = pids_str.parse().unwrap_or(0);
                    }
                }

                let disk_info = get_container_disk_usage("docker", &name);

                out.push(ContainerInfo {
                    id,
                    name,
                    image,
                    runtime: "docker".to_string(),
                    project: "".to_string(),
                    cpu_percent: cpu_perc,
                    cpu_effective_cpus: 1.0,
                    mem_bytes,
                    mem_limit_bytes,
                    mem_percent: mem_perc,
                    net_rx_bps: rx_bps,
                    net_tx_bps: tx_bps,
                    conn_count: pids,
                    tcp_country_stats: Vec::new(),
                    udp_country_stats: Vec::new(),
                    disk: host_disk.clone(),
                    container_disk: disk_info,
                    top_cpu_process: TopCpuProcess::default(),
                    security: ContainerSecurity {
                        process_count: pids,
                        ..Default::default()
                    },
                    status,
                });
            }
        }
    }

    fn collect_podman_containers(&self, out: &mut Vec<ContainerInfo>, host_disk: &HostDiskInfo, now: i64) {
        let output = match Command::new("podman")
            .args(["ps", "--format", "json"])
            .output()
        {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => return,
        };

        let parsed: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap_or_default();

        let mut stats_map = HashMap::new();
        // 依次尝试 json 与 template 格式解析 podman stats
        if let Ok(stats_out) = Command::new("podman")
            .args(["stats", "--no-stream", "--format", "json"])
            .output()
        {
            if stats_out.status.success() {
                if let Ok(s_list) = serde_json::from_str::<Vec<serde_json::Value>>(&String::from_utf8_lossy(&stats_out.stdout)) {
                    for item in s_list {
                        if let Some(name) = item.get("Name").or_else(|| item.get("name")).and_then(|n| n.as_str()) {
                            stats_map.insert(name.to_string(), item);
                        }
                    }
                }
            }
        }

        // 如果 json stats 为空，尝试使用 format 模板字符串兜底
        if stats_map.is_empty() {
            if let Ok(tpl_out) = Command::new("podman")
                .args(["stats", "--no-stream", "--format", "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}|{{.NetIO}}|{{.PIDs}}"])
                .output()
            {
                if tpl_out.status.success() {
                    for line in String::from_utf8_lossy(&tpl_out.stdout).lines() {
                        let parts: Vec<&str> = line.split('|').collect();
                        if parts.len() >= 5 {
                            let mut map = serde_json::Map::new();
                            map.insert("Name".to_string(), serde_json::Value::String(parts[0].trim().to_string()));
                            map.insert("CPUPerc".to_string(), serde_json::Value::String(parts[1].trim().to_string()));
                            map.insert("MemUsage".to_string(), serde_json::Value::String(parts[2].trim().to_string()));
                            map.insert("MemPerc".to_string(), serde_json::Value::String(parts[3].trim().to_string()));
                            map.insert("NetIO".to_string(), serde_json::Value::String(parts[4].trim().to_string()));
                            if parts.len() >= 6 {
                                map.insert("PIDs".to_string(), serde_json::Value::String(parts[5].trim().to_string()));
                            }
                            stats_map.insert(parts[0].trim().to_string(), serde_json::Value::Object(map));
                        }
                    }
                }
            }
        }

        for item in parsed {
            let names = item.get("Names").and_then(|n| n.as_array());
            let name = names
                .and_then(|arr| arr.first())
                .and_then(|n| n.as_str())
                .or_else(|| item.get("Name").and_then(|n| n.as_str()))
                .or_else(|| item.get("names").and_then(|n| n.as_str()))
                .unwrap_or("unknown")
                .to_string();

            let id = item.get("Id")
                .or_else(|| item.get("ID"))
                .or_else(|| item.get("id"))
                .and_then(|i| i.as_str())
                .unwrap_or("")
                .chars()
                .take(12)
                .collect::<String>();

            let image = item.get("Image").or_else(|| item.get("image")).and_then(|i| i.as_str()).unwrap_or("").to_string();
            let status = item.get("State").or_else(|| item.get("Status")).or_else(|| item.get("state")).and_then(|s| s.as_str()).map(|s| s.to_string());

            let mut cpu_perc = 0.0;
            let mut mem_bytes = 0;
            let mut mem_limit_bytes = 0;
            let mut mem_perc = 0.0;
            let mut rx_bps = 0.0;
            let mut tx_bps = 0.0;
            let mut pids = 0;

            if let Some(stats) = stats_map.get(&name) {
                // CPU
                if let Some(cpu) = stats.get("CPUPerc").or_else(|| stats.get("CPU")).and_then(|c| c.as_str()) {
                    cpu_perc = cpu.trim_end_matches('%').trim().parse().unwrap_or(0.0);
                } else if let Some(cpu_num) = stats.get("CPU").or_else(|| stats.get("cpu_percent")).and_then(|c| c.as_f64()) {
                    cpu_perc = cpu_num;
                }

                // MemPerc
                if let Some(mem_p) = stats.get("MemPerc").and_then(|m| m.as_str()) {
                    mem_perc = mem_p.trim_end_matches('%').trim().parse().unwrap_or(0.0);
                } else if let Some(mem_p_num) = stats.get("MemPerc").and_then(|m| m.as_f64()) {
                    mem_perc = mem_p_num;
                }

                // MemUsage
                if let Some(mem_u) = stats.get("MemUsage").and_then(|m| m.as_str()) {
                    if let Some((used_part, total_part)) = mem_u.split_once('/') {
                        mem_bytes = parse_size_bytes(used_part.trim());
                        mem_limit_bytes = parse_size_bytes(total_part.trim());
                        if mem_perc <= 0.0 && mem_limit_bytes > 0 {
                            mem_perc = (mem_bytes as f64 / mem_limit_bytes as f64) * 100.0;
                        }
                    }
                } else if let Some(mem_b) = stats.get("MemUsageBytes").and_then(|m| m.as_u64()) {
                    mem_bytes = mem_b;
                }

                // NetIO
                if let Some(net) = stats.get("NetIO").and_then(|n| n.as_str()) {
                    if let Some((rx_part, tx_part)) = net.split_once('/') {
                        let total_rx = parse_size_bytes(rx_part.trim());
                        let total_tx = parse_size_bytes(tx_part.trim());
                        let (r_bps, t_bps) = self.calculate_net_rates(&format!("podman:{}", name), total_rx, total_tx, now);
                        rx_bps = r_bps;
                        tx_bps = t_bps;
                    }
                }

                // PIDs
                if let Some(p) = stats.get("PIDs").and_then(|p| p.as_u64()) {
                    pids = p;
                } else if let Some(p_str) = stats.get("PIDs").and_then(|p| p.as_str()) {
                    pids = p_str.trim().parse().unwrap_or(0);
                }
            }

            let disk_info = get_container_disk_usage("podman", &name);

            out.push(ContainerInfo {
                id,
                name,
                image,
                runtime: "podman".to_string(),
                project: "".to_string(),
                cpu_percent: cpu_perc,
                cpu_effective_cpus: 1.0,
                mem_bytes,
                mem_limit_bytes,
                mem_percent: mem_perc,
                net_rx_bps: rx_bps,
                net_tx_bps: tx_bps,
                conn_count: pids,
                tcp_country_stats: Vec::new(),
                udp_country_stats: Vec::new(),
                disk: host_disk.clone(),
                container_disk: disk_info,
                top_cpu_process: TopCpuProcess::default(),
                security: ContainerSecurity {
                    process_count: pids,
                    ..Default::default()
                },
                status,
            });
        }
    }

    fn collect_incus_containers(&self, out: &mut Vec<ContainerInfo>, host_disk: &HostDiskInfo) {
        let output = match Command::new("incus")
            .args(["list", "type=container", "status=running", "--format", "json"])
            .output()
        {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => return,
        };

        let parsed: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap_or_default();
        for item in parsed {
            let name = item.get("name").and_then(|n| n.as_str()).unwrap_or("unknown").to_string();
            let status = item.get("status").and_then(|s| s.as_str()).map(|s| s.to_string());
            let project = item.get("project").and_then(|p| p.as_str()).unwrap_or("default").to_string();

            let state = item.get("state").cloned().unwrap_or_default();
            let memory = state.get("memory").cloned().unwrap_or_default();
            let mem_bytes = memory.get("usage").and_then(|u| u.as_u64()).unwrap_or(0);
            let mem_total = memory.get("total").and_then(|t| t.as_u64()).unwrap_or(0);
            let mem_perc = if mem_total > 0 { (mem_bytes as f64 / mem_total as f64) * 100.0 } else { 0.0 };

            let disk_info = get_container_disk_usage("incus", &name);

            out.push(ContainerInfo {
                id: "".to_string(),
                name,
                image: "".to_string(),
                runtime: "incus".to_string(),
                project,
                cpu_percent: 0.0,
                cpu_effective_cpus: 1.0,
                mem_bytes,
                mem_limit_bytes: mem_total,
                mem_percent: mem_perc,
                net_rx_bps: 0.0,
                net_tx_bps: 0.0,
                conn_count: 0,
                tcp_country_stats: Vec::new(),
                udp_country_stats: Vec::new(),
                disk: host_disk.clone(),
                container_disk: disk_info,
                top_cpu_process: TopCpuProcess::default(),
                security: ContainerSecurity::default(),
                status,
            });
        }
    }
}

fn get_container_disk_usage(runtime: &str, container_name: &str) -> ContainerDiskPayload {
    let output = match runtime {
        "docker" => Command::new("docker").args(["exec", container_name, "df", "-P", "/"]).output().ok(),
        "podman" => Command::new("podman").args(["exec", container_name, "df", "-P", "/"]).output().ok(),
        "incus" => Command::new("incus").args(["exec", container_name, "--", "df", "-P", "/"]).output().ok(),
        _ => None,
    };

    let mut payload = ContainerDiskPayload {
        rw_bytes: 0,
        rootfs_bytes: 0,
        fs: ContainerFs {
            root: Some(FsUsage { total_bytes: 0, avail_bytes: 0 }),
            data: None,
        },
    };

    if let Some(out) = output {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    let total_kb: u64 = parts[1].parse().unwrap_or(0);
                    let avail_kb: u64 = parts[3].parse().unwrap_or(0);
                    payload.fs.root = Some(FsUsage {
                        total_bytes: total_kb * 1024,
                        avail_bytes: avail_kb * 1024,
                    });
                    break;
                }
            }
        }
    }

    payload
}

fn parse_size_bytes(s: &str) -> u64 {
    let s = s.trim();
    let re = regex::Regex::new(r"(?i)^([0-9.]+)\s*([a-z]*)$").ok();
    if let Some(r) = re {
        if let Some(cap) = r.captures(s) {
            let num: f64 = cap.get(1).map(|m| m.as_str().parse().unwrap_or(0.0)).unwrap_or(0.0);
            let unit = cap.get(2).map(|m| m.as_str().to_uppercase()).unwrap_or_default();
            let factor: f64 = match unit.as_str() {
                "B" => 1.0,
                "KB" | "KIB" | "K" => 1024.0,
                "MB" | "MIB" | "M" => 1024.0 * 1024.0,
                "GB" | "GIB" | "G" => 1024.0 * 1024.0 * 1024.0,
                "TB" | "TIB" | "T" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
                _ => 1.0,
            };
            return (num * factor) as u64;
        }
    }
    0
}
