use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ContainerDisk {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    pub size_bytes: u64,
    pub used_percent: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ContainerInfo {
    pub name: String,
    pub runtime: String,
    pub project: String,
    pub cpu_percent: f64,
    pub mem_bytes: u64,
    pub mem_percent: f64,
    pub net_rx_bps: f64,
    pub net_tx_bps: f64,
    pub conn_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk: Option<ContainerDisk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deep_sample: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
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
        }
    }

    pub fn collect(&self, host_id: &str, version: &str, runtimes_config: &str, docker_mode: &str) -> ReportPayload {
        let now = chrono::Utc::now().timestamp();
        let mut containers = Vec::new();

        let allowed_runtimes = runtimes_config.to_lowercase();
        let auto = allowed_runtimes == "auto";

        if self.has_podman && (auto || allowed_runtimes.contains("podman")) {
            self.collect_podman_containers(&mut containers);
        }

        if self.has_docker && (auto || allowed_runtimes.contains("docker")) && docker_mode != "off" {
            self.collect_docker_containers(&mut containers, docker_mode == "full");
        }

        if self.has_incus && (auto || allowed_runtimes.contains("incus")) {
            self.collect_incus_containers(&mut containers);
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

    fn collect_docker_containers(&self, out: &mut Vec<ContainerInfo>, is_full: bool) {
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

                let image = val.get("Image").and_then(|i| i.as_str()).map(|s| s.to_string());
                let status = val.get("Status").and_then(|s| s.as_str()).map(|s| s.to_string());

                let mut cpu_perc = 0.0;
                let mut mem_bytes = 0;
                let mut mem_perc = 0.0;
                let mut rx_bps = 0.0;
                let mut tx_bps = 0.0;

                if let Some(stats) = stats_map.get(&name) {
                    if let Some(cpu_str) = stats.get("CPUPerc").and_then(|c| c.as_str()) {
                        cpu_perc = cpu_str.trim_end_matches('%').parse().unwrap_or(0.0);
                    }
                    if let Some(mem_str) = stats.get("MemPerc").and_then(|m| m.as_str()) {
                        mem_perc = mem_str.trim_end_matches('%').parse().unwrap_or(0.0);
                    }
                    if let Some(mem_usage) = stats.get("MemUsage").and_then(|m| m.as_str()) {
                        if let Some((used_part, _)) = mem_usage.split_once('/') {
                            mem_bytes = parse_size_bytes(used_part.trim());
                        }
                    }
                    if let Some(net_io) = stats.get("NetIO").and_then(|n| n.as_str()) {
                        if let Some((rx_part, tx_part)) = net_io.split_once('/') {
                            rx_bps = parse_size_bytes(rx_part.trim()) as f64;
                            tx_bps = parse_size_bytes(tx_part.trim()) as f64;
                        }
                    }
                }

                let disk_info = get_container_df("docker", &name);

                out.push(ContainerInfo {
                    name,
                    runtime: "docker".to_string(),
                    project: "".to_string(),
                    cpu_percent: cpu_perc,
                    mem_bytes,
                    mem_percent: mem_perc,
                    net_rx_bps: rx_bps,
                    net_tx_bps: tx_bps,
                    conn_count: 0,
                    disk: disk_info,
                    deep_sample: None,
                    image,
                    status,
                });
            }
        }
    }

    fn collect_podman_containers(&self, out: &mut Vec<ContainerInfo>) {
        let output = match Command::new("podman")
            .args(["ps", "--format", "json"])
            .output()
        {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => return,
        };

        let parsed: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap_or_default();

        let mut stats_map = HashMap::new();
        if let Ok(stats_out) = Command::new("podman")
            .args(["stats", "--no-stream", "--format", "json"])
            .output()
        {
            if stats_out.status.success() {
                if let Ok(s_list) = serde_json::from_str::<Vec<serde_json::Value>>(&String::from_utf8_lossy(&stats_out.stdout)) {
                    for item in s_list {
                        if let Some(name) = item.get("Name").and_then(|n| n.as_str()) {
                            stats_map.insert(name.to_string(), item);
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
                .unwrap_or("unknown")
                .to_string();

            let image = item.get("Image").and_then(|i| i.as_str()).map(|s| s.to_string());
            let status = item.get("State").or_else(|| item.get("Status")).and_then(|s| s.as_str()).map(|s| s.to_string());

            let mut cpu_perc = 0.0;
            let mut mem_bytes = 0;
            let mut mem_perc = 0.0;
            let mut rx_bps = 0.0;
            let mut tx_bps = 0.0;

            if let Some(stats) = stats_map.get(&name) {
                if let Some(cpu) = stats.get("CPUPerc").and_then(|c| c.as_str()) {
                    cpu_perc = cpu.trim_end_matches('%').parse().unwrap_or(0.0);
                } else if let Some(cpu_num) = stats.get("CPU").and_then(|c| c.as_f64()) {
                    cpu_perc = cpu_num;
                }
                if let Some(mem_p) = stats.get("MemPerc").and_then(|m| m.as_str()) {
                    mem_perc = mem_p.trim_end_matches('%').parse().unwrap_or(0.0);
                }
                if let Some(mem_u) = stats.get("MemUsage").and_then(|m| m.as_str()) {
                    if let Some((used_part, _)) = mem_u.split_once('/') {
                        mem_bytes = parse_size_bytes(used_part.trim());
                    }
                }
                if let Some(net) = stats.get("NetIO").and_then(|n| n.as_str()) {
                    if let Some((rx_part, tx_part)) = net.split_once('/') {
                        rx_bps = parse_size_bytes(rx_part.trim()) as f64;
                        tx_bps = parse_size_bytes(tx_part.trim()) as f64;
                    }
                }
            }

            let disk_info = get_container_df("podman", &name);

            out.push(ContainerInfo {
                name,
                runtime: "podman".to_string(),
                project: "".to_string(),
                cpu_percent: cpu_perc,
                mem_bytes,
                mem_percent: mem_perc,
                net_rx_bps: rx_bps,
                net_tx_bps: tx_bps,
                conn_count: 0,
                disk: disk_info,
                deep_sample: None,
                image,
                status,
            });
        }
    }

    fn collect_incus_containers(&self, out: &mut Vec<ContainerInfo>) {
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

            let disk_info = get_container_df("incus", &name);

            out.push(ContainerInfo {
                name,
                runtime: "incus".to_string(),
                project,
                cpu_percent: 0.0,
                mem_bytes,
                mem_percent: mem_perc,
                net_rx_bps: 0.0,
                net_tx_bps: 0.0,
                conn_count: 0,
                disk: disk_info,
                deep_sample: None,
                image: None,
                status,
            });
        }
    }
}

fn get_container_df(runtime: &str, container_name: &str) -> Option<ContainerDisk> {
    let output = match runtime {
        "docker" => Command::new("docker").args(["exec", container_name, "df", "-P", "/"]).output().ok()?,
        "podman" => Command::new("podman").args(["exec", container_name, "df", "-P", "/"]).output().ok()?,
        "incus" => Command::new("incus").args(["exec", container_name, "--", "df", "-P", "/"]).output().ok()?,
        _ => return None,
    };

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            let size_kb: u64 = parts[1].parse().unwrap_or(0);
            let used_perc: f64 = parts[4].trim_end_matches('%').parse().unwrap_or(0.0);
            return Some(ContainerDisk {
                file: Some("/".to_string()),
                size_bytes: size_kb * 1024,
                used_percent: used_perc,
            });
        }
    }
    None
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
