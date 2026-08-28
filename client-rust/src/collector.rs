use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
    pub inbound_unique_ip_threshold: u64,
    pub inbound_ip_observation: String,
    pub inbound_top_ips: Vec<serde_json::Value>,
    pub syn_recv_count: u64,
    pub incoming_established: u64,
    pub outgoing_established: u64,
    pub outbound_unique_ips: u64,
    pub net_rx_pps: f64,
    pub net_tx_pps: f64,
    pub process_count: u64,
    pub suspicious_processes: Vec<serde_json::Value>,
    pub configuration_risks: Vec<serde_json::Value>,
    pub listening_ports: Vec<u16>,
    pub network_exposure: Vec<serde_json::Value>,
    pub protocol_rates: HashMap<String, f64>,
    pub panel_pairing: serde_json::Value,
    pub socks_proxy: serde_json::Value,
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
    pub agent_kind: String,
    pub timestamp: i64,
    pub container_network: NetworkStatus,
    pub containers: Vec<ContainerInfo>,
    pub security: SecurityStatus,
}

#[derive(Debug, Clone, Default, PartialEq)]
struct RuntimeStats {
    cpu_percent: f64,
    cpu_effective_cpus: f64,
    mem_bytes: u64,
    mem_limit_bytes: u64,
    mem_percent: f64,
    net_rx_total_bytes: u64,
    net_tx_total_bytes: u64,
    net_rx_total_packets: u64,
    net_tx_total_packets: u64,
    pids: u64,
}

#[derive(Debug, Clone, Default)]
struct IncusMetrics {
    cpu_seconds: f64,
    effective_cpus: f64,
    mem_total_bytes: u64,
    mem_available_bytes: Option<u64>,
    net_rx_total_bytes: u64,
    net_tx_total_bytes: u64,
    net_rx_total_packets: u64,
    net_tx_total_packets: u64,
    fs_total_bytes: u64,
    fs_avail_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq)]
struct ProcTelemetry {
    net_rx_total_bytes: u64,
    net_tx_total_bytes: u64,
    net_rx_total_packets: u64,
    net_tx_total_packets: u64,
    connection_count: u64,
    syn_recv_count: u64,
    incoming_established: u64,
    outgoing_established: u64,
    inbound_unique_ips: u64,
    outbound_unique_ips: u64,
    inbound_ip_counts: HashMap<IpAddr, u64>,
    tcp_remote_ip_counts: HashMap<IpAddr, u64>,
    udp_remote_ip_counts: HashMap<IpAddr, u64>,
    listening_ports: Vec<u16>,
    protocol_counters: HashMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq)]
struct SocketEntry {
    protocol: String,
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
    state: u8,
}

pub struct Collector {
    has_docker: bool,
    has_podman: bool,
    has_incus: bool,
    prev_net_io: Mutex<HashMap<String, (u64, u64, i64)>>,
    prev_packet_io: Mutex<HashMap<String, (u64, u64, i64)>>,
    prev_cpu: Mutex<HashMap<String, (f64, i64)>>,
    prev_protocol: Mutex<HashMap<String, (HashMap<String, u64>, i64)>>,
    geoip_country_cache: Mutex<HashMap<String, String>>,
    geoip_agent: ureq::Agent,
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
            prev_packet_io: Mutex::new(HashMap::new()),
            prev_cpu: Mutex::new(HashMap::new()),
            prev_protocol: Mutex::new(HashMap::new()),
            geoip_country_cache: Mutex::new(HashMap::new()),
            geoip_agent: ureq::AgentBuilder::new()
                .timeout_connect(std::time::Duration::from_secs(3))
                .timeout_read(std::time::Duration::from_secs(8))
                .timeout_write(std::time::Duration::from_secs(8))
                .build(),
        }
    }

    pub fn collect(
        &self,
        host_id: &str,
        version: &str,
        runtimes_config: &str,
        docker_mode: &str,
    ) -> ReportPayload {
        let now = chrono::Utc::now().timestamp();
        let mut containers = Vec::new();
        let host_disk = self.collect_host_disk();

        let allowed_runtimes = runtimes_config.to_lowercase();
        let auto = allowed_runtimes == "auto";

        if self.has_podman && (auto || allowed_runtimes.contains("podman")) {
            self.collect_podman_containers(&mut containers, &host_disk, now);
        }

        if self.has_docker && (auto || allowed_runtimes.contains("docker")) && docker_mode != "off"
        {
            self.collect_docker_containers(&mut containers, &host_disk, docker_mode == "full", now);
        }

        if self.has_incus && (auto || allowed_runtimes.contains("incus")) {
            self.collect_incus_containers(&mut containers, &host_disk, now);
        }

        let network_status = self.check_network();

        ReportPayload {
            host_id: host_id.to_string(),
            agent_version: version.to_string(),
            agent_kind: "rust".to_string(),
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
        calculate_counter_rates(&self.prev_net_io, key, cur_rx, cur_tx, now)
    }

    fn calculate_packet_rates(&self, key: &str, cur_rx: u64, cur_tx: u64, now: i64) -> (f64, f64) {
        calculate_counter_rates(&self.prev_packet_io, key, cur_rx, cur_tx, now)
    }

    fn calculate_cpu_percent(&self, key: &str, cpu_seconds: f64, now: i64) -> f64 {
        let mut map = self.prev_cpu.lock().unwrap();
        if let Some((prev_cpu, prev_ts)) = map.get(key).copied() {
            let dt = now - prev_ts;
            map.insert(key.to_string(), (cpu_seconds, now));
            if dt <= 0 {
                return 0.0;
            }
            ((cpu_seconds - prev_cpu).max(0.0) / dt as f64) * 100.0
        } else {
            map.insert(key.to_string(), (cpu_seconds, now));
            0.0
        }
    }

    fn calculate_protocol_rates(
        &self,
        key: &str,
        counters: &HashMap<String, u64>,
        now: i64,
    ) -> HashMap<String, f64> {
        let mut state = self.prev_protocol.lock().unwrap();
        let previous = state.get(key).cloned();
        state.insert(key.to_string(), (counters.clone(), now));
        let Some((previous_values, previous_ts)) = previous else {
            return counters
                .keys()
                .map(|name| (format!("{}_per_second", name), 0.0))
                .collect();
        };
        let elapsed = now - previous_ts;
        counters
            .iter()
            .map(|(name, value)| {
                let rate = if elapsed > 0 {
                    value.saturating_sub(*previous_values.get(name).unwrap_or(value)) as f64
                        / elapsed as f64
                } else {
                    0.0
                };
                (format!("{}_per_second", name), rate)
            })
            .collect()
    }

    fn country_stats(&self, ip_counts: &HashMap<IpAddr, u64>) -> Vec<serde_json::Value> {
        if ip_counts.is_empty() {
            return Vec::new();
        }
        let unresolved: Vec<String> = {
            let cache = self.geoip_country_cache.lock().unwrap();
            ip_counts
                .keys()
                .map(ToString::to_string)
                .filter(|ip| !cache.contains_key(ip))
                .take(100)
                .collect()
        };
        if !unresolved.is_empty() {
            let payload: Vec<serde_json::Value> = unresolved
                .iter()
                .map(|ip| serde_json::json!({"query": ip}))
                .collect();
            let resolved = self
                .geoip_agent
                .post("http://ip-api.com/batch?fields=status,query,countryCode")
                .send_json(serde_json::Value::Array(payload))
                .ok()
                .and_then(|response| response.into_json::<Vec<serde_json::Value>>().ok())
                .unwrap_or_default();
            let mut cache = self.geoip_country_cache.lock().unwrap();
            for item in resolved {
                let Some(ip) = item.get("query").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                let country =
                    if item.get("status").and_then(serde_json::Value::as_str) == Some("success") {
                        item.get("countryCode")
                            .and_then(serde_json::Value::as_str)
                            .filter(|value| !value.is_empty())
                            .unwrap_or("UN")
                    } else {
                        "UN"
                    };
                cache.insert(ip.to_string(), country.to_string());
            }
            for ip in unresolved {
                cache.entry(ip).or_insert_with(|| "UN".to_string());
            }
        }

        let cache = self.geoip_country_cache.lock().unwrap();
        let mut countries: HashMap<String, (u64, u64)> = HashMap::new();
        for (ip, connections) in ip_counts {
            let country = cache
                .get(&ip.to_string())
                .cloned()
                .unwrap_or_else(|| "UN".to_string());
            let entry = countries.entry(country).or_default();
            entry.0 = entry.0.saturating_add(*connections);
            entry.1 = entry.1.saturating_add(1);
        }
        let mut result: Vec<serde_json::Value> = countries
            .into_iter()
            .map(|(country, (connections, ip_count))| {
                serde_json::json!({
                    "country": country,
                    "connections": connections,
                    "ip_count": ip_count,
                })
            })
            .collect();
        result.sort_by_key(|item| std::cmp::Reverse(item["connections"].as_u64().unwrap_or(0)));
        result
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

    fn collect_docker_containers(
        &self,
        out: &mut Vec<ContainerInfo>,
        host_disk: &HostDiskInfo,
        is_full: bool,
        now: i64,
    ) {
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
                let name = val
                    .get("Names")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown")
                    .trim_start_matches('/')
                    .to_string();

                let id = val
                    .get("ID")
                    .and_then(|i| i.as_str())
                    .unwrap_or("")
                    .to_string();
                let image = val
                    .get("Image")
                    .and_then(|i| i.as_str())
                    .unwrap_or("")
                    .to_string();
                let status = val
                    .get("Status")
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string());

                let mut stats = stats_map
                    .get(&name)
                    .map(parse_runtime_stats)
                    .unwrap_or_default();
                let inspect = if is_full {
                    inspect_oci_container("docker", &name)
                } else {
                    serde_json::Value::Null
                };
                let pid = container_pid(&inspect);
                let proc_stats = collect_proc_telemetry(pid);
                stats.merge_proc_network(&proc_stats);
                let key = format!("docker:{}", name);
                let (rx_bps, tx_bps) = self.calculate_net_rates(
                    &key,
                    stats.net_rx_total_bytes,
                    stats.net_tx_total_bytes,
                    now,
                );
                let (rx_pps, tx_pps) = self.calculate_packet_rates(
                    &key,
                    stats.net_rx_total_packets,
                    stats.net_tx_total_packets,
                    now,
                );
                let protocol_rates =
                    self.calculate_protocol_rates(&key, &proc_stats.protocol_counters, now);
                let process_count = stats.pids.max(read_process_count(pid));
                let mut security = build_container_security(
                    &proc_stats,
                    rx_pps,
                    tx_pps,
                    process_count,
                    protocol_rates,
                    &inspect,
                );
                security.suspicious_processes = collect_suspicious_processes("docker", &name, "");

                let disk_info = get_container_disk_usage("docker", &name);
                let top_cpu_process = collect_top_cpu_process("docker", &name, "");

                out.push(ContainerInfo {
                    id,
                    name,
                    image,
                    runtime: "docker".to_string(),
                    project: "".to_string(),
                    cpu_percent: stats.cpu_percent,
                    cpu_effective_cpus: stats.cpu_effective_cpus.max(1.0),
                    mem_bytes: stats.mem_bytes,
                    mem_limit_bytes: stats.mem_limit_bytes,
                    mem_percent: stats.mem_percent,
                    net_rx_bps: rx_bps,
                    net_tx_bps: tx_bps,
                    conn_count: proc_stats.connection_count,
                    tcp_country_stats: self.country_stats(&proc_stats.tcp_remote_ip_counts),
                    udp_country_stats: self.country_stats(&proc_stats.udp_remote_ip_counts),
                    disk: host_disk.clone(),
                    container_disk: disk_info,
                    top_cpu_process,
                    security,
                    status,
                });
            }
        }
    }

    fn collect_podman_containers(
        &self,
        out: &mut Vec<ContainerInfo>,
        host_disk: &HostDiskInfo,
        now: i64,
    ) {
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
                if let Ok(s_list) = serde_json::from_str::<Vec<serde_json::Value>>(
                    &String::from_utf8_lossy(&stats_out.stdout),
                ) {
                    for item in s_list {
                        if let Some(name) = item
                            .get("Name")
                            .or_else(|| item.get("name"))
                            .and_then(|n| n.as_str())
                        {
                            stats_map.insert(name.to_string(), item);
                        }
                    }
                }
            }
        }

        // JSON 与模板结果同时解析并按字段合并，避免“JSON 非空但字段不兼容”时跳过兜底。
        let mut template_stats_map = HashMap::new();
        for template in [
            "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}|{{.NetIO}}|{{.PIDs}}",
            "{{.Name}}|{{.CPU}}|{{.MemUsage}}||{{.NetIO}}|{{.PIDs}}",
        ] {
            let Ok(tpl_out) = Command::new("podman")
                .args(["stats", "--no-stream", "--format", template])
                .output()
            else {
                continue;
            };
            if !tpl_out.status.success() || tpl_out.stdout.is_empty() {
                continue;
            }
            for line in String::from_utf8_lossy(&tpl_out.stdout).lines() {
                if let Some((name, stats)) = parse_stats_template_line(line) {
                    template_stats_map.insert(name, stats);
                }
            }
            if !template_stats_map.is_empty() {
                break;
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

            let id = item
                .get("Id")
                .or_else(|| item.get("ID"))
                .or_else(|| item.get("id"))
                .and_then(|i| i.as_str())
                .unwrap_or("")
                .chars()
                .take(12)
                .collect::<String>();

            let image = item
                .get("Image")
                .or_else(|| item.get("image"))
                .and_then(|i| i.as_str())
                .unwrap_or("")
                .to_string();
            let status = item
                .get("State")
                .or_else(|| item.get("Status"))
                .or_else(|| item.get("state"))
                .and_then(|s| s.as_str())
                .map(|s| s.to_string());

            let mut stats = stats_map
                .get(&name)
                .map(parse_runtime_stats)
                .unwrap_or_default();
            if let Some(fallback) = template_stats_map.get(&name) {
                stats.merge_missing(fallback);
            }
            if stats.is_empty() {
                eprintln!(
                    "warn: podman stats for '{}' had no compatible CPU/memory/network fields",
                    name
                );
            }
            let inspect = inspect_oci_container("podman", &name);
            let pid = container_pid(&inspect);
            let proc_stats = collect_proc_telemetry(pid);
            stats.merge_proc_network(&proc_stats);
            let key = format!("podman:{}", name);
            let (rx_bps, tx_bps) = self.calculate_net_rates(
                &key,
                stats.net_rx_total_bytes,
                stats.net_tx_total_bytes,
                now,
            );
            let (rx_pps, tx_pps) = self.calculate_packet_rates(
                &key,
                stats.net_rx_total_packets,
                stats.net_tx_total_packets,
                now,
            );
            let protocol_rates =
                self.calculate_protocol_rates(&key, &proc_stats.protocol_counters, now);
            let process_count = stats.pids.max(read_process_count(pid));
            let mut security = build_container_security(
                &proc_stats,
                rx_pps,
                tx_pps,
                process_count,
                protocol_rates,
                &inspect,
            );
            security.suspicious_processes = collect_suspicious_processes("podman", &name, "");

            let disk_info = get_container_disk_usage("podman", &name);
            let top_cpu_process = collect_top_cpu_process("podman", &name, "");

            out.push(ContainerInfo {
                id,
                name,
                image,
                runtime: "podman".to_string(),
                project: "".to_string(),
                cpu_percent: stats.cpu_percent,
                cpu_effective_cpus: stats.cpu_effective_cpus.max(1.0),
                mem_bytes: stats.mem_bytes,
                mem_limit_bytes: stats.mem_limit_bytes,
                mem_percent: stats.mem_percent,
                net_rx_bps: rx_bps,
                net_tx_bps: tx_bps,
                conn_count: proc_stats.connection_count,
                tcp_country_stats: self.country_stats(&proc_stats.tcp_remote_ip_counts),
                udp_country_stats: self.country_stats(&proc_stats.udp_remote_ip_counts),
                disk: host_disk.clone(),
                container_disk: disk_info,
                top_cpu_process,
                security,
                status,
            });
        }
    }

    fn collect_incus_containers(
        &self,
        out: &mut Vec<ContainerInfo>,
        host_disk: &HostDiskInfo,
        now: i64,
    ) {
        let output = match Command::new("incus")
            .args([
                "list",
                "type=container",
                "status=running",
                "--format",
                "json",
            ])
            .output()
        {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => return,
        };

        let parsed: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap_or_default();
        let metrics = Command::new("incus")
            .args(["query", "/1.0/metrics"])
            .output()
            .ok()
            .filter(|result| result.status.success())
            .map(|result| parse_incus_metrics(&String::from_utf8_lossy(&result.stdout)))
            .unwrap_or_default();

        for item in parsed {
            let name = item
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("unknown")
                .to_string();
            let status = item
                .get("status")
                .and_then(|s| s.as_str())
                .map(|s| s.to_string());
            let project = item
                .get("project")
                .and_then(|p| p.as_str())
                .unwrap_or("default")
                .to_string();
            let metric = metrics
                .get(&(project.clone(), name.clone()))
                .cloned()
                .unwrap_or_default();
            let state = item.get("state").cloned().unwrap_or_default();
            let memory = state.get("memory").cloned().unwrap_or_default();
            let state_mem_bytes = memory
                .get("usage")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            let state_mem_total = memory
                .get("total")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            let mem_total = metric.mem_total_bytes.max(state_mem_total);
            let mem_bytes = metric
                .mem_available_bytes
                .map(|available| mem_total.saturating_sub(available.min(mem_total)))
                .unwrap_or(state_mem_bytes);
            let mem_perc = percentage(mem_bytes, mem_total);
            let key = format!("incus:{}:{}", project, name);
            let cpu_percent = self.calculate_cpu_percent(&key, metric.cpu_seconds, now);
            let pid = state
                .get("pid")
                .and_then(|value| value.as_i64())
                .unwrap_or(0);
            let proc_stats = collect_proc_telemetry(pid);
            let net_rx_total = if metric.net_rx_total_bytes > 0 || metric.net_tx_total_bytes > 0 {
                metric.net_rx_total_bytes
            } else {
                proc_stats.net_rx_total_bytes
            };
            let net_tx_total = if metric.net_rx_total_bytes > 0 || metric.net_tx_total_bytes > 0 {
                metric.net_tx_total_bytes
            } else {
                proc_stats.net_tx_total_bytes
            };
            let packet_rx_total =
                if metric.net_rx_total_packets > 0 || metric.net_tx_total_packets > 0 {
                    metric.net_rx_total_packets
                } else {
                    proc_stats.net_rx_total_packets
                };
            let packet_tx_total =
                if metric.net_rx_total_packets > 0 || metric.net_tx_total_packets > 0 {
                    metric.net_tx_total_packets
                } else {
                    proc_stats.net_tx_total_packets
                };
            let (rx_bps, tx_bps) = self.calculate_net_rates(&key, net_rx_total, net_tx_total, now);
            let (rx_pps, tx_pps) =
                self.calculate_packet_rates(&key, packet_rx_total, packet_tx_total, now);
            let protocol_rates =
                self.calculate_protocol_rates(&key, &proc_stats.protocol_counters, now);
            let process_count = read_process_count(pid);
            let mut security = build_container_security(
                &proc_stats,
                rx_pps,
                tx_pps,
                process_count,
                protocol_rates,
                &serde_json::Value::Null,
            );
            security.configuration_risks = incus_configuration_risks(&item);
            security.network_exposure = incus_network_exposure(&item);
            security.suspicious_processes = collect_suspicious_processes("incus", &name, &project);

            let mut disk_info = get_container_disk_usage("incus", &name);
            if metric.fs_total_bytes > 0 {
                disk_info.fs.root = Some(FsUsage {
                    total_bytes: metric.fs_total_bytes,
                    avail_bytes: metric.fs_avail_bytes,
                });
            }
            let top_cpu_process = collect_top_cpu_process("incus", &name, &project);

            out.push(ContainerInfo {
                id: name.clone(),
                name,
                image: incus_image_name(&item),
                runtime: "incus".to_string(),
                project,
                cpu_percent,
                cpu_effective_cpus: metric.effective_cpus,
                mem_bytes,
                mem_limit_bytes: mem_total,
                mem_percent: mem_perc,
                net_rx_bps: rx_bps,
                net_tx_bps: tx_bps,
                conn_count: proc_stats.connection_count,
                tcp_country_stats: self.country_stats(&proc_stats.tcp_remote_ip_counts),
                udp_country_stats: self.country_stats(&proc_stats.udp_remote_ip_counts),
                disk: host_disk.clone(),
                container_disk: disk_info,
                top_cpu_process,
                security,
                status,
            });
        }
    }
}

impl RuntimeStats {
    fn merge_missing(&mut self, fallback: &Self) {
        if self.cpu_percent <= 0.0 {
            self.cpu_percent = fallback.cpu_percent;
        }
        if self.cpu_effective_cpus <= 0.0 {
            self.cpu_effective_cpus = fallback.cpu_effective_cpus;
        }
        if self.mem_bytes == 0 {
            self.mem_bytes = fallback.mem_bytes;
        }
        if self.mem_limit_bytes == 0 {
            self.mem_limit_bytes = fallback.mem_limit_bytes;
        }
        if self.mem_percent <= 0.0 {
            self.mem_percent = fallback.mem_percent;
        }
        if self.net_rx_total_bytes == 0 {
            self.net_rx_total_bytes = fallback.net_rx_total_bytes;
        }
        if self.net_tx_total_bytes == 0 {
            self.net_tx_total_bytes = fallback.net_tx_total_bytes;
        }
        if self.net_rx_total_packets == 0 {
            self.net_rx_total_packets = fallback.net_rx_total_packets;
        }
        if self.net_tx_total_packets == 0 {
            self.net_tx_total_packets = fallback.net_tx_total_packets;
        }
        if self.pids == 0 {
            self.pids = fallback.pids;
        }
        if self.mem_percent <= 0.0 {
            self.mem_percent = percentage(self.mem_bytes, self.mem_limit_bytes);
        }
    }

    fn is_empty(&self) -> bool {
        self.cpu_percent <= 0.0
            && self.mem_bytes == 0
            && self.mem_limit_bytes == 0
            && self.net_rx_total_bytes == 0
            && self.net_tx_total_bytes == 0
    }

    fn merge_proc_network(&mut self, proc_stats: &ProcTelemetry) {
        if self.net_rx_total_bytes == 0 && self.net_tx_total_bytes == 0 {
            self.net_rx_total_bytes = proc_stats.net_rx_total_bytes;
            self.net_tx_total_bytes = proc_stats.net_tx_total_bytes;
        }
        if self.net_rx_total_packets == 0 && self.net_tx_total_packets == 0 {
            self.net_rx_total_packets = proc_stats.net_rx_total_packets;
            self.net_tx_total_packets = proc_stats.net_tx_total_packets;
        }
    }
}

fn calculate_counter_rates(
    state: &Mutex<HashMap<String, (u64, u64, i64)>>,
    key: &str,
    current_rx: u64,
    current_tx: u64,
    now: i64,
) -> (f64, f64) {
    let mut map = state.lock().unwrap();
    if let Some((previous_rx, previous_tx, previous_ts)) = map.get(key).copied() {
        let elapsed = now - previous_ts;
        map.insert(key.to_string(), (current_rx, current_tx, now));
        if elapsed <= 0 {
            return (0.0, 0.0);
        }
        (
            current_rx.saturating_sub(previous_rx) as f64 / elapsed as f64,
            current_tx.saturating_sub(previous_tx) as f64 / elapsed as f64,
        )
    } else {
        map.insert(key.to_string(), (current_rx, current_tx, now));
        (0.0, 0.0)
    }
}

fn normalize_key(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn find_value<'a>(value: &'a serde_json::Value, aliases: &[&str]) -> Option<&'a serde_json::Value> {
    let object = value.as_object()?;
    let normalized_aliases: Vec<String> =
        aliases.iter().map(|alias| normalize_key(alias)).collect();
    object.iter().find_map(|(key, item)| {
        normalized_aliases
            .contains(&normalize_key(key))
            .then_some(item)
    })
}

fn value_number(value: Option<&serde_json::Value>) -> f64 {
    match value {
        Some(serde_json::Value::Number(number)) => number.as_f64().unwrap_or(0.0),
        Some(serde_json::Value::String(text)) => text
            .trim()
            .trim_end_matches('%')
            .trim()
            .parse()
            .unwrap_or(0.0),
        _ => 0.0,
    }
}

fn value_size(value: Option<&serde_json::Value>) -> u64 {
    match value {
        Some(serde_json::Value::Number(number)) => number
            .as_u64()
            .unwrap_or_else(|| number.as_f64().unwrap_or(0.0).max(0.0) as u64),
        Some(serde_json::Value::String(text)) => parse_size_bytes(text),
        _ => 0,
    }
}

fn percentage(used: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (used as f64 / total as f64) * 100.0
    }
}

fn parse_size_pair(value: Option<&serde_json::Value>) -> (u64, u64) {
    let Some(text) = value.and_then(serde_json::Value::as_str) else {
        return (0, 0);
    };
    let Some((left, right)) = text.split_once('/') else {
        return (parse_size_bytes(text), 0);
    };
    (parse_size_bytes(left), parse_size_bytes(right))
}

fn parse_runtime_stats(value: &serde_json::Value) -> RuntimeStats {
    let mut stats = RuntimeStats {
        cpu_percent: value_number(find_value(
            value,
            &["CPU", "CPUPerc", "CPU%", "cpu_percent"],
        )),
        cpu_effective_cpus: value_number(find_value(
            value,
            &["cpu_effective_cpus", "effective_cpus"],
        )),
        mem_percent: value_number(find_value(
            value,
            &["MemPerc", "Mem%", "mem_percent", "memory_percent"],
        )),
        pids: value_number(find_value(value, &["PIDs", "processes"])).max(0.0) as u64,
        ..Default::default()
    };

    let (combined_mem, combined_limit) = parse_size_pair(find_value(
        value,
        &["MemUsage", "Mem Usage", "mem_usage", "memory"],
    ));
    stats.mem_bytes = combined_mem.max(value_size(find_value(
        value,
        &["MemUsageBytes", "mem_usage_bytes", "memory_bytes"],
    )));
    stats.mem_limit_bytes = combined_limit.max(value_size(find_value(
        value,
        &["MemLimit", "MemLimitBytes", "mem_limit", "memory_limit"],
    )));
    if stats.mem_percent <= 0.0 {
        stats.mem_percent = percentage(stats.mem_bytes, stats.mem_limit_bytes);
    }

    let (combined_rx, combined_tx) =
        parse_size_pair(find_value(value, &["NetIO", "Net I/O", "net_io"]));
    stats.net_rx_total_bytes = combined_rx.max(value_size(find_value(
        value,
        &["NetInput", "Net In", "net_input", "rxbytes", "rx"],
    )));
    stats.net_tx_total_bytes = combined_tx.max(value_size(find_value(
        value,
        &["NetOutput", "Net Out", "net_output", "txbytes", "tx"],
    )));
    stats.net_rx_total_packets =
        value_size(find_value(value, &["net_rx_total_packets", "rx_packets"]));
    stats.net_tx_total_packets =
        value_size(find_value(value, &["net_tx_total_packets", "tx_packets"]));

    if stats.net_rx_total_bytes == 0 && stats.net_tx_total_bytes == 0 {
        if let Some(networks) =
            find_value(value, &["Network", "Networks"]).and_then(|item| item.as_object())
        {
            for network in networks.values() {
                stats.net_rx_total_bytes =
                    stats
                        .net_rx_total_bytes
                        .saturating_add(value_size(find_value(
                            network,
                            &["RxBytes", "rx_bytes", "received"],
                        )));
                stats.net_tx_total_bytes =
                    stats
                        .net_tx_total_bytes
                        .saturating_add(value_size(find_value(
                            network,
                            &["TxBytes", "tx_bytes", "transmit"],
                        )));
            }
        }
    }

    stats
}

fn parse_stats_template_line(line: &str) -> Option<(String, RuntimeStats)> {
    let parts: Vec<&str> = line.split('|').collect();
    if parts.len() < 5 || parts[0].trim().is_empty() {
        return None;
    }
    let (mem_bytes, mem_limit_bytes) = parse_size_pair(Some(&serde_json::Value::String(
        parts[2].trim().to_string(),
    )));
    let (net_rx_total_bytes, net_tx_total_bytes) = parse_size_pair(Some(
        &serde_json::Value::String(parts[4].trim().to_string()),
    ));
    let mem_percent = parts
        .get(3)
        .map(|value| value.trim().trim_end_matches('%').parse().unwrap_or(0.0))
        .unwrap_or_else(|| percentage(mem_bytes, mem_limit_bytes));
    Some((
        parts[0].trim().to_string(),
        RuntimeStats {
            cpu_percent: parts[1].trim().trim_end_matches('%').parse().unwrap_or(0.0),
            mem_bytes,
            mem_limit_bytes,
            mem_percent: if mem_percent > 0.0 {
                mem_percent
            } else {
                percentage(mem_bytes, mem_limit_bytes)
            },
            net_rx_total_bytes,
            net_tx_total_bytes,
            pids: parts
                .get(5)
                .and_then(|value| value.trim().parse().ok())
                .unwrap_or(0),
            ..Default::default()
        },
    ))
}

fn parse_prometheus_labels(raw: &str) -> HashMap<String, String> {
    raw.split(',')
        .filter_map(|part| {
            let (key, value) = part.split_once('=')?;
            Some((
                key.trim().to_string(),
                value.trim().trim_matches('"').replace("\\\"", "\""),
            ))
        })
        .collect()
}

fn parse_incus_metrics(text: &str) -> HashMap<(String, String), IncusMetrics> {
    let line_pattern = regex::Regex::new(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+([^\s]+)")
        .expect("valid OpenMetrics pattern");
    let mut result = HashMap::new();

    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(captures) = line_pattern.captures(line) else {
            continue;
        };
        let metric = captures.get(1).map(|value| value.as_str()).unwrap_or("");
        let labels =
            parse_prometheus_labels(captures.get(2).map(|value| value.as_str()).unwrap_or(""));
        if labels.get("type").is_some_and(|kind| kind != "container") {
            continue;
        }
        let Some(name) = labels.get("name").filter(|name| !name.is_empty()) else {
            continue;
        };
        let value: f64 = captures
            .get(3)
            .and_then(|raw| raw.as_str().parse().ok())
            .unwrap_or(0.0);
        if !value.is_finite() || value < 0.0 {
            continue;
        }
        let project = labels
            .get("project")
            .cloned()
            .unwrap_or_else(|| "default".to_string());
        let item = result
            .entry((project, name.clone()))
            .or_insert_with(IncusMetrics::default);
        let integer_value = value as u64;

        match metric {
            "incus_cpu_seconds_total" if labels.get("mode").map(String::as_str) != Some("idle") => {
                item.cpu_seconds += value;
            }
            "incus_cpu_effective_total" => item.effective_cpus = value,
            "incus_memory_MemTotal_bytes" => item.mem_total_bytes = integer_value,
            "incus_memory_MemAvailable_bytes" => item.mem_available_bytes = Some(integer_value),
            "incus_network_receive_bytes_total"
                if labels.get("device").map(String::as_str) != Some("lo") =>
            {
                item.net_rx_total_bytes = item.net_rx_total_bytes.saturating_add(integer_value);
            }
            "incus_network_transmit_bytes_total"
                if labels.get("device").map(String::as_str) != Some("lo") =>
            {
                item.net_tx_total_bytes = item.net_tx_total_bytes.saturating_add(integer_value);
            }
            "incus_network_receive_packets_total"
                if labels.get("device").map(String::as_str) != Some("lo") =>
            {
                item.net_rx_total_packets = item.net_rx_total_packets.saturating_add(integer_value);
            }
            "incus_network_transmit_packets_total"
                if labels.get("device").map(String::as_str) != Some("lo") =>
            {
                item.net_tx_total_packets = item.net_tx_total_packets.saturating_add(integer_value);
            }
            "incus_filesystem_size_bytes" => {
                item.fs_total_bytes = item.fs_total_bytes.max(integer_value)
            }
            "incus_filesystem_avail_bytes" => {
                item.fs_avail_bytes = item.fs_avail_bytes.max(integer_value)
            }
            _ => {}
        }
    }

    result
}

fn incus_image_name(item: &serde_json::Value) -> String {
    for section in ["config", "expanded_config"] {
        if let Some(config) = item.get(section).and_then(serde_json::Value::as_object) {
            for key in ["image.description", "image.os", "volatile.base_image"] {
                if let Some(value) = config.get(key).and_then(serde_json::Value::as_str) {
                    if !value.trim().is_empty() {
                        return value.to_string();
                    }
                }
            }
        }
    }
    "incus-container".to_string()
}

fn inspect_oci_container(runtime: &str, name: &str) -> serde_json::Value {
    let Ok(output) = Command::new(runtime).args(["inspect", name]).output() else {
        return serde_json::Value::Null;
    };
    if !output.status.success() {
        return serde_json::Value::Null;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
        return serde_json::Value::Null;
    };
    value
        .as_array()
        .and_then(|items| items.first())
        .cloned()
        .unwrap_or(value)
}

fn container_pid(inspect: &serde_json::Value) -> i64 {
    inspect
        .get("State")
        .and_then(|state| state.get("Pid"))
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0)
}

fn collect_proc_telemetry(pid: i64) -> ProcTelemetry {
    if pid <= 0 {
        return ProcTelemetry::default();
    }
    let mut telemetry = ProcTelemetry::default();
    let base = format!("/proc/{}/net", pid);

    if let Ok(text) = fs::read_to_string(format!("{}/dev", base)) {
        for line in text.lines().skip(2) {
            let Some((interface, counters)) = line.split_once(':') else {
                continue;
            };
            if interface.trim() == "lo" {
                continue;
            }
            let fields: Vec<&str> = counters.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            telemetry.net_rx_total_bytes = telemetry
                .net_rx_total_bytes
                .saturating_add(fields[0].parse().unwrap_or(0));
            telemetry.net_rx_total_packets = telemetry
                .net_rx_total_packets
                .saturating_add(fields[1].parse().unwrap_or(0));
            telemetry.net_tx_total_bytes = telemetry
                .net_tx_total_bytes
                .saturating_add(fields[8].parse().unwrap_or(0));
            telemetry.net_tx_total_packets = telemetry
                .net_tx_total_packets
                .saturating_add(fields[9].parse().unwrap_or(0));
        }
    }

    let mut sockets = Vec::new();
    for (file, protocol, ipv6) in [
        ("tcp", "tcp", false),
        ("tcp6", "tcp", true),
        ("udp", "udp", false),
        ("udp6", "udp", true),
    ] {
        if let Ok(text) = fs::read_to_string(format!("{}/{}", base, file)) {
            sockets.extend(parse_proc_socket_table(&text, protocol, ipv6));
        }
    }

    let listening: HashSet<u16> = sockets
        .iter()
        .filter(|socket| {
            (socket.protocol == "tcp" && socket.state == 0x0a)
                || (socket.protocol == "udp"
                    && socket.remote_ip.is_unspecified()
                    && socket.remote_port == 0)
        })
        .map(|socket| socket.local_port)
        .collect();
    let mut inbound_ips = HashSet::new();
    let mut outbound_ips = HashSet::new();

    for socket in &sockets {
        let is_listener = (socket.protocol == "tcp" && socket.state == 0x0a)
            || (socket.protocol == "udp"
                && socket.remote_ip.is_unspecified()
                && socket.remote_port == 0);
        if is_listener {
            continue;
        }
        if is_trackable_ip(socket.remote_ip) {
            if socket.protocol == "tcp" && socket.state == 0x01 {
                *telemetry
                    .tcp_remote_ip_counts
                    .entry(socket.remote_ip)
                    .or_default() += 1;
            } else if socket.protocol == "udp" && socket.remote_port > 0 {
                *telemetry
                    .udp_remote_ip_counts
                    .entry(socket.remote_ip)
                    .or_default() += 1;
            }
        }
        telemetry.connection_count += 1;
        if socket.protocol == "tcp" && socket.state == 0x03 {
            telemetry.syn_recv_count += 1;
        }
        let incoming = listening.contains(&socket.local_port) || socket.state == 0x03;
        if socket.protocol != "tcp" || socket.state == 0x01 {
            if incoming {
                telemetry.incoming_established += 1;
            } else {
                telemetry.outgoing_established += 1;
            }
        }
        if is_trackable_ip(socket.remote_ip) {
            if incoming {
                if is_public_ip(socket.remote_ip) {
                    inbound_ips.insert(socket.remote_ip);
                    *telemetry
                        .inbound_ip_counts
                        .entry(socket.remote_ip)
                        .or_default() += 1;
                }
            } else {
                outbound_ips.insert(socket.remote_ip);
            }
        }
    }

    telemetry.inbound_unique_ips = inbound_ips.len() as u64;
    telemetry.outbound_unique_ips = outbound_ips.len() as u64;
    telemetry.listening_ports = listening.into_iter().collect();
    telemetry.listening_ports.sort_unstable();
    telemetry.protocol_counters = read_protocol_counters(pid);
    telemetry
}

fn parse_proc_socket_table(text: &str, protocol: &str, ipv6: bool) -> Vec<SocketEntry> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                return None;
            }
            let (local_ip, local_port) = decode_proc_endpoint(fields[1], ipv6)?;
            let (remote_ip, remote_port) = decode_proc_endpoint(fields[2], ipv6)?;
            let state = u8::from_str_radix(fields[3], 16).ok()?;
            Some(SocketEntry {
                protocol: protocol.to_string(),
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                state,
            })
        })
        .collect()
}

fn decode_proc_endpoint(value: &str, ipv6: bool) -> Option<(IpAddr, u16)> {
    let (raw_ip, raw_port) = value.split_once(':')?;
    let port = u16::from_str_radix(raw_port, 16).ok()?;
    let bytes = hex::decode(raw_ip).ok()?;
    if ipv6 {
        if bytes.len() != 16 {
            return None;
        }
        let mut normalized = [0_u8; 16];
        for (source, target) in bytes.chunks_exact(4).zip(normalized.chunks_exact_mut(4)) {
            target.copy_from_slice(&[source[3], source[2], source[1], source[0]]);
        }
        let address = Ipv6Addr::from(normalized);
        Some((
            address
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(address)),
            port,
        ))
    } else {
        if bytes.len() != 4 {
            return None;
        }
        Some((
            IpAddr::V4(Ipv4Addr::new(bytes[3], bytes[2], bytes[1], bytes[0])),
            port,
        ))
    }
}

fn is_trackable_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_link_local()
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && (ip.segments()[0] & 0xfe00) != 0xfc00
                && (ip.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => is_trackable_ip(address) && !ip.is_private(),
        IpAddr::V6(ip) => is_trackable_ip(address) && (ip.segments()[0] & 0xfe00) != 0xfc00,
    }
}

fn read_protocol_counters(pid: i64) -> HashMap<String, u64> {
    let mut result = HashMap::new();
    let Ok(text) = fs::read_to_string(format!("/proc/{}/net/snmp", pid)) else {
        return result;
    };
    let lines: Vec<&str> = text.lines().collect();
    for pair in lines.chunks_exact(2) {
        let headers: Vec<&str> = pair[0].split_whitespace().collect();
        let values: Vec<&str> = pair[1].split_whitespace().collect();
        if headers.is_empty() || values.is_empty() || headers[0] != values[0] {
            continue;
        }
        let protocol = headers[0].trim_end_matches(':');
        let wanted: &[&str] = match protocol {
            "Tcp" => &["ActiveOpens", "AttemptFails", "EstabResets", "OutRsts"],
            "Udp" => &["OutDatagrams", "NoPorts", "InErrors"],
            _ => continue,
        };
        for field in wanted {
            if let Some(index) = headers.iter().position(|header| header == field) {
                result.insert(
                    format!("{}_{}", protocol, field),
                    values
                        .get(index)
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(0),
                );
            }
        }
    }
    result
}

fn read_process_count(pid: i64) -> u64 {
    if pid <= 0 {
        return 0;
    }
    for path in [
        format!("/proc/{}/root/sys/fs/cgroup/pids.current", pid),
        format!("/proc/{}/root/sys/fs/cgroup/pids/pids.current", pid),
    ] {
        if let Ok(value) = fs::read_to_string(path) {
            if let Ok(count) = value.trim().parse() {
                return count;
            }
        }
    }
    0
}

fn build_container_security(
    proc_stats: &ProcTelemetry,
    rx_pps: f64,
    tx_pps: f64,
    process_count: u64,
    protocol_rates: HashMap<String, f64>,
    inspect: &serde_json::Value,
) -> ContainerSecurity {
    ContainerSecurity {
        inbound_unique_ips: proc_stats.inbound_unique_ips,
        inbound_unique_ip_threshold: 10,
        inbound_ip_observation: "container_socket".to_string(),
        inbound_top_ips: top_ip_counts(&proc_stats.inbound_ip_counts, 10),
        syn_recv_count: proc_stats.syn_recv_count,
        incoming_established: proc_stats.incoming_established,
        outgoing_established: proc_stats.outgoing_established,
        outbound_unique_ips: proc_stats.outbound_unique_ips,
        net_rx_pps: rx_pps,
        net_tx_pps: tx_pps,
        process_count,
        suspicious_processes: Vec::new(),
        configuration_risks: oci_configuration_risks(inspect),
        listening_ports: proc_stats.listening_ports.clone(),
        network_exposure: oci_network_exposure(inspect),
        protocol_rates,
        panel_pairing: serde_json::json!({"detected": false, "approved": false}),
        socks_proxy: serde_json::json!({"detected": false, "auth_mode": "unknown"}),
    }
}

fn top_ip_counts(counts: &HashMap<IpAddr, u64>, limit: usize) -> Vec<serde_json::Value> {
    let mut entries: Vec<(IpAddr, u64)> = counts.iter().map(|(ip, count)| (*ip, *count)).collect();
    entries.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    entries
        .into_iter()
        .take(limit)
        .map(|(ip, connections)| {
            serde_json::json!({"ip": ip.to_string(), "connections": connections})
        })
        .collect()
}

fn oci_network_exposure(inspect: &serde_json::Value) -> Vec<serde_json::Value> {
    let ports = inspect
        .get("NetworkSettings")
        .and_then(|settings| settings.get("Ports"))
        .and_then(serde_json::Value::as_object)
        .filter(|ports| !ports.is_empty())
        .or_else(|| {
            inspect
                .get("HostConfig")
                .and_then(|config| config.get("PortBindings"))
                .and_then(serde_json::Value::as_object)
        });
    let mut result = Vec::new();
    for (container_port, bindings) in ports.into_iter().flatten() {
        for binding in bindings.as_array().into_iter().flatten() {
            let host_ip = binding
                .get("HostIp")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .unwrap_or("0.0.0.0");
            let host_port = binding
                .get("HostPort")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            result.push(serde_json::json!({
                "source": "podman-publish",
                "listen": if host_port.is_empty() { host_ip.to_string() } else { format!("{}:{}", host_ip, host_port) },
                "target": container_port,
            }));
        }
    }
    result
}

fn oci_configuration_risks(inspect: &serde_json::Value) -> Vec<serde_json::Value> {
    let mut risks = Vec::new();
    let empty_host = serde_json::Value::Null;
    let host = inspect.get("HostConfig").unwrap_or(&empty_host);
    if host.get("Privileged").and_then(serde_json::Value::as_bool) == Some(true) {
        risks.push(serde_json::json!({"code":"privileged","severity":"critical","message":"容器以 privileged 模式运行"}));
    }
    for (field, label) in [
        ("NetworkMode", "network"),
        ("PidMode", "PID"),
        ("IpcMode", "IPC"),
    ] {
        if host.get(field).and_then(serde_json::Value::as_str) == Some("host") {
            risks.push(serde_json::json!({"code":format!("host_{}_namespace", label.to_lowercase()),"severity":"warning","message":format!("容器共享宿主机 {} 命名空间", label)}));
        }
    }
    let sensitive = [
        "/",
        "/etc",
        "/proc",
        "/sys",
        "/var/run",
        "/run/podman/podman.sock",
        "/var/run/docker.sock",
    ];
    for mount in inspect
        .get("Mounts")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        let source = mount
            .get("Source")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if sensitive.iter().any(|path| {
            source == *path
                || (*path != "/" && source.starts_with(&format!("{}/", path.trim_end_matches('/'))))
        }) {
            risks.push(serde_json::json!({"code":"sensitive_mount","severity":"warning","message":format!("容器挂载宿主机敏感路径 {}", source)}));
        }
    }
    risks
}

fn incus_configuration_risks(item: &serde_json::Value) -> Vec<serde_json::Value> {
    let mut risks = Vec::new();
    let config = item
        .get("expanded_config")
        .or_else(|| item.get("config"))
        .and_then(serde_json::Value::as_object);
    for (key, severity, message) in [
        (
            "security.privileged",
            "critical",
            "Incus 容器启用了 privileged",
        ),
        ("security.nesting", "warning", "Incus 容器启用了 nesting"),
    ] {
        if config
            .and_then(|values| values.get(key))
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| value.eq_ignore_ascii_case("true"))
        {
            risks.push(serde_json::json!({"code":key.replace('.', "_"),"severity":severity,"message":message}));
        }
    }
    risks
}

fn incus_network_exposure(item: &serde_json::Value) -> Vec<serde_json::Value> {
    let devices = item
        .get("expanded_devices")
        .or_else(|| item.get("devices"))
        .and_then(serde_json::Value::as_object);
    let mut result = Vec::new();
    for (name, device) in devices.into_iter().flatten() {
        if device.get("type").and_then(serde_json::Value::as_str) != Some("proxy") {
            continue;
        }
        result.push(serde_json::json!({
            "source": format!("incus-proxy:{}", name),
            "listen": device.get("listen").and_then(serde_json::Value::as_str).unwrap_or(""),
            "target": device.get("connect").and_then(serde_json::Value::as_str).unwrap_or(""),
        }));
    }
    result
}

fn collect_top_cpu_process(runtime: &str, name: &str, project: &str) -> TopCpuProcess {
    let mut command = Command::new(runtime);
    if runtime == "incus" && !project.is_empty() && project != "default" {
        command.args(["--project", project]);
    }
    let output = if runtime == "incus" {
        command
            .args(["exec", name, "--", "ps", "-eo", "pcpu,pid,comm,args"])
            .output()
    } else {
        command.args(["top", name, "pcpu,pid,comm,args"]).output()
    };
    let Ok(output) = output else {
        return TopCpuProcess::default();
    };
    if !output.status.success() {
        return TopCpuProcess::default();
    }
    let mut best = TopCpuProcess::default();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3
            || parts[0].eq_ignore_ascii_case("%cpu")
            || parts[0].eq_ignore_ascii_case("pcpu")
        {
            continue;
        }
        let cpu = parts[0].parse().unwrap_or(0.0);
        let pid = parts[1].parse().unwrap_or(0);
        if cpu >= best.cpu_percent {
            best = TopCpuProcess {
                pid,
                cpu_percent: cpu,
                command: parts[2..].join(" "),
            };
        }
    }
    best
}

fn collect_suspicious_processes(
    runtime: &str,
    name: &str,
    project: &str,
) -> Vec<serde_json::Value> {
    let mut command = Command::new(runtime);
    if runtime == "incus" && !project.is_empty() && project != "default" {
        command.args(["--project", project]);
    }
    let output = if runtime == "incus" {
        command
            .args(["exec", name, "--", "ps", "-eo", "pid,comm,args"])
            .output()
    } else {
        command.args(["top", name, "pid,comm,args"]).output()
    };
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let patterns = [
        "xmrig",
        "kinsing",
        "kdevtmpfsi",
        "watchbog",
        "minerd",
        "cryptominer",
        "kinsing2",
    ];
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 || parts[0].eq_ignore_ascii_case("pid") {
                return None;
            }
            let pid: i64 = parts[0].parse().ok()?;
            let command = parts[1..].join(" ");
            let lowered = command.to_lowercase();
            let pattern = patterns.iter().find(|pattern| {
                lowered
                    .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                    .any(|token| token == **pattern)
            })?;
            Some(serde_json::json!({
                "pid": pid,
                "pattern": pattern,
                "command": command,
            }))
        })
        .take(20)
        .collect()
}

fn get_container_disk_usage(runtime: &str, container_name: &str) -> ContainerDiskPayload {
    let output = match runtime {
        "docker" => Command::new("docker")
            .args(["exec", container_name, "df", "-P", "/"])
            .output()
            .ok(),
        "podman" => Command::new("podman")
            .args(["exec", container_name, "df", "-P", "/"])
            .output()
            .ok(),
        "incus" => Command::new("incus")
            .args(["exec", container_name, "--", "df", "-P", "/"])
            .output()
            .ok(),
        _ => None,
    };

    let mut payload = ContainerDiskPayload {
        rw_bytes: 0,
        rootfs_bytes: 0,
        fs: ContainerFs {
            root: Some(FsUsage {
                total_bytes: 0,
                avail_bytes: 0,
            }),
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
            let num: f64 = cap
                .get(1)
                .map(|m| m.as_str().parse().unwrap_or(0.0))
                .unwrap_or(0.0);
            let unit = cap
                .get(2)
                .map(|m| m.as_str().to_uppercase())
                .unwrap_or_default();
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_podman_snake_case_stats() {
        let stats = parse_runtime_stats(&json!({
            "name": "web",
            "cpu": "1.25%",
            "mem_usage": "20MiB",
            "mem_limit": "100MiB",
            "mem_perc": "20.00%",
            "net_input": "1MiB",
            "net_output": "2MiB",
            "pids": "7"
        }));

        assert_eq!(stats.cpu_percent, 1.25);
        assert_eq!(stats.mem_bytes, 20 * 1024 * 1024);
        assert_eq!(stats.mem_limit_bytes, 100 * 1024 * 1024);
        assert_eq!(stats.mem_percent, 20.0);
        assert_eq!(stats.net_rx_total_bytes, 1024 * 1024);
        assert_eq!(stats.net_tx_total_bytes, 2 * 1024 * 1024);
        assert_eq!(stats.pids, 7);
    }

    #[test]
    fn parses_docker_combined_stats() {
        let stats = parse_runtime_stats(&json!({
            "Name": "db",
            "CPUPerc": "2.50%",
            "MemUsage": "32MiB / 128MiB",
            "NetIO": "3MB / 4MB",
            "PIDs": "11"
        }));

        assert_eq!(stats.cpu_percent, 2.5);
        assert_eq!(stats.mem_bytes, 32 * 1024 * 1024);
        assert_eq!(stats.mem_limit_bytes, 128 * 1024 * 1024);
        assert_eq!(stats.mem_percent, 25.0);
        assert_eq!(stats.net_rx_total_bytes, 3 * 1024 * 1024);
        assert_eq!(stats.net_tx_total_bytes, 4 * 1024 * 1024);
        assert_eq!(stats.pids, 11);
    }

    #[test]
    fn template_fallback_fills_missing_json_fields() {
        let mut stats = parse_runtime_stats(&json!({"name": "api", "cpu_nano": 10}));
        let (_, fallback) =
            parse_stats_template_line("api|3.5%|10MiB / 50MiB||1MB / 2MB|5").unwrap();

        stats.merge_missing(&fallback);

        assert_eq!(stats.cpu_percent, 3.5);
        assert_eq!(stats.mem_percent, 20.0);
        assert_eq!(stats.net_rx_total_bytes, 1024 * 1024);
        assert_eq!(stats.pids, 5);
    }

    #[test]
    fn parses_incus_openmetrics_and_excludes_idle_and_loopback() {
        let input = r#"
# TYPE incus_cpu_seconds_total counter
incus_cpu_seconds_total{cpu="0",mode="user",name="c1",project="default",type="container"} 12.5
incus_cpu_seconds_total{cpu="0",mode="system",name="c1",project="default",type="container"} 2.5
incus_cpu_seconds_total{cpu="0",mode="idle",name="c1",project="default",type="container"} 100
incus_cpu_effective_total{name="c1",project="default",type="container"} 2
incus_memory_MemTotal_bytes{name="c1",project="default",type="container"} 1048576
incus_memory_MemAvailable_bytes{name="c1",project="default",type="container"} 262144
incus_network_receive_bytes_total{device="eth0",name="c1",project="default",type="container"} 1000
incus_network_receive_bytes_total{device="lo",name="c1",project="default",type="container"} 999
incus_network_transmit_bytes_total{device="eth0",name="c1",project="default",type="container"} 2000
incus_network_receive_packets_total{device="eth0",name="c1",project="default",type="container"} 10
incus_network_transmit_packets_total{device="eth0",name="c1",project="default",type="container"} 20
incus_cpu_seconds_total{cpu="0",mode="user",name="vm1",project="default",type="virtual-machine"} 999
"#;

        let parsed = parse_incus_metrics(input);
        let metrics = parsed
            .get(&("default".to_string(), "c1".to_string()))
            .unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(metrics.cpu_seconds, 15.0);
        assert_eq!(metrics.effective_cpus, 2.0);
        assert_eq!(metrics.mem_total_bytes, 1_048_576);
        assert_eq!(metrics.mem_available_bytes, Some(262_144));
        assert_eq!(metrics.net_rx_total_bytes, 1000);
        assert_eq!(metrics.net_tx_total_bytes, 2000);
        assert_eq!(metrics.net_rx_total_packets, 10);
        assert_eq!(metrics.net_tx_total_packets, 20);
    }

    #[test]
    fn counter_rates_require_two_samples_and_handle_resets() {
        let state = Mutex::new(HashMap::new());

        assert_eq!(
            calculate_counter_rates(&state, "c1", 100, 200, 10),
            (0.0, 0.0)
        );
        assert_eq!(
            calculate_counter_rates(&state, "c1", 300, 500, 20),
            (20.0, 30.0)
        );
        assert_eq!(
            calculate_counter_rates(&state, "c1", 50, 80, 30),
            (0.0, 0.0)
        );
    }

    #[test]
    fn parses_proc_socket_addresses_and_listeners() {
        let input = "  sl  local_address rem_address   st\n   0: 0100007F:1F90 00000000:0000 0A\n   1: 0100007F:1F90 08080808:C350 01\n";
        let sockets = parse_proc_socket_table(input, "tcp", false);

        assert_eq!(sockets.len(), 2);
        assert_eq!(sockets[0].local_ip, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(sockets[0].local_port, 8080);
        assert_eq!(sockets[0].state, 0x0a);
        assert_eq!(sockets[1].remote_ip, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(sockets[1].state, 0x01);

        let mut telemetry = ProcTelemetry::default();
        let listening: HashSet<u16> = sockets
            .iter()
            .filter(|socket| socket.state == 0x0a)
            .map(|socket| socket.local_port)
            .collect();
        for socket in sockets.iter().filter(|socket| socket.state == 0x01) {
            if listening.contains(&socket.local_port) && is_public_ip(socket.remote_ip) {
                *telemetry
                    .inbound_ip_counts
                    .entry(socket.remote_ip)
                    .or_default() += 1;
            }
            *telemetry
                .tcp_remote_ip_counts
                .entry(socket.remote_ip)
                .or_default() += 1;
        }
        assert_eq!(telemetry.inbound_ip_counts.values().sum::<u64>(), 1);
        assert_eq!(telemetry.tcp_remote_ip_counts.values().sum::<u64>(), 1);
        assert_eq!(
            top_ip_counts(&telemetry.inbound_ip_counts, 3)[0]["ip"],
            "8.8.8.8"
        );
    }

    #[test]
    fn maps_oci_exposure_and_configuration_risks() {
        let inspect = json!({
            "State": {"Pid": 42},
            "NetworkSettings": {"Ports": {"443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8443"}]}},
            "HostConfig": {"Privileged": true, "NetworkMode": "host"},
            "Mounts": [{"Source": "/var/run/docker.sock"}]
        });

        assert_eq!(container_pid(&inspect), 42);
        let exposure = oci_network_exposure(&inspect);
        assert_eq!(exposure[0]["listen"], "0.0.0.0:8443");
        assert_eq!(exposure[0]["target"], "443/tcp");
        let risks = oci_configuration_risks(&inspect);
        assert!(risks.iter().any(|risk| risk["code"] == "privileged"));
        assert!(risks
            .iter()
            .any(|risk| risk["code"] == "host_network_namespace"));
        assert!(risks.iter().any(|risk| risk["code"] == "sensitive_mount"));
    }

    #[test]
    fn security_payload_uses_server_dashboard_field_names() {
        let payload = serde_json::to_value(ContainerSecurity {
            inbound_unique_ips: 2,
            incoming_established: 3,
            outbound_unique_ips: 4,
            listening_ports: vec![80, 443],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(payload["inbound_unique_ips"], 2);
        assert_eq!(payload["incoming_established"], 3);
        assert_eq!(payload["outbound_unique_ips"], 4);
        assert_eq!(payload["listening_ports"], json!([80, 443]));
        assert!(payload.get("protocol_rates").is_some());
        assert!(payload.get("network_exposure").is_some());
    }
}
