use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Config {
    pub server_url: String,
    pub shared_secret: String,
    pub host_id: String,
    pub report_interval_secs: u64,
    pub action_poll_interval_secs: u64,
    pub container_runtimes: String,
    pub docker_monitor_mode: String,
    pub monitored_image_patterns: String,
    pub monitored_incus_patterns: String,
    pub incus_project: String,
    pub security_monitor_enabled: bool,
    pub version: String,
}

impl Config {
    pub fn load() -> Self {
        let env_file_path = "/opt/narwhal-monitor/client.env";
        let file_vars = Self::parse_env_file(env_file_path);

        let get_var = |key: &str, default: &str| -> String {
            if let Ok(v) = std::env::var(key) {
                if !v.trim().is_empty() {
                    return v.trim().to_string();
                }
            }
            if let Some(v) = file_vars.get(key) {
                if !v.trim().is_empty() {
                    return v.trim().to_string();
                }
            }
            default.to_string()
        };

        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .or_else(|_| fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
            .unwrap_or_else(|_| "unknown-host".to_string());

        let report_interval: u64 = get_var("REPORT_INTERVAL", "300")
            .parse()
            .unwrap_or(300);

        let action_poll_interval: u64 = get_var("ACTION_POLL_INTERVAL", "10")
            .parse()
            .unwrap_or(10);

        let security_enabled = get_var("SECURITY_MONITOR_ENABLED", "true")
            .to_lowercase()
            == "true";

        Self {
            server_url: get_var("SERVER_URL", "http://127.0.0.1:8080"),
            shared_secret: get_var("SHARED_SECRET", "change-me"),
            host_id: get_var("HOST_ID", &hostname),
            report_interval_secs: report_interval,
            action_poll_interval_secs: action_poll_interval,
            container_runtimes: get_var("CONTAINER_RUNTIMES", "auto"),
            docker_monitor_mode: get_var("DOCKER_MONITOR_MODE", "notice"),
            monitored_image_patterns: get_var("MONITORED_IMAGE_PATTERNS", "*"),
            monitored_incus_patterns: get_var("MONITORED_INCUS_PATTERNS", "*"),
            incus_project: get_var("INCUS_PROJECT", "default"),
            security_monitor_enabled: security_enabled,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn parse_env_file(path: &str) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Ok(contents) = fs::read_to_string(Path::new(path)) {
            for line in contents.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = trimmed.split_once('=') {
                    let key = k.trim().to_string();
                    let val = v.trim().trim_matches('"').trim_matches('\'').to_string();
                    map.insert(key, val);
                }
            }
        }
        map
    }
}
