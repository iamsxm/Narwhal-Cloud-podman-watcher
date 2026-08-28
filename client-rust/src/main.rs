mod collector;
mod config;
mod reporter;

use collector::Collector;
use config::Config;
use reporter::Reporter;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

const RUST_INSTALL_URL: &str = "https://raw.githubusercontent.com/iamsxm/Narwhal-Cloud-podman-watcher/main/scripts/install-rust-client.sh";

fn schedule_client_update(action_id: u64) -> Result<String, String> {
    let unit = format!("narwhal-client-update-{}", action_id);
    let unit_arg = format!("--unit={}", unit);
    let command = format!("sleep 3; curl -fsSL '{}' | /bin/bash", RUST_INSTALL_URL);
    Command::new("systemd-run")
        .args(["--collect", &unit_arg, "/bin/bash", "-lc", &command])
        .spawn()
        .map_err(|error| format!("failed to schedule systemd update: {}", error))?;
    Ok(format!("Rust Client update scheduled in {}", unit))
}

fn main() {
    println!("==========================================");
    println!(
        "  Narwhal Monitor Rust Agent v{}",
        env!("CARGO_PKG_VERSION")
    );
    println!("==========================================");

    let config = Config::load();
    println!("Host ID:         {}", config.host_id);
    println!("Server URL:      {}", config.server_url);
    println!("Report Interval: {}s", config.report_interval_secs);
    println!("Runtimes:        {}", config.container_runtimes);
    println!("Docker Mode:     {}", config.docker_monitor_mode);
    println!("==========================================");

    let collector = Collector::new();
    let reporter = Reporter::new(config.server_url.clone(), config.shared_secret.clone());

    let report_interval = Duration::from_secs(config.report_interval_secs.max(1));
    let poll_interval = Duration::from_secs(config.action_poll_interval_secs.max(1));
    let mut next_report = Instant::now();

    loop {
        if Instant::now() >= next_report {
            let payload = collector.collect(
                &config.host_id,
                &config.version,
                &config.container_runtimes,
                &config.docker_monitor_mode,
            );
            let container_count = payload.containers.len();
            match reporter.report(&payload) {
                Ok(_) => println!(
                    "[{}] Reported {} container(s) to {}",
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                    container_count,
                    config.server_url
                ),
                Err(error) => eprintln!(
                    "[{}] Report failed: {}",
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                    error
                ),
            }
            next_report = Instant::now() + report_interval;
        }

        match reporter.poll_actions(&config.host_id) {
            Ok(actions) => {
                for action in actions {
                    let result = match action.action_type.as_str() {
                        "update_client" => schedule_client_update(action.id),
                        other => Err(format!("unsupported Rust Client action: {}", other)),
                    };
                    let (succeeded, message) = match result {
                        Ok(message) => (true, message),
                        Err(message) => (false, message),
                    };
                    if let Err(error) = reporter.report_action_result(
                        action.id,
                        &config.host_id,
                        succeeded,
                        &message,
                    ) {
                        eprintln!("Action {} result report failed: {}", action.id, error);
                    } else {
                        println!("Action {}: {}", action.id, message);
                    }
                }
            }
            Err(error) => eprintln!("Action poll failed: {}", error),
        }
        sleep(poll_interval.min(next_report.saturating_duration_since(Instant::now())));
    }
}
