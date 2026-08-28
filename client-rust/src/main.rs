mod config;
mod collector;
mod reporter;

use config::Config;
use collector::Collector;
use reporter::Reporter;
use std::thread::sleep;
use std::time::Duration;

fn main() {
    println!("==========================================");
    println!("  Narwhal Monitor Rust Agent v{}", env!("CARGO_PKG_VERSION"));
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

    loop {
        let payload = collector.collect(
            &config.host_id,
            &config.version,
            &config.container_runtimes,
            &config.docker_monitor_mode,
        );

        let container_count = payload.containers.len();
        match reporter.report(&payload) {
            Ok(_) => {
                println!(
                    "[{}] Reported {} container(s) to {}",
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                    container_count,
                    config.server_url
                );
            }
            Err(e) => {
                eprintln!(
                    "[{}] Report failed: {}",
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                    e
                );
            }
        }

        sleep(Duration::from_secs(config.report_interval_secs));
    }
}
