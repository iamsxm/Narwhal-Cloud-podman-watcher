import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("narwhal_agent", ROOT / "client" / "agent.py")
assert SPEC and SPEC.loader
agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent)


class RuntimeDiscoveryTests(unittest.TestCase):
    def setUp(self):
        agent._podman_bin = None
        agent._container_bin = None
        agent._runtime_bins = None
        agent._warned_missing_bins.clear()

    def test_auto_discovers_all_available_runtimes(self):
        with mock.patch.dict(os.environ, {"CONTAINER_RUNTIMES": "auto"}, clear=False):
            with mock.patch.object(agent.shutil, "which", side_effect=lambda name: f"/usr/bin/{name}"):
                self.assertEqual(
                    agent.get_runtime_bins(),
                    {"podman": "podman", "docker": "docker", "incus": "incus"},
                )

    def test_explicit_runtime_subset_is_honored(self):
        with mock.patch.dict(os.environ, {"CONTAINER_RUNTIMES": "docker,incus"}, clear=False):
            with mock.patch.object(agent.shutil, "which", side_effect=lambda name: f"/usr/bin/{name}"):
                self.assertEqual(agent.get_runtime_bins(), {"docker": "docker", "incus": "incus"})

    def test_lists_oci_and_incus_containers_together(self):
        incus_payload = json.dumps(
            [
                {
                    "name": "web-incus",
                    "type": "container",
                    "status": "Running",
                    "project": "default",
                    "config": {"image.description": "Debian 13"},
                    "state": {"pid": 4321},
                }
            ]
        )

        def fake_run(cmd):
            if cmd[0] == "podman" and cmd[1] == "ps":
                return "p1|web-podman|alpine:latest\n"
            if cmd[0] == "docker" and cmd[1] == "ps":
                return "d1|web-docker|alpine:latest\n"
            if cmd[0] == "incus" and "list" in cmd:
                return incus_payload
            return ""

        env = {
            "MONITORED_IMAGE_PATTERNS": "alpine",
            "MONITORED_INCUS_PATTERNS": "*",
            "INCUS_PROJECT": "default",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            with mock.patch.object(
                agent,
                "get_runtime_bins",
                return_value={"podman": "podman", "docker": "docker", "incus": "incus"},
            ), mock.patch.object(agent, "run", side_effect=fake_run):
                containers = agent.list_containers()

        self.assertEqual([x["runtime"] for x in containers], ["podman", "docker", "incus"])
        self.assertEqual(containers[-1]["pid"], "4321")
        self.assertEqual(containers[-1]["project"], "default")

    def test_wildcard_includes_panel_and_service_images(self):
        with mock.patch.object(
            agent,
            "run",
            return_value="x1|xboard-panel|ghcr.io/cedar2025/xboard:latest\nn1|node|custom/service:latest\n",
        ):
            containers = agent._oci_containers("docker", "docker", ["*"])
        self.assertEqual([item["name"] for item in containers], ["xboard-panel", "node"])

    def test_docker_notice_mode_creates_lightweight_report_and_info_alert(self):
        source = {"id": "d1", "name": "helper", "image": "helper:latest", "runtime": "docker"}
        with mock.patch.object(agent, "collect_disk_alert", return_value={}):
            report = agent.collect_docker_notice(source)
        with mock.patch.dict(os.environ, {"SECURITY_ACCESS_LOG_PATHS": ""}, clear=False):
            summary = agent.collect_security_summary([report], 60)
        self.assertEqual(report["monitor_mode"], "notice")
        self.assertTrue(report["security"]["notice_only"])
        self.assertEqual(summary["alerts"][0]["type"], "docker_container_notice")
        self.assertEqual(summary["alerts"][0]["severity"], "info")

    def test_docker_off_mode_omits_docker_from_discovery(self):
        with mock.patch.dict(os.environ, {"DOCKER_MONITOR_MODE": "off"}, clear=False), mock.patch.object(
            agent, "get_runtime_bins", return_value={"docker": "docker", "podman": "podman"}
        ), mock.patch.object(agent, "_oci_containers", return_value=[] ) as collect_mock:
            agent.list_containers()
        self.assertEqual(collect_mock.call_count, 1)
        self.assertEqual(collect_mock.call_args.args[0], "podman")


class IncusMetricsTests(unittest.TestCase):
    SAMPLE = """
# TYPE incus_cpu_seconds_total counter
incus_cpu_seconds_total{cpu="0",mode="user",name="c1",project="default",type="container"} 12.5
incus_cpu_seconds_total{cpu="0",mode="system",name="c1",project="default",type="container"} 2.5
incus_cpu_seconds_total{cpu="0",mode="idle",name="c1",project="default",type="container"} 100
incus_memory_MemTotal_bytes{name="c1",project="default",type="container"} 1048576
incus_network_receive_bytes_total{device="eth0",name="c1",project="default",type="container"} 1000
incus_network_receive_bytes_total{device="lo",name="c1",project="default",type="container"} 999
incus_network_transmit_bytes_total{device="eth0",name="c1",project="default",type="container"} 2000
incus_network_receive_packets_total{device="eth0",name="c1",project="default",type="container"} 10
incus_network_transmit_packets_total{device="eth0",name="c1",project="default",type="container"} 20
incus_cpu_seconds_total{cpu="0",mode="user",name="vm1",project="default",type="virtual-machine"} 999
"""

    def test_parses_and_sums_container_metrics(self):
        parsed = agent._parse_incus_metrics(self.SAMPLE)
        self.assertEqual(set(parsed), {("default", "c1")})
        item = parsed[("default", "c1")]
        self.assertEqual(item["cpu_seconds"], 15.0)
        self.assertEqual(item["mem_bytes"], 1048576)
        self.assertEqual(item["net_rx_total_bytes"], 1000)
        self.assertEqual(item["net_tx_total_bytes"], 2000)
        self.assertEqual(item["net_rx_total_packets"], 10)
        self.assertEqual(item["net_tx_total_packets"], 20)

    def test_incus_exec_uses_argument_separator_and_project(self):
        self.assertEqual(
            agent._runtime_exec_cmd("incus", "c1", "df -P /", "prod"),
            ["incus", "--project", "prod", "exec", "c1", "--", "sh", "-lc", "df -P /"],
        )
        self.assertEqual(
            agent._runtime_exec_cmd("docker", "c1", "df -P /"),
            ["docker", "exec", "c1", "sh", "-lc", "df -P /"],
        )


class SecurityTelemetryTests(unittest.TestCase):
    def setUp(self):
        agent._access_log_states.clear()
        agent._protocol_counters.clear()

    def test_reads_protocol_counters_from_container_network_namespace(self):
        snmp = (
            "Tcp: ActiveOpens AttemptFails EstabResets OutRsts\n"
            "Tcp: 100 7 3 9\n"
            "Udp: OutDatagrams NoPorts InErrors\n"
            "Udp: 500 2 1\n"
        )
        with mock.patch("builtins.open", mock.mock_open(read_data=snmp)):
            counters = agent._read_protocol_counters(123)
        self.assertEqual(counters["Tcp_ActiveOpens"], 100)
        self.assertEqual(counters["Tcp_AttemptFails"], 7)
        self.assertEqual(counters["Udp_OutDatagrams"], 500)

    def test_reads_process_count_from_container_cgroup(self):
        with mock.patch("builtins.open", mock.mock_open(read_data="321\n")):
            self.assertEqual(agent._read_process_count_from_pid(123), 321)

    def test_audits_podman_and_incus_isolation_risks(self):
        oci = agent._oci_security_risks(
            {
                "HostConfig": {"Privileged": True, "CapAdd": ["SYS_ADMIN"], "NetworkMode": "host"},
                "Mounts": [{"Source": "/", "Destination": "/host"}],
            }
        )
        incus = agent._incus_security_risks(
            {
                "config": {"security.privileged": "true", "security.nesting": "true"},
                "expanded_devices": {"host-root": {"type": "disk", "source": "/", "path": "/host"}},
            }
        )
        self.assertIn("oci_privileged", {item["code"] for item in oci})
        self.assertIn("oci_sensitive_mount", {item["code"] for item in oci})
        self.assertIn("incus_privileged", {item["code"] for item in incus})
        self.assertIn("incus_sensitive_mount", {item["code"] for item in incus})
        oci_exposure = agent._oci_network_exposure(
            {
                "NetworkSettings": {
                    "Ports": {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "32001"}]}
                }
            }
        )
        incus_exposure = agent._incus_network_exposure(
            {
                "expanded_devices": {
                    "web": {
                        "type": "proxy",
                        "listen": "tcp:0.0.0.0:32002",
                        "connect": "tcp:127.0.0.1:8080",
                    }
                }
            }
        )
        self.assertEqual(oci_exposure[0]["listen"], "0.0.0.0:32001")
        self.assertEqual(oci_exposure[0]["target"], "8080/tcp")
        self.assertEqual(incus_exposure[0]["listen"], "tcp:0.0.0.0:32002")
        self.assertEqual(incus_exposure[0]["target"], "tcp:127.0.0.1:8080")

    def test_detects_panel_pairing_without_returning_api_keys(self):
        def fake_run(cmd):
            if "ps -eo comm,args" in cmd[-1]:
                return "xboard-node --config /etc/xboard-node/config.yml\n"
            return (
                "@@FILE:/etc/xboard-node/config.yml\n"
                "https://panel.example.net/api\n"
                "@@KEY:ApiHost\n@@KEY:ApiKey\n@@KEY:NodeID\n@@ENV\n"
            )

        env = {
            "SECURITY_PANEL_PROCESS_PATTERNS": "xboard-node,xrayr",
            "SECURITY_PANEL_CONFIG_PATHS": "/etc/xboard-node/config.yml",
            "SECURITY_ALLOWED_PANEL_DOMAINS": "trusted.example.com",
        }
        with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(agent, "run", side_effect=fake_run):
            result = agent.collect_panel_pairing_indicators("node", "podman")
        self.assertTrue(result["detected"])
        self.assertEqual(result["panel_domains"], ["panel.example.net"])
        self.assertEqual(result["unapproved_domains"], ["panel.example.net"])
        self.assertNotIn("secret", json.dumps(result))
        self.assertTrue(agent._panel_domain_allowed("api.trusted.example.com", ["trusted.example.com"]))
        self.assertFalse(agent._panel_domain_allowed("trusted.example.com.evil.test", ["trusted.example.com"]))

    def test_parses_caddy_and_nginx_access_logs(self):
        caddy = agent._parse_access_log_line(
            json.dumps(
                {
                    "request": {"client_ip": "203.0.113.5", "method": "GET", "uri": "/login"},
                    "status": 429,
                }
            )
        )
        nginx = agent._parse_access_log_line(
            '198.51.100.2 - - [25/Aug/2026:10:00:00 +0800] "POST /api/login HTTP/1.1" 403 12 "-" "curl"'
        )
        self.assertEqual(caddy, {"ip": "203.0.113.5", "status": 429, "method": "GET", "uri": "/login"})
        self.assertEqual(nginx["ip"], "198.51.100.2")
        self.assertEqual(nginx["status"], 403)

    def test_access_log_reader_only_counts_new_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "access.log"
            path.write_text(
                '198.51.100.2 - - [x] "GET / HTTP/1.1" 200 1 "-" "x"\n',
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {"SECURITY_ACCESS_LOG_PATHS": str(path)}, clear=False):
                first = agent._collect_access_log_stats(10)
                with path.open("a", encoding="utf-8") as handle:
                    handle.write('198.51.100.2 - - [x] "GET /x HTTP/1.1" 404 1 "-" "x"\n')
                second = agent._collect_access_log_stats(10)
            self.assertEqual(first["requests"], 0)
            self.assertEqual(second["requests"], 1)
            self.assertEqual(second["status_4xx"], 1)

    def test_container_access_log_reader_scans_logs_inside_runtime(self):
        state = {"size": 100}

        def fake_run(cmd):
            shell = cmd[-1]
            if "wc -c" in shell:
                return str(state["size"])
            if "tail -c" in shell:
                return '203.0.113.9 - - [x] "GET /.env HTTP/1.1" 403 1 "-" "x"\n'
            return ""

        container = {"name": "xboard", "runtime": "docker", "runtime_bin": "docker", "project": ""}
        env = {"SECURITY_CONTAINER_ACCESS_LOG_PATHS": "/var/log/nginx/access.log"}
        with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(agent, "run", side_effect=fake_run):
            first = agent._collect_container_access_log_stats(container, 10)
            state["size"] = 200
            second = agent._collect_container_access_log_stats(container, 10)
        self.assertEqual(first["requests"], 0)
        self.assertEqual(second["requests"], 1)
        self.assertEqual(second["suspicious_requests"], 1)

    def test_security_summary_emits_all_detector_categories(self):
        container = {
            "name": "panel",
            "runtime": "podman",
            "project": "",
            "net_rx_bps": 200,
            "net_tx_bps": 200,
            "security": {
                "net_rx_pps": 200,
                "net_tx_pps": 200,
                "syn_recv_count": 20,
                "scan_unique_ports_max": 8,
                "scan_source_ip": "203.0.113.10",
                "outbound_unique_ips": 20,
                "suspicious_outbound_connections": 5,
                "protocol_rates": {
                    "Tcp_ActiveOpens_per_second": 20,
                    "Tcp_AttemptFails_per_second": 10,
                    "Udp_OutDatagrams_per_second": 200,
                },
                "configuration_risks": [
                    {"code": "oci_privileged", "severity": "critical", "message": "privileged"}
                ],
                "process_count": 20,
                "panel_pairing": {
                    "detected": True,
                    "process_patterns": ["xboard-node"],
                    "config_files": ["/etc/xboard-node/config.yml"],
                    "panel_domains": ["panel.example.net"],
                    "unapproved_domains": ["panel.example.net"],
                },
            },
        }
        env = {
            "SECURITY_MONITOR_ENABLED": "true",
            "SECURITY_ACCESS_LOG_PATHS": "",
            "ALERT_DDOS_RX_BPS": "100",
            "ALERT_DDOS_RX_PPS": "100",
            "ALERT_DDOS_SYN_RECV": "10",
            "ALERT_SCAN_UNIQUE_PORTS": "5",
            "ALERT_ABUSE_OUTBOUND_UNIQUE_IPS": "10",
            "ALERT_ABUSE_SUSPICIOUS_CONNECTIONS": "3",
            "ALERT_ABUSE_TX_BPS": "100",
            "ALERT_ABUSE_TX_PPS": "100",
            "ALERT_ABUSE_TCP_OPENS_PER_SEC": "10",
            "ALERT_ABUSE_TCP_FAILS_PER_SEC": "5",
            "ALERT_ABUSE_UDP_OUT_PER_SEC": "100",
            "ALERT_ABUSE_PROCESS_COUNT": "10",
            "SECURITY_CONFIG_AUDIT_ENABLED": "true",
            "SECURITY_PANEL_PAIRING_DETECTION_ENABLED": "true",
            "SECURITY_ALLOWED_PANEL_DOMAINS": "trusted.example.com",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            result = agent.collect_security_summary([container], 60)
        types = {item["type"] for item in result["alerts"]}
        self.assertTrue(
            {
                "ddos_bandwidth",
                "ddos_packets",
                "ddos_syn",
                "port_scan",
                "outbound_fanout",
                "outbound_sensitive_ports",
                "outbound_bandwidth_abuse",
                "outbound_packet_abuse",
                "outbound_connection_churn",
                "outbound_connection_failures",
                "udp_outbound_flood",
                "container_security_risk",
                "process_fanout_abuse",
                "unauthorized_panel_pairing",
            }.issubset(types)
        )

    def test_security_summary_detects_http_cc_signals(self):
        access_stats = {
            "enabled": True,
            "readable_files": 1,
            "requests": 200,
            "requests_per_second": 20.0,
            "unique_ips": 2,
            "top_ip": "203.0.113.8",
            "top_ip_requests": 150,
            "top_ip_requests_per_second": 15.0,
            "status_4xx": 150,
            "status_5xx": 0,
            "top_ip_4xx": "203.0.113.8",
            "top_ip_4xx_requests": 30,
            "suspicious_requests": 12,
            "suspicious_unique_paths": 3,
            "top_scanner_ip": "203.0.113.8",
            "parse_errors": 0,
        }
        env = {
            "SECURITY_MONITOR_ENABLED": "true",
            "ALERT_CC_TOTAL_RPS": "10",
            "ALERT_CC_IP_RPS": "10",
            "ALERT_CC_4XX_RATE": "0.5",
            "ALERT_CC_MIN_REQUESTS": "50",
            "ALERT_WEB_SCAN_REQUESTS": "10",
            "ALERT_AUTH_FAILURES_PER_IP": "20",
        }
        with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(
            agent, "_collect_access_log_stats", return_value=access_stats
        ):
            result = agent.collect_security_summary([], 10)
        self.assertEqual(
            {item["type"] for item in result["alerts"]},
            {"cc_total_rps", "cc_single_ip", "cc_4xx_ratio", "web_scan", "http_abuse"},
        )

    def test_container_access_log_alert_keeps_container_identity(self):
        container = {
            "name": "xboard",
            "runtime": "docker",
            "project": "",
            "security": {
                "access_log": {
                    "requests": 20,
                    "requests_per_second": 20,
                    "top_ip_requests_per_second": 0,
                    "status_4xx": 0,
                }
            },
        }
        with mock.patch.dict(
            os.environ,
            {"SECURITY_ACCESS_LOG_PATHS": "", "ALERT_CC_TOTAL_RPS": "10"},
            clear=False,
        ):
            result = agent.collect_security_summary([container], 10)
        alert = next(item for item in result["alerts"] if item["type"] == "cc_total_rps")
        self.assertEqual(alert["container_name"], "xboard")
        self.assertEqual(alert["runtime"], "docker")

    def test_suspicious_process_is_reported_for_monitored_container(self):
        process_output = "PID %CPU COMMAND COMMAND\n42 88.0 xmrig /tmp/xmrig --donate-level 1\n"
        with mock.patch.dict(
            os.environ,
            {"SECURITY_SUSPICIOUS_PROCESS_PATTERNS": "xmrig", "SECURITY_ACCESS_LOG_PATHS": ""},
            clear=False,
        ), mock.patch.object(agent, "run", return_value=process_output):
            processes = agent.collect_suspicious_processes("panel", "podman")
        container = {
            "name": "panel",
            "runtime": "podman",
            "project": "",
            "security": {"suspicious_processes": processes},
        }
        with mock.patch.dict(os.environ, {"SECURITY_ACCESS_LOG_PATHS": ""}, clear=False):
            result = agent.collect_security_summary([container], 60)
        alert = next(item for item in result["alerts"] if item["type"] == "malicious_process")
        self.assertEqual(alert["severity"], "critical")
        self.assertEqual(alert["container_name"], "panel")
if __name__ == "__main__":
    unittest.main()
