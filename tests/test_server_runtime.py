import asyncio
import base64
import hashlib
import hmac
import importlib.util
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("narwhal_server", ROOT / "server" / "app.py")
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


class ServerRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        server.DB_PATH = str(Path(self.tmp.name) / "monitor.db")
        self.original_tls_ca_path = server.TLS_CA_CERT_PATH
        server.init_db()

    def tearDown(self):
        server.TLS_CA_CERT_PATH = self.original_tls_ca_path
        self.tmp.cleanup()

    def _insert(self, runtime: str, cpu: float, project: str = ""):
        now = int(time.time())
        payload = {"id": f"{runtime}-id", "name": "same-name", "runtime": runtime}
        conn = sqlite3.connect(server.DB_PATH)
        conn.execute(
            """
            INSERT INTO reports(
                host_id, container_name, runtime, project, cpu_percent, mem_bytes, mem_percent,
                net_rx_bps, net_tx_bps, conn_count, disk_file, disk_size_bytes,
                disk_used_percent, podman_network_ok_v4, podman_network_ok_v6, ts, payload_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            ("host", "same-name", runtime, project, cpu, 1, 1, 1, 1, 1, "", 0, 0, 1, 1, now, json.dumps(payload)),
        )
        conn.commit()
        conn.close()

    def test_latest_keeps_same_name_from_different_runtimes_separate(self):
        self._insert("docker", 10)
        self._insert("incus", 20, "default")
        response = server.latest()
        body = json.loads(response.body)
        self.assertEqual(len(body["items"]), 2)
        self.assertEqual({x["runtime"] for x in body["items"]}, {"docker", "incus"})

    def test_report_accepts_runtime_and_project_fields(self):
        now = int(time.time())
        payload = {
            "host_id": "host",
            "timestamp": now,
            "container_network": {"ipv4_ok": True, "ipv6_ok": False},
            "security": {
                "enabled": True,
                "total_rx_bps": 1234,
                "total_rx_pps": 12,
                "syn_recv_count": 3,
                "access_log": {"enabled": True, "readable_files": 1, "requests_per_second": 2},
                "alerts": [],
            },
            "containers": [
                {
                    "id": "c1",
                    "name": "app",
                    "runtime": "incus",
                    "project": "prod",
                    "cpu_percent": 2.5,
                }
            ],
        }
        body = json.dumps(payload).encode()

        class Request:
            async def body(self):
                return body

        timestamp = str(now)
        signature = hmac.new(
            server.SHARED_SECRET.encode(), body + timestamp.encode(), hashlib.sha256
        ).hexdigest()
        result = asyncio.run(server.report(Request(), timestamp, signature))
        self.assertEqual(result, {"ok": True, "records": 1, "new_alerts": 0})

        conn = sqlite3.connect(server.DB_PATH)
        row = conn.execute("SELECT runtime, project FROM reports").fetchone()
        conn.close()
        self.assertEqual(row, ("incus", "prod"))
        status = json.loads(server.security_status().body)
        self.assertEqual(status["items"][0]["total_rx_bps"], 1234)
        self.assertEqual(status["items"][0]["access_log"]["requests_per_second"], 2)

    def test_tls_ca_endpoint_authenticates_request_and_response(self):
        certificate = b"-----BEGIN CERTIFICATE-----\ntest-public-ca\n-----END CERTIFICATE-----\n"
        ca_path = Path(self.tmp.name) / "root.crt"
        ca_path.write_bytes(certificate)
        server.TLS_CA_CERT_PATH = str(ca_path)
        timestamp = str(int(time.time()))
        request_signature = hmac.new(
            server.SHARED_SECRET.encode(), timestamp.encode(), hashlib.sha256
        ).hexdigest()

        response = server.tls_ca(timestamp, request_signature)

        self.assertEqual(response.body, certificate)
        expected_response_signature = hmac.new(
            server.SHARED_SECRET.encode(), certificate + timestamp.encode(), hashlib.sha256
        ).hexdigest()
        self.assertEqual(response.headers["x-narwhal-ca-signature"], expected_response_signature)
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_security_alert_lifecycle_deduplicates_and_resolves(self):
        alert = {
            "type": "ddos_packets",
            "severity": "warning",
            "title": "packet flood",
            "message": "high pps",
            "value": 200,
            "threshold": 100,
            "runtime": "docker",
            "container_name": "panel",
        }
        conn = server.db()
        first = server.process_security_alerts(conn, "host", 100, [alert])
        second = server.process_security_alerts(conn, "host", 110, [alert])
        server.process_security_alerts(conn, "host", 120, [])
        conn.commit()
        row = conn.execute(
            "SELECT occurrence_count, status FROM security_alerts WHERE host_id='host'"
        ).fetchone()
        conn.close()
        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        self.assertEqual(tuple(row), (2, "resolved"))

    def test_security_alert_endpoint_returns_active_alerts(self):
        conn = server.db()
        server.process_security_alerts(
            conn,
            "host",
            int(time.time()),
            [{"type": "port_scan", "severity": "warning", "title": "scan", "message": "scan"}],
        )
        conn.commit()
        conn.close()
        response = server.security_alerts()
        body = json.loads(response.body)
        self.assertEqual(body["active_count"], 1)
        self.assertEqual(body["items"][0]["type"], "port_scan")

    def test_dashboard_basic_auth_validates_generated_credentials(self):
        original_user = server.DASHBOARD_USERNAME
        original_password = server.DASHBOARD_PASSWORD
        try:
            server.DASHBOARD_USERNAME = "narwhal-test"
            server.DASHBOARD_PASSWORD = "random-password"
            token = base64.b64encode(b"narwhal-test:random-password").decode()
            self.assertEqual(
                server.dashboard_user_from_authorization(f"Basic {token}"), "narwhal-test"
            )
            self.assertIsNone(server.dashboard_user_from_authorization("Basic invalid"))
            wrong = base64.b64encode(b"narwhal-test:wrong").decode()
            self.assertIsNone(server.dashboard_user_from_authorization(f"Basic {wrong}"))
        finally:
            server.DASHBOARD_USERNAME = original_user
            server.DASHBOARD_PASSWORD = original_password

    def test_panel_action_queue_and_agent_poll_are_signed(self):
        now = int(time.time())
        alert = {
            "type": "unauthorized_panel_pairing",
            "severity": "critical",
            "title": "panel",
            "message": "unapproved panel",
            "runtime": "incus",
            "project": "default",
            "container_name": "node1",
            "unapproved_domains": ["panel.example.net"],
            "process_patterns": ["v2bx"],
            "config_files": ["/etc/V2bX/config.json"],
        }
        conn = server.db()
        server.process_security_alerts(conn, "host1", now, [alert])
        conn.commit()
        alert_id = conn.execute("SELECT id FROM security_alerts").fetchone()["id"]
        conn.close()

        class State:
            dashboard_user = "operator"

        class DashboardRequest:
            state = State()

            async def json(self):
                return {"action": "remediate"}

        queued = asyncio.run(server.queue_security_action(alert_id, DashboardRequest()))
        queued_body = json.loads(queued.body)
        self.assertTrue(queued_body["queued"])
        self.assertEqual(queued_body["action"]["action_type"], "remediate_panel_pairing")

        poll_body = json.dumps({"host_id": "host1"}, separators=(",", ":")).encode()

        class PollRequest:
            async def body(self):
                return poll_body

        timestamp = str(now)
        signature = hmac.new(
            server.SHARED_SECRET.encode(), poll_body + timestamp.encode(), hashlib.sha256
        ).hexdigest()
        response = asyncio.run(server.poll_security_actions(PollRequest(), timestamp, signature))
        response_body = json.loads(response.body)
        self.assertEqual(len(response_body["actions"]), 1)
        expected = hmac.new(
            server.SHARED_SECRET.encode(), response.body + timestamp.encode(), hashlib.sha256
        ).hexdigest()
        self.assertEqual(response.headers["x-narwhal-response-signature"], expected)
        self.assertNotIn("stop_container", response.body.decode())

    def test_latest_keeps_same_incus_name_from_different_projects_separate(self):
        self._insert("incus", 10, "default")
        self._insert("incus", 20, "prod")
        response = server.latest()
        body = json.loads(response.body)
        self.assertEqual(len(body["items"]), 2)
        self.assertEqual({x["project"] for x in body["items"]}, {"default", "prod"})

    def test_schema_has_runtime_column(self):
        conn = sqlite3.connect(server.DB_PATH)
        names = {row[1] for row in conn.execute("PRAGMA table_info(reports)")}
        conn.close()
        self.assertIn("runtime", names)
        self.assertIn("project", names)

    def test_legacy_schema_is_migrated_without_losing_rows(self):
        conn = sqlite3.connect(server.DB_PATH)
        conn.execute("DROP TABLE reports")
        conn.execute(
            """
            CREATE TABLE reports (
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
            )
            """
        )
        conn.execute(
            """
            INSERT INTO reports(
                host_id, container_name, cpu_percent, mem_bytes, mem_percent,
                net_rx_bps, net_tx_bps, conn_count, podman_network_ok_v4,
                podman_network_ok_v6, ts, payload_json
            ) VALUES('legacy-host','legacy-container',1,1,1,1,1,1,1,1,1,'{}')
            """
        )
        conn.commit()
        conn.close()

        server.init_db()

        conn = sqlite3.connect(server.DB_PATH)
        row = conn.execute("SELECT runtime, project FROM reports").fetchone()
        conn.close()
        self.assertEqual(row, ("podman", ""))


if __name__ == "__main__":
    unittest.main()
