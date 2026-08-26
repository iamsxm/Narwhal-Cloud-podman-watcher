import hashlib
import hmac
import importlib.util
import json
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "narwhal_version_gate", ROOT / "scripts" / "check-server-version.py"
)
assert SPEC and SPEC.loader
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class FakeResponse:
    def __init__(self, body: bytes, headers: dict[str, str]):
        self.body = body
        self.headers = headers

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size: int = -1) -> bytes:
        return self.body[:size] if size >= 0 else self.body


class VersionGateTests(unittest.TestCase):
    def test_signed_matching_server_version_allows_client_update(self):
        secret = "shared-secret"
        timestamp = "1234567890"
        response_body = json.dumps(
            {
                "ok": True,
                "server_version": "1.5.0",
                "expected_version": "1.5.0",
                "ready": True,
            },
            separators=(",", ":"),
        ).encode()
        signature = hmac.new(
            secret.encode(), response_body + timestamp.encode(), hashlib.sha256
        ).hexdigest()
        response = FakeResponse(
            response_body, {"X-Narwhal-Response-Signature": signature}
        )
        with mock.patch.object(gate.time, "time", return_value=int(timestamp)), mock.patch.object(
            gate.ssl, "create_default_context", return_value=object()
        ), mock.patch.object(gate.urllib.request, "urlopen", return_value=response):
            version = gate.check_server_version(
                "https://monitor.example.com", secret, "1.5.0"
            )
        self.assertEqual(version, "1.5.0")

    def test_older_server_defers_client_update(self):
        secret = "shared-secret"
        timestamp = "1234567890"
        response_body = json.dumps(
            {
                "ok": True,
                "server_version": "1.4.0",
                "expected_version": "1.5.0",
                "ready": False,
            },
            separators=(",", ":"),
        ).encode()
        signature = hmac.new(
            secret.encode(), response_body + timestamp.encode(), hashlib.sha256
        ).hexdigest()
        response = FakeResponse(
            response_body, {"X-Narwhal-Response-Signature": signature}
        )
        with mock.patch.object(gate.time, "time", return_value=int(timestamp)), mock.patch.object(
            gate.ssl, "create_default_context", return_value=object()
        ), mock.patch.object(gate.urllib.request, "urlopen", return_value=response):
            with self.assertRaises(gate.UpdateDeferred):
                gate.check_server_version(
                    "https://monitor.example.com", secret, "1.5.0"
                )

    def test_unsigned_version_response_is_rejected(self):
        response_body = b'{"server_version":"1.5.0","ready":true}'
        response = FakeResponse(response_body, {})
        with mock.patch.object(gate.ssl, "create_default_context", return_value=object()), mock.patch.object(
            gate.urllib.request, "urlopen", return_value=response
        ):
            with self.assertRaisesRegex(RuntimeError, "signature verification failed"):
                gate.check_server_version(
                    "https://monitor.example.com", "shared-secret", "1.5.0"
                )


if __name__ == "__main__":
    unittest.main()
