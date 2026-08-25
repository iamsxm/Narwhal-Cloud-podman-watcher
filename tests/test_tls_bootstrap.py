import hashlib
import hmac
import importlib.util
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "narwhal_tls_bootstrap", ROOT / "scripts" / "bootstrap-client-ca.py"
)
assert SPEC and SPEC.loader
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


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


class TLSBootstrapTests(unittest.TestCase):
    def test_publicly_trusted_server_needs_no_custom_ca(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            bootstrap, "probe_tls", return_value=None
        ):
            selected = bootstrap.bootstrap_ca(
                "https://monitor.example.com", "secret", Path(directory) / "root.crt"
            )
        self.assertEqual(selected, "")

    def test_internal_ca_is_saved_after_signed_download(self):
        certificate = b"-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
        certificate_error = ssl.SSLCertVerificationError("untrusted")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "root.crt"
            with mock.patch.object(
                bootstrap, "probe_tls", side_effect=[certificate_error, None]
            ), mock.patch.object(
                bootstrap, "fetch_signed_ca", return_value=certificate
            ), mock.patch.object(
                bootstrap.ssl, "create_default_context", side_effect=[object(), object()]
            ):
                selected = bootstrap.bootstrap_ca("https://192.0.2.1", "secret", output)
            self.assertEqual(selected, str(output))
            self.assertEqual(output.read_bytes(), certificate)

    def test_ca_response_signature_is_verified(self):
        secret = "shared-secret"
        certificate = b"-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
        timestamp = "1234567890"
        signature = hmac.new(
            secret.encode(), certificate + timestamp.encode(), hashlib.sha256
        ).hexdigest()
        response = FakeResponse(certificate, {"X-Narwhal-CA-Signature": signature})
        with mock.patch.object(bootstrap.time, "time", return_value=int(timestamp)), mock.patch.object(
            bootstrap.urllib.request, "urlopen", return_value=response
        ), mock.patch.object(bootstrap.ssl, "PEM_cert_to_DER_cert", return_value=b"certificate"):
            result = bootstrap.fetch_signed_ca("https://192.0.2.1", secret, 1)
        self.assertEqual(result, certificate)


if __name__ == "__main__":
    unittest.main()
