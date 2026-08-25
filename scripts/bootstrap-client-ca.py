#!/usr/bin/env python3
"""Securely bootstrap a Narwhal Server internal CA using the shared secret."""

import argparse
import hashlib
import hmac
import os
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

MAX_CA_BYTES = 64 * 1024


def normalize_server_url(value: str) -> str:
    cleaned = value.strip().rstrip("/")
    if not urlparse(cleaned).scheme:
        cleaned = f"https://{cleaned}"
    return cleaned


def is_certificate_error(exc: BaseException) -> bool:
    current: BaseException | None = exc
    while current is not None:
        if isinstance(current, (ssl.SSLCertVerificationError, ssl.CertificateError)):
            return True
        reason = getattr(current, "reason", None)
        current = reason if isinstance(reason, BaseException) else None
    return False


def probe_tls(server_url: str, context: ssl.SSLContext, timeout: float) -> None:
    request = urllib.request.Request(
        f"{server_url}/",
        headers={"User-Agent": "Narwhal-CA-Bootstrap/1.0"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, context=context, timeout=timeout) as response:
            response.read(1)
    except urllib.error.HTTPError:
        # TLS and hostname validation already succeeded; the HTTP status is irrelevant here.
        return


def fetch_signed_ca(server_url: str, secret: str, timeout: float) -> bytes:
    timestamp = str(int(time.time()))
    request_signature = hmac.new(secret.encode(), timestamp.encode(), hashlib.sha256).hexdigest()
    request = urllib.request.Request(
        f"{server_url}/api/v1/tls/ca",
        headers={
            "User-Agent": "Narwhal-CA-Bootstrap/1.0",
            "X-Timestamp": timestamp,
            "X-Signature": request_signature,
        },
        method="GET",
    )
    insecure_context = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(request, context=insecure_context, timeout=timeout) as response:
            certificate = response.read(MAX_CA_BYTES + 1)
            response_signature = response.headers.get("X-Narwhal-CA-Signature", "")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"CA endpoint returned HTTP {exc.code}; check the shared secret and Server version") from exc

    if len(certificate) > MAX_CA_BYTES:
        raise RuntimeError("CA response is too large")
    if not certificate.startswith(b"-----BEGIN CERTIFICATE-----"):
        raise RuntimeError("CA endpoint returned an invalid PEM certificate")
    try:
        ssl.PEM_cert_to_DER_cert(certificate.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise RuntimeError("CA endpoint returned an invalid certificate") from exc

    expected_signature = hmac.new(
        secret.encode(), certificate + timestamp.encode(), hashlib.sha256
    ).hexdigest()
    if not response_signature or not hmac.compare_digest(expected_signature, response_signature):
        raise RuntimeError("CA response signature verification failed")
    return certificate


def save_certificate(certificate: bytes, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=str(output.parent))
    try:
        with os.fdopen(fd, "wb") as temporary_file:
            temporary_file.write(certificate)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.chmod(temporary_name, 0o644)
        os.replace(temporary_name, output)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def bootstrap_ca(server_url: str, secret: str, output: Path, timeout: float = 12.0) -> str:
    server_url = normalize_server_url(server_url)
    if urlparse(server_url).scheme.lower() != "https":
        return ""

    system_context = ssl.create_default_context()
    try:
        probe_tls(server_url, system_context, timeout)
        return ""
    except Exception as exc:
        if not is_certificate_error(exc):
            raise RuntimeError(f"cannot connect to Server: {exc}") from exc

    if output.is_file():
        try:
            existing_context = ssl.create_default_context(cafile=str(output))
            probe_tls(server_url, existing_context, timeout)
            return str(output)
        except Exception as exc:
            print(f"[INFO] Existing CA is not valid for this Server: {exc}", file=sys.stderr)

    print("[INFO] Server certificate is not publicly trusted; requesting its signed internal CA...", file=sys.stderr)
    certificate = fetch_signed_ca(server_url, secret, timeout)
    save_certificate(certificate, output)

    downloaded_context = ssl.create_default_context(cafile=str(output))
    probe_tls(server_url, downloaded_context, timeout)
    print(f"[OK] Internal CA verified and saved to {output}", file=sys.stderr)
    return str(output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-url", required=True)
    secret_group = parser.add_mutually_exclusive_group(required=True)
    secret_group.add_argument("--secret")
    secret_group.add_argument("--secret-stdin", action="store_true")
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=float, default=12.0)
    args = parser.parse_args()
    try:
        secret = sys.stdin.read() if args.secret_stdin else args.secret
        if not secret:
            raise RuntimeError("shared secret is empty")
        selected_ca = bootstrap_ca(
            server_url=args.server_url,
            secret=secret,
            output=Path(args.output),
            timeout=args.timeout,
        )
    except Exception as exc:
        print(f"[ERROR] TLS CA bootstrap failed: {exc}", file=sys.stderr)
        return 1
    print(selected_ca)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
