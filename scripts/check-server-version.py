#!/usr/bin/env python3
"""Authenticate the Server version before allowing a Client update."""

import argparse
import hashlib
import hmac
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse


class UpdateDeferred(RuntimeError):
    """The Server is healthy or temporarily unavailable but not ready yet."""


def normalize_server_url(value: str) -> str:
    cleaned = value.strip().rstrip("/")
    if not urlparse(cleaned).scheme:
        cleaned = f"https://{cleaned}"
    return cleaned


def check_server_version(
    server_url: str,
    secret: str,
    expected_version: str,
    ca_file: str = "",
    timeout: float = 12.0,
) -> str:
    server_url = normalize_server_url(server_url)
    body = json.dumps(
        {"expected_version": expected_version}, separators=(",", ":")
    ).encode()
    timestamp = str(int(time.time()))
    signature = hmac.new(
        secret.encode(), body + timestamp.encode(), hashlib.sha256
    ).hexdigest()
    request = urllib.request.Request(
        f"{server_url}/api/v1/update/version",
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Narwhal-Client-Updater/1.0",
            "X-Timestamp": timestamp,
            "X-Signature": signature,
        },
        method="POST",
    )
    context = ssl.create_default_context(cafile=ca_file or None)
    try:
        with urllib.request.urlopen(request, context=context, timeout=timeout) as response:
            response_body = response.read(65537)
            response_signature = response.headers.get(
                "X-Narwhal-Response-Signature", ""
            )
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 409, 425, 503):
            raise UpdateDeferred(
                f"Server version gate is not ready (HTTP {exc.code})"
            ) from exc
        raise RuntimeError(f"Server version gate returned HTTP {exc.code}") from exc
    except (OSError, urllib.error.URLError) as exc:
        raise UpdateDeferred(f"cannot reach Server version gate: {exc}") from exc
    if len(response_body) > 65536:
        raise RuntimeError("Server version response is too large")
    expected_signature = hmac.new(
        secret.encode(), response_body + timestamp.encode(), hashlib.sha256
    ).hexdigest()
    if not response_signature or not hmac.compare_digest(
        expected_signature, response_signature
    ):
        raise RuntimeError("Server version response signature verification failed")
    try:
        payload = json.loads(response_body)
    except (UnicodeDecodeError, ValueError) as exc:
        raise RuntimeError("Server version response is invalid JSON") from exc
    server_version = str(payload.get("server_version") or "")
    if not payload.get("ready") or server_version != expected_version:
        raise UpdateDeferred(
            f"Server v{server_version or 'unknown'} has not reached v{expected_version}"
        )
    return server_version


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-url", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--ca-file", default="")
    parser.add_argument("--timeout", type=float, default=12.0)
    secret_group = parser.add_mutually_exclusive_group(required=True)
    secret_group.add_argument("--secret")
    secret_group.add_argument("--secret-stdin", action="store_true")
    args = parser.parse_args()
    secret = (sys.stdin.read() if args.secret_stdin else args.secret or "").strip()
    if not secret:
        print("[ERROR] shared secret is empty", file=sys.stderr)
        return 1
    try:
        server_version = check_server_version(
            args.server_url,
            secret,
            args.expected_version,
            args.ca_file,
            args.timeout,
        )
    except UpdateDeferred as exc:
        print(f"[WAIT] {exc}", file=sys.stderr)
        return 10
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    print(f"Server v{server_version} is ready for the Client update.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
