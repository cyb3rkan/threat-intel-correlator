# tests/unit/test_ssrf_guard.py
from __future__ import annotations

from unittest.mock import patch

import pytest

from tic.domain.errors import SecurityViolationError
from tic.security.ssrf_guard import ensure_public_url


def _mock_resolve(ip: str):
    return [(None, None, None, None, (ip, 0))]


def test_rejects_http_scheme() -> None:
    with pytest.raises(SecurityViolationError, match="scheme"):
        ensure_public_url("http://example.com/api")


def test_rejects_ftp_scheme() -> None:
    with pytest.raises(SecurityViolationError, match="scheme"):
        ensure_public_url("ftp://example.com/file")


def test_rejects_missing_host() -> None:
    with pytest.raises(SecurityViolationError):
        ensure_public_url("https:///path")


def test_rejects_loopback() -> None:
    with patch(
        "tic.security.ssrf_guard.socket.getaddrinfo", return_value=_mock_resolve("127.0.0.1")
    ):
        with pytest.raises(SecurityViolationError, match="disallowed IP"):
            ensure_public_url("https://localhost/api")


def test_rejects_private_ip() -> None:
    with patch(
        "tic.security.ssrf_guard.socket.getaddrinfo", return_value=_mock_resolve("192.168.1.1")
    ):
        with pytest.raises(SecurityViolationError, match="disallowed IP"):
            ensure_public_url("https://internal.corp/api")


def test_rejects_link_local() -> None:
    with patch(
        "tic.security.ssrf_guard.socket.getaddrinfo", return_value=_mock_resolve("169.254.1.1")
    ):
        with pytest.raises(SecurityViolationError, match="disallowed IP"):
            ensure_public_url("https://linklocal.example/")


def test_rejects_metadata_hostname() -> None:
    with pytest.raises(SecurityViolationError, match="blocked host"):
        ensure_public_url("https://169.254.169.254/latest/meta-data/")


def test_rejects_google_metadata() -> None:
    with pytest.raises(SecurityViolationError, match="blocked host"):
        ensure_public_url("https://metadata.google.internal/computeMetadata/v1/")


def test_allows_explicit_allowlist() -> None:
    with patch(
        "tic.security.ssrf_guard.socket.getaddrinfo", return_value=_mock_resolve("10.0.0.5")
    ):
        # Should NOT raise because host is in allowlist
        ensure_public_url("https://misp.internal/api", extra_allowlist=frozenset({"misp.internal"}))


def test_rejects_dns_failure() -> None:
    import socket

    with patch(
        "tic.security.ssrf_guard.socket.getaddrinfo", side_effect=socket.gaierror("nxdomain")
    ):
        with pytest.raises(SecurityViolationError, match="dns resolve failed"):
            ensure_public_url("https://nonexistent.invalid/")


def test_allows_public_ip() -> None:
    with patch("tic.security.ssrf_guard.socket.getaddrinfo", return_value=_mock_resolve("8.8.8.8")):
        ensure_public_url("https://dns.google/")  # should not raise
