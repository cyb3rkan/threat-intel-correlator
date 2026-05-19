# tests/security/test_ssrf_corpus.py
"""SSRF corpus tests."""
from __future__ import annotations
from unittest.mock import patch
import pytest
from tic.domain.errors import SecurityViolationError
from tic.security.ssrf_guard import ensure_public_url


def _resolve(ip):
    def _inner(host, *_a, **_kw):
        return [(0, 0, 0, "", (ip, 0))]
    return _inner


@pytest.mark.parametrize("url", [
    "http://example.com/", "ftp://example.com/", "file:///etc/passwd",
    "gopher://example.com/", "ldap://example.com/", "//example.com/",
])
def test_non_https_schemes_rejected(url):
    with pytest.raises(SecurityViolationError):
        ensure_public_url(url)


@pytest.mark.parametrize("ip", [
    "169.254.169.254", "192.168.0.1", "10.0.0.1",
    "172.16.0.1", "172.31.255.255", "127.0.0.1", "::1", "0.0.0.0",
])
def test_private_ips_rejected(ip):
    with patch("socket.getaddrinfo", _resolve(ip)):
        with pytest.raises(SecurityViolationError):
            ensure_public_url("https://victim.internal/")


@pytest.mark.parametrize("url", [
    "https://metadata.google.internal/",
    "https://169.254.169.254/latest/meta-data/",
    "https://metadata.azure.com/",
])
def test_metadata_hostnames_rejected(url):
    with pytest.raises(SecurityViolationError):
        ensure_public_url(url)


def test_dns_rebinding_all_addresses_checked():
    def _multi(*_a, **_kw):
        return [(0, 0, 0, "", ("8.8.8.8", 0)), (0, 0, 0, "", ("10.0.0.1", 0))]
    with patch("socket.getaddrinfo", _multi):
        with pytest.raises(SecurityViolationError):
            ensure_public_url("https://rebind.example/")


def test_allowlisted_hostname_passes():
    with patch("socket.getaddrinfo", _resolve("10.0.0.50")):
        ensure_public_url("https://misp.internal/", extra_allowlist=frozenset({"misp.internal"}))


def test_allowlist_does_not_bypass_metadata():
    with pytest.raises(SecurityViolationError):
        ensure_public_url("https://metadata.google.internal/",
                          extra_allowlist=frozenset({"metadata.google.internal"}))


def test_public_ip_passes():
    with patch("socket.getaddrinfo", _resolve("8.8.8.8")):
        ensure_public_url("https://dns.google/")


def test_missing_host_rejected():
    with pytest.raises(SecurityViolationError):
        ensure_public_url("https:///path")
