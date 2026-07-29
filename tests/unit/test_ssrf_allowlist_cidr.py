# tests/unit/test_ssrf_allowlist_cidr.py
"""Finding #4: allowlisted hosts are IP-re-resolved and pinned to declared CIDRs."""
from __future__ import annotations

import socket
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from tic.domain.errors import SecurityViolationError
from tic.infra.config import ProviderConfig
from tic.security.ssrf_guard import ensure_public_url

_GAI = "tic.security.ssrf_guard.socket.getaddrinfo"
ALLOW = frozenset({"misp.local"})
LOOPBACK = frozenset({"127.0.0.0/8", "::1/128"})


def _resolve(ip: str) -> list:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return [(family, socket.SOCK_STREAM, 6, "", (ip, 0))]


def test_allowlist_without_cidr_is_documented_residual() -> None:
    # No declared CIDR -> allowlisted host is not range-checked (residual).
    with patch(_GAI, return_value=_resolve("10.0.0.5")):
        ensure_public_url(
            "https://misp.local/api", extra_allowlist=ALLOW, allowed_cidrs=frozenset()
        )  # must NOT raise


def test_allowlist_with_cidr_in_range_allowed() -> None:
    with patch(_GAI, return_value=_resolve("127.0.0.1")):
        ensure_public_url(
            "https://misp.local/api", extra_allowlist=ALLOW, allowed_cidrs=LOOPBACK
        )  # 127.0.0.1 in 127.0.0.0/8 -> allowed


def test_allowlist_with_cidr_rebind_to_private_rejected() -> None:
    with (
        patch(_GAI, return_value=_resolve("10.0.0.5")),
        pytest.raises(SecurityViolationError),
    ):
            ensure_public_url(
                "https://misp.local/api", extra_allowlist=ALLOW, allowed_cidrs=LOOPBACK
            )


def test_allowlist_with_cidr_rebind_to_metadata_rejected() -> None:
    with (
        patch(_GAI, return_value=_resolve("169.254.169.254")),
        pytest.raises(SecurityViolationError),
    ):
            ensure_public_url(
                "https://misp.local/api", extra_allowlist=ALLOW, allowed_cidrs=LOOPBACK
            )


def test_metadata_hostname_blocked_before_allowlist() -> None:
    # Even allowlisted + CIDR-declared, a metadata host name is blocked by the
    # unconditional substring check that runs first.
    with (
        patch(_GAI, return_value=_resolve("127.0.0.1")),
        pytest.raises(SecurityViolationError),
    ):
            ensure_public_url(
                "https://metadata.google.internal/x",
                extra_allowlist=frozenset({"metadata.google.internal"}),
                allowed_cidrs=LOOPBACK,
            )


def test_non_allowlisted_internal_ip_still_rejected() -> None:
    # Regression: the normal (non-allowlist) path still blocks internal IPs.
    with (
        patch(_GAI, return_value=_resolve("192.168.1.1")),
        pytest.raises(SecurityViolationError),
    ):
            ensure_public_url("https://example.com/x")


def test_ipv6_loopback_in_cidr_allowed() -> None:
    with patch(_GAI, return_value=_resolve("::1")):
        ensure_public_url(
            "https://misp.local/api", extra_allowlist=ALLOW, allowed_cidrs=LOOPBACK
        )


def test_ipv6_rebind_outside_cidr_rejected() -> None:
    with (
        patch(_GAI, return_value=_resolve("fd00::1")),
        pytest.raises(SecurityViolationError),
    ):
            ensure_public_url(
                "https://misp.local/api", extra_allowlist=ALLOW, allowed_cidrs=LOOPBACK
            )


def test_provider_config_accepts_and_normalizes_cidrs() -> None:
    cfg = ProviderConfig(
        keyring_service="s",
        keyring_user="u",
        allowed_hosts=["localhost"],
        allowed_host_cidrs=["127.0.0.0/8", "::1/128"],
    )
    assert cfg.allowed_host_cidrs == ["127.0.0.0/8", "::1/128"]


def test_provider_config_rejects_invalid_cidr() -> None:
    with pytest.raises(ValidationError):
        ProviderConfig(
            keyring_service="s", keyring_user="u", allowed_host_cidrs=["not-a-cidr"]
        )
