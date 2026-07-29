# tests/unit/test_output_modes.py
"""Tests for PublicFinding output modes."""

from __future__ import annotations

from datetime import UTC, datetime

from tic.domain.finding import Finding, OutputMode, Severity
from tic.domain.ioc import IOC, IOCType


def _finding(value="evil.example.com", ioc_type=IOCType.DOMAIN):
    return Finding(
        finding_id="00000000-0000-4000-8000-000000000000",
        ioc=IOC(value=value, ioc_type=ioc_type, source="test"),
        matches=[],
        enrichments=[],
        score=60,
        severity=Severity.MEDIUM,
        profile_hash="a" * 64,
        correlation_id="cid",
        created_at=datetime(2025, 1, 1, tzinfo=UTC),
    )


def test_analyst_mode_full_value():
    pub = _finding("evil.example.com").to_public(mode=OutputMode.ANALYST)
    assert pub.ioc_value == "evil.example.com"


def test_summary_mode_truncates():
    pub = _finding("evil.example.com").to_public(mode=OutputMode.SUMMARY)
    assert pub.ioc_value.endswith("…")
    assert "evil.example.com" not in pub.ioc_value


def test_hash_mode_produces_hmac_prefix():
    pub = _finding("1.2.3.4", ioc_type=IOCType.IP).to_public(
        mode=OutputMode.HASH, hmac_key=b"k" * 32
    )
    assert pub.ioc_value.startswith("hmac:")


def test_hash_mode_deterministic():
    f = _finding("1.2.3.4", ioc_type=IOCType.IP)
    key = b"k" * 32
    p1 = f.to_public(mode=OutputMode.HASH, hmac_key=key)
    p2 = f.to_public(mode=OutputMode.HASH, hmac_key=key)
    assert p1.ioc_value == p2.ioc_value


def test_hash_mode_key_sensitive():
    f = _finding("1.2.3.4", ioc_type=IOCType.IP)
    p1 = f.to_public(mode=OutputMode.HASH, hmac_key=b"a" * 32)
    p2 = f.to_public(mode=OutputMode.HASH, hmac_key=b"b" * 32)
    assert p1.ioc_value != p2.ioc_value


def test_score_and_severity_never_changed_by_mode():
    f = _finding()
    for mode in (OutputMode.ANALYST, OutputMode.SUMMARY, OutputMode.HASH):
        pub = f.to_public(mode=mode, hmac_key=b"k" * 32)
        assert pub.score == f.score
        assert pub.severity == f.severity.value
