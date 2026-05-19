# tests/unit/test_domain_models.py
"""Tests for newly added domain models: LogEvent, Asset."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from tic.domain.asset import Asset, AssetCriticality
from tic.domain.log_event import LogEvent


def test_log_event_requires_raw_line_hash_exact_length() -> None:
    with pytest.raises(ValidationError):
        LogEvent(
            timestamp=datetime.now(timezone.utc),
            source="x",
            raw_line_hash="tooshort",
        )


def test_log_event_is_frozen() -> None:
    ev = LogEvent(
        timestamp=datetime.now(timezone.utc),
        source="s",
        raw_line_hash="a" * 64,
    )
    with pytest.raises(ValidationError):
        ev.source = "other"  # type: ignore[misc]


def test_log_event_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        LogEvent(  # type: ignore[call-arg]
            timestamp=datetime.now(timezone.utc),
            source="s",
            raw_line_hash="a" * 64,
            nope="x",
        )


def test_log_event_accepts_optional_fields() -> None:
    ev = LogEvent(
        timestamp=datetime.now(timezone.utc),
        source="firewall",
        src_ip="10.0.0.1",
        dst_ip="8.8.8.8",
        url="https://example.com/x",
        hash_fields={"sha256": "a" * 64},
        host="web-01",
        user="svc-account",
        raw_line_hash="b" * 64,
    )
    assert ev.src_ip == "10.0.0.1"
    assert ev.hash_fields["sha256"] == "a" * 64


def test_asset_defaults_medium_criticality() -> None:
    a = Asset(hostname="web-01")
    assert a.criticality == AssetCriticality.MEDIUM
    assert a.criticality.weight == 0.5


def test_asset_criticality_weights_monotonic() -> None:
    weights = [c.weight for c in AssetCriticality]
    assert weights == sorted(weights)
    assert weights[0] < weights[-1]


def test_asset_is_frozen() -> None:
    a = Asset(hostname="h")
    with pytest.raises(ValidationError):
        a.hostname = "x"  # type: ignore[misc]


def test_asset_accepts_optional_fields() -> None:
    a = Asset(
        hostname="db-01",
        ip="10.0.0.5",
        owner_email="ops@example.com",
        criticality=AssetCriticality.CRITICAL,
        os="Ubuntu 22.04",
        location="eu-west-1",
        tags=frozenset({"prod", "finance"}),
    )
    assert a.criticality == AssetCriticality.CRITICAL
    assert "prod" in a.tags
