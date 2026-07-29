# tests/unit/test_redaction.py
from __future__ import annotations

import json
from datetime import UTC, datetime

from tic.application.redaction import Redactor
from tic.domain.finding import Finding, Match, Severity
from tic.domain.ioc import IOC, IOCType

_HMAC_KEY = b"0" * 32


def _finding(ioc_value: str = "evil.example.com") -> Finding:
    ioc = IOC(value=ioc_value, ioc_type=IOCType.DOMAIN, source="test")
    return Finding(
        finding_id="00000000-0000-4000-8000-000000000000",
        ioc=ioc,
        matches=[
            Match(
                log_source="internal-host-01.corp.local",
                field="user_email",
                timestamp=datetime(2025, 1, 1, tzinfo=UTC),
                raw_line_hash="a" * 64,
            )
        ],
        enrichments=[],
        score=50,
        severity=Severity.MEDIUM,
        profile_hash="b" * 64,
        correlation_id="cid",
        created_at=datetime(2025, 1, 1, tzinfo=UTC),
    )


def test_redaction_hides_raw_ioc_value() -> None:
    r = Redactor(_HMAC_KEY)
    redacted = r.redact(_finding("supersecret.evil.com"))
    payload = json.dumps(redacted.model_dump())
    assert "supersecret.evil.com" not in payload


def test_redaction_hides_internal_hostname() -> None:
    r = Redactor(_HMAC_KEY)
    redacted = r.redact(_finding())
    payload = json.dumps(redacted.model_dump())
    assert "internal-host-01.corp.local" not in payload


def test_pseudonymization_stable() -> None:
    r = Redactor(_HMAC_KEY)
    p1 = r.redact(_finding("x.com")).ioc_pseudo
    p2 = r.redact(_finding("x.com")).ioc_pseudo
    assert p1 == p2


def test_pseudonymization_key_sensitive() -> None:
    r1 = Redactor(_HMAC_KEY)
    r2 = Redactor(b"1" * 32)
    assert r1.redact(_finding()).ioc_pseudo != r2.redact(_finding()).ioc_pseudo


# ---------------------------------------------------------------------------
# Phase A additions: freeze the contract that output_mode does NOT influence
# what is sent to AI. Even in analyst mode (where the operator sees the raw
# IOC in the UI), the AI must only ever see the HMAC pseudonym.
# ---------------------------------------------------------------------------


def test_redacted_finding_never_contains_raw_ioc_value_regardless_of_mode() -> None:
    """The Redactor takes a Finding and emits a RedactedFinding. The
    output_mode (analyst/summary/hash) is a *rendering* concern and lives
    elsewhere (PublicFinding) — it must not affect the AI input path."""
    r = Redactor(_HMAC_KEY)
    raw = "very-secret-ioc-value.example"
    redacted = r.redact(_finding(raw))
    blob = redacted.model_dump_json()
    assert raw not in blob
    # ioc_pseudo is always present and is an opaque pseudonym.
    assert redacted.ioc_pseudo
    assert raw not in redacted.ioc_pseudo


def test_redacted_finding_has_no_log_source_or_raw_line_hash() -> None:
    """Match-level fields that could re-identify a host or a log line are
    replaced with generic categorisations. The raw_line_hash never crosses
    into the AI input layer at all."""
    r = Redactor(_HMAC_KEY)
    redacted = r.redact(_finding("evil.example.com"))
    payload = redacted.model_dump_json()
    assert "internal-host-01.corp.local" not in payload
    assert "raw_line_hash" not in payload
    # `field` is genericised into a fixed enum value.
    if redacted.matches:
        assert redacted.matches[0].field_generic in {
            "network",
            "host",
            "user",
            "hash",
            "url",
            "other",
        }


def test_redactor_rejects_short_hmac_key() -> None:
    """The Redactor's constructor must enforce a 32-byte minimum HMAC key —
    a deterministic zero-key fallback would let attackers correlate IOCs
    across deployments."""
    import pytest

    with pytest.raises(ValueError, match="32 bytes"):
        Redactor(b"too-short")
