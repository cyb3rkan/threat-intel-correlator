# tests/unit/test_prompt_input_truncation.py
"""Phase C: input truncation behaviour.

Truncation strategy:
  1. Drop trailing `matches` entries until the payload fits.
  2. If still oversized, drop trailing `enrichments` entries.
  3. Required fields (finding_id, ioc_type, ioc_pseudo, severity, score,
     match_count, etc.) are NEVER touched.
  4. If the required-fields core is itself too large for `max_input_chars`,
     return `(RedactedFinding, meta)` where `meta["final_chars"]` still
     exceeds `max_chars`. The Narrator interprets this as fail-safe None
     and skips invocation.

The Narrator emits an `ai_input_truncated` audit event containing only
counts — never the dropped content.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from tic.application.ai.narrator import Narrator
from tic.application.ai.prompt_builder import _truncate_redacted
from tic.application.redaction import RedactedFinding, Redactor
from tic.domain.finding import (
    EnrichmentResult,
    Finding,
    Match,
    Severity,
)
from tic.domain.ioc import IOC, IOCType


_HMAC_KEY = b"0" * 32


def _bulk_finding(*, n_matches: int = 100, n_enrichments: int = 4) -> Finding:
    matches = [
        Match(
            log_source=f"host-{i}.corp.local",
            field="src_ip",
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            raw_line_hash="a" * 64,
        )
        for i in range(n_matches)
    ]
    enrichments = [
        EnrichmentResult(
            provider=f"prov_{i}"[:64],
            reputation_score=50 + i,
            tags=frozenset({f"tag{i}"}),
            fetched_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
            ttl_seconds=3600,
        )
        for i in range(n_enrichments)
    ]
    return Finding(
        finding_id="00000000-0000-4000-8000-000000000001",
        ioc=IOC(value="evil.example.com", ioc_type=IOCType.DOMAIN, source="feed"),
        matches=matches,
        enrichments=enrichments,
        score=70,
        severity=Severity.HIGH,
        profile_hash="a" * 64,
        correlation_id="cid",
        created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )


def _redact(f: Finding) -> RedactedFinding:
    return Redactor(_HMAC_KEY).redact(f)


# ---------------------------------------------------------------------------
# _truncate_redacted directly
# ---------------------------------------------------------------------------


def test_no_truncation_when_payload_fits() -> None:
    redacted = _redact(_bulk_finding(n_matches=2, n_enrichments=1))
    new, meta = _truncate_redacted(redacted, max_chars=10_000)
    assert new == redacted
    assert meta["dropped_matches_count"] == 0
    assert meta["dropped_enrichments_count"] == 0
    assert meta["final_chars"] == meta["original_chars"]


def test_truncation_drops_matches_first() -> None:
    redacted = _redact(_bulk_finding(n_matches=25, n_enrichments=4))
    new, meta = _truncate_redacted(redacted, max_chars=600)
    assert meta["dropped_matches_count"] > 0
    # We dropped matches before touching enrichments (unless matches alone
    # were enough to bring us under).
    assert meta["dropped_enrichments_count"] >= 0
    # Required fields preserved.
    assert new.finding_id == redacted.finding_id
    assert new.ioc_pseudo == redacted.ioc_pseudo
    assert new.severity == redacted.severity
    assert new.score == redacted.score


def test_truncation_drops_enrichments_if_matches_alone_insufficient() -> None:
    """Set a very tight budget so we MUST drop both matches and
    enrichments to fit."""
    redacted = _redact(_bulk_finding(n_matches=25, n_enrichments=4))
    new, meta = _truncate_redacted(redacted, max_chars=350)
    assert meta["dropped_matches_count"] > 0
    assert meta["dropped_enrichments_count"] > 0
    # Required identity remains intact.
    assert new.finding_id == redacted.finding_id
    assert new.ioc_pseudo == redacted.ioc_pseudo


def test_truncation_meta_carries_only_counts() -> None:
    redacted = _redact(_bulk_finding(n_matches=25, n_enrichments=4))
    _, meta = _truncate_redacted(redacted, max_chars=400)
    # No content keys leaked.
    for forbidden in ("matches", "enrichments", "ioc_pseudo", "source"):
        assert forbidden not in meta
    # Keys are exactly the documented Phase C set.
    assert set(meta.keys()) == {
        "original_chars",
        "final_chars",
        "dropped_matches_count",
        "dropped_enrichments_count",
    }


def test_truncation_returns_oversized_when_core_too_large() -> None:
    """If even an empty-matches/empty-enrichments payload is larger than
    the budget, `final_chars` stays above `max_chars`. The Narrator
    detects this and skips invocation."""
    redacted = _redact(_bulk_finding(n_matches=0, n_enrichments=0))
    # Use a budget that is impossible to satisfy.
    _, meta = _truncate_redacted(redacted, max_chars=10)
    assert meta["final_chars"] > 10


# ---------------------------------------------------------------------------
# Narrator audit + fail-safe behaviour
# ---------------------------------------------------------------------------


class _RecordingAudit:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def append(self, event_type, payload):
        self.events.append((event_type, dict(payload)))

    def verify_chain(self):
        return True


class _OkAI:
    async def narrate(self, _redacted):
        from tic.domain.finding import AINarrative
        return AINarrative(
            summary="ok",
            false_positive_likelihood="low",
            suggested_actions=["Review in SIEM"],
            confidence="medium",
            model="placeholder",
            generated_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        )


@pytest.mark.asyncio
async def test_narrator_emits_ai_input_truncated_when_truncation_happens() -> None:
    audit = _RecordingAudit()
    narrator = Narrator(_OkAI(), Redactor(_HMAC_KEY), audit=audit, max_input_chars=400)
    f = _bulk_finding(n_matches=25, n_enrichments=4)
    result = await narrator.narrate(f)
    assert result.ai_narrative is not None
    trunc_events = [e for e in audit.events if e[0] == "ai_input_truncated"]
    assert len(trunc_events) == 1
    payload = trunc_events[0][1]
    assert payload["finding_id"] == f.finding_id
    assert payload["dropped_matches_count"] > 0
    assert payload["original_chars"] > payload["final_chars"]
    # Metadata only — never content.
    blob = json.dumps(audit.events, default=str)
    assert "evil.example.com" not in blob
    assert "host-0.corp.local" not in blob


@pytest.mark.asyncio
async def test_narrator_returns_original_when_payload_too_large_to_fit() -> None:
    """A degenerate input whose required core exceeds the budget yields a
    fail-safe pass-through: original Finding, no narrative."""
    audit = _RecordingAudit()
    narrator = Narrator(_OkAI(), Redactor(_HMAC_KEY), audit=audit, max_input_chars=10)
    f = _bulk_finding(n_matches=0, n_enrichments=0)
    result = await narrator.narrate(f)
    assert result.ai_narrative is None
    rejected = [e for e in audit.events if e[0] == "ai_response_rejected"]
    assert len(rejected) == 1
    assert rejected[0][1]["reason"] == "input_too_large"


@pytest.mark.asyncio
async def test_narrator_does_not_emit_truncation_event_when_payload_fits() -> None:
    audit = _RecordingAudit()
    narrator = Narrator(_OkAI(), Redactor(_HMAC_KEY), audit=audit, max_input_chars=10_000)
    await narrator.narrate(_bulk_finding(n_matches=2, n_enrichments=1))
    assert not any(e[0] == "ai_input_truncated" for e in audit.events)
