# tests/unit/test_narrator_audit.py
"""Phase B: freeze the Narrator's audit-hook contract.

Audit events are metadata-only. Bodies, completions, headers, API keys,
raw IOC values, and raw provider payloads must never appear in any audit
event. Audit-write failures must be isolated from the sweep.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from tic.application.ai.narrator import Narrator
from tic.application.redaction import Redactor
from tic.domain.finding import AINarrative, Finding, Severity
from tic.domain.ioc import IOC, IOCType

_HMAC_KEY = b"0" * 32
_RAW_IOC = "very-secret-raw-ioc.example"


def _finding() -> Finding:
    return Finding(
        finding_id="00000000-0000-4000-8000-000000000001",
        ioc=IOC(value=_RAW_IOC, ioc_type=IOCType.DOMAIN, source="feed"),
        matches=[],
        enrichments=[],
        score=60,
        severity=Severity.MEDIUM,
        profile_hash="a" * 64,
        correlation_id="cid",
        created_at=datetime(2025, 1, 1, tzinfo=UTC),
    )


def _narrative() -> AINarrative:
    return AINarrative(
        summary="Defensive narrative.",
        false_positive_likelihood="low",
        suggested_actions=["Review in SIEM"],
        confidence="medium",
        model="placeholder-model",
        generated_at=datetime(2025, 1, 1, tzinfo=UTC),
    )


class _RecordingAudit:
    """In-memory audit logger. Stores (event_type, payload) tuples for
    inspection. Implements the AuditLogger Protocol contract."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def append(self, event_type: str, payload: dict) -> None:
        # Defensive copy: store dict by value, not reference, so later
        # mutation in the SUT cannot retroactively change history.
        self.events.append((event_type, dict(payload)))

    def verify_chain(self) -> bool:
        return True


class _AlwaysFailAudit:
    """Audit sink that always raises. Used to verify the Narrator isolates
    audit-write failures from the sweep."""

    def append(self, event_type: str, payload: dict) -> None:
        raise OSError("simulated audit-write failure")

    def verify_chain(self) -> bool:
        return False


class _OkAI:
    async def narrate(self, _redacted):
        return _narrative()


class _NoneAI:
    async def narrate(self, _redacted):
        return None


class _TimeoutAI:
    async def narrate(self, _redacted):
        raise TimeoutError("simulated timeout")


class _ExceptionAI:
    async def narrate(self, _redacted):
        raise RuntimeError("Bearer placeholder-not-a-real-token would-leak-here")


# ---------------------------------------------------------------------------
# Happy path: ai_invoke + ai_narrative_attached
# ---------------------------------------------------------------------------


@pytest.mark.asyncio()
async def test_success_emits_invoke_and_attached_events() -> None:
    audit = _RecordingAudit()
    narrator = Narrator(_OkAI(), Redactor(_HMAC_KEY), audit=audit)
    f = _finding()
    result = await narrator.narrate(f)
    assert result.ai_narrative is not None
    types = [e[0] for e in audit.events]
    assert types == ["ai_invoke", "ai_narrative_attached"]
    # ai_invoke may include the Phase C `latency_ms` observability metric;
    # ai_narrative_attached stays strictly `{finding_id}`.
    allowed_invoke = {"finding_id", "latency_ms"}
    allowed_attached = {"finding_id"}
    for ev, payload in audit.events:
        if ev == "ai_invoke":
            assert set(payload.keys()) <= allowed_invoke
            assert "latency_ms" in payload  # Phase C surfaces this on success
            assert isinstance(payload["latency_ms"], int)
            assert payload["latency_ms"] >= 0
        else:
            assert set(payload.keys()) == allowed_attached
        assert payload["finding_id"] == f.finding_id


# ---------------------------------------------------------------------------
# Failure paths: each surfaces a distinct closed-set reason.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio()
async def test_timeout_emits_response_rejected_with_reason_timeout() -> None:
    audit = _RecordingAudit()
    narrator = Narrator(_TimeoutAI(), Redactor(_HMAC_KEY), audit=audit)
    result = await narrator.narrate(_finding())
    assert result.ai_narrative is None
    types = [e[0] for e in audit.events]
    assert types == ["ai_invoke", "ai_response_rejected"]
    assert audit.events[1][1]["reason"] == "timeout"


@pytest.mark.asyncio()
async def test_provider_exception_emits_provider_error_reason() -> None:
    audit = _RecordingAudit()
    narrator = Narrator(_ExceptionAI(), Redactor(_HMAC_KEY), audit=audit)
    result = await narrator.narrate(_finding())
    assert result.ai_narrative is None
    types = [e[0] for e in audit.events]
    assert types == ["ai_invoke", "ai_response_rejected"]
    assert audit.events[1][1]["reason"] == "provider_error"


@pytest.mark.asyncio()
async def test_none_narrative_emits_schema_reason() -> None:
    """A None return from the provider (validator dropped it, non-2xx,
    etc.) surfaces as a coarse `schema` rejection in the audit chain."""
    audit = _RecordingAudit()
    narrator = Narrator(_NoneAI(), Redactor(_HMAC_KEY), audit=audit)
    result = await narrator.narrate(_finding())
    assert result.ai_narrative is None
    types = [e[0] for e in audit.events]
    assert types == ["ai_invoke", "ai_response_rejected"]
    assert audit.events[1][1]["reason"] == "schema"


# ---------------------------------------------------------------------------
# Privacy: payloads contain no secrets, no raw IOC, no completion text.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio()
async def test_audit_payloads_never_contain_secrets_or_raw_ioc() -> None:
    """Sweep every Narrator path with an audit sink, then assert that no
    event payload anywhere contains a secret-looking field, the raw IOC,
    or completion content."""
    forbidden_substrings = (
        "Bearer ",
        "Authorization",
        "api_key",
        "X-API-Key",
        _RAW_IOC,
        "Defensive narrative.",  # completion body must not be audited
        "Review in SIEM",  # suggested action text must not be audited
        "placeholder-not-a-real-token",
    )

    for ai_class in (_OkAI, _NoneAI, _TimeoutAI, _ExceptionAI):
        audit = _RecordingAudit()
        narrator = Narrator(ai_class(), Redactor(_HMAC_KEY), audit=audit)
        await narrator.narrate(_finding())
        blob = json.dumps(audit.events, default=str)
        for s in forbidden_substrings:
            assert s not in blob, f"{s!r} leaked into audit for {ai_class.__name__}"


@pytest.mark.asyncio()
async def test_audit_event_types_are_from_closed_set() -> None:
    """Audit event types must come from the closed allowlist so downstream
    consumers can render localised labels safely. Phase C added
    `ai_input_truncated` to the set."""
    allowed = {
        "ai_invoke",
        "ai_response_rejected",
        "ai_narrative_attached",
        "ai_input_truncated",  # Phase C addition
    }
    for ai_class in (_OkAI, _NoneAI, _TimeoutAI, _ExceptionAI):
        audit = _RecordingAudit()
        narrator = Narrator(ai_class(), Redactor(_HMAC_KEY), audit=audit)
        await narrator.narrate(_finding())
        for ev, _ in audit.events:
            assert ev in allowed, f"unknown audit event: {ev!r}"


@pytest.mark.asyncio()
async def test_rejection_reason_is_from_closed_set() -> None:
    allowed_reasons = {
        "schema",
        "timeout",
        "non_2xx",
        "filtered",
        "invalid_json",
        "provider_error",
        "redaction_failed",
        "input_too_large",  # Phase C addition
    }
    for ai_class in (_NoneAI, _TimeoutAI, _ExceptionAI):
        audit = _RecordingAudit()
        narrator = Narrator(ai_class(), Redactor(_HMAC_KEY), audit=audit)
        await narrator.narrate(_finding())
        for ev, payload in audit.events:
            if ev == "ai_response_rejected":
                assert payload["reason"] in allowed_reasons


# ---------------------------------------------------------------------------
# Audit sink failure must not break the sweep.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio()
async def test_failing_audit_sink_does_not_break_success_path() -> None:
    narrator = Narrator(_OkAI(), Redactor(_HMAC_KEY), audit=_AlwaysFailAudit())
    result = await narrator.narrate(_finding())
    # Narrative still attaches; audit-write failure is swallowed.
    assert result.ai_narrative is not None
    assert result.ai_narrative.summary == "Defensive narrative."


@pytest.mark.asyncio()
async def test_failing_audit_sink_does_not_break_failure_path() -> None:
    narrator = Narrator(_TimeoutAI(), Redactor(_HMAC_KEY), audit=_AlwaysFailAudit())
    result = await narrator.narrate(_finding())
    # Sweep result is unchanged from the no-audit-sink case.
    assert result.ai_narrative is None
    assert result.score == _finding().score
    assert result.severity == _finding().severity


# ---------------------------------------------------------------------------
# Backward compatibility: existing Narrator callers without `audit` still work.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio()
async def test_narrator_works_without_audit_param() -> None:
    """Pre-Phase-B call sites that did not pass `audit=` must keep working."""
    narrator = Narrator(_OkAI(), Redactor(_HMAC_KEY))
    result = await narrator.narrate(_finding())
    assert result.ai_narrative is not None
