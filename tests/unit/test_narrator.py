# tests/unit/test_narrator.py
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tic.application.ai.narrator import Narrator
from tic.application.redaction import Redactor
from tic.domain.finding import AINarrative, Finding, Severity
from tic.domain.ioc import IOC, IOCType

_HMAC_KEY = b"0" * 32


def _make_finding() -> Finding:
    return Finding(
        finding_id="00000000-0000-4000-8000-000000000000",
        ioc=IOC(value="evil.example.com", ioc_type=IOCType.DOMAIN, source="feed"),
        matches=[],
        enrichments=[],
        score=60,
        severity=Severity.MEDIUM,
        profile_hash="a" * 64,
        correlation_id="cid",
        created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )


class _FakeAI:
    def __init__(self, narrative: AINarrative | None, raise_exc: Exception | None = None) -> None:
        self._narrative = narrative
        self._raise = raise_exc

    async def narrate(self, redacted):
        if self._raise is not None:
            raise self._raise
        return self._narrative


def _narrative() -> AINarrative:
    return AINarrative(
        summary="Test narrative.",
        false_positive_likelihood="low",
        suggested_actions=["Investigate"],
        confidence="medium",
        model="fake-model",
        generated_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )


@pytest.mark.asyncio
async def test_narrator_attaches_narrative_on_success() -> None:
    narrator = Narrator(_FakeAI(_narrative()), Redactor(_HMAC_KEY))
    result = await narrator.narrate(_make_finding())
    assert result.ai_narrative is not None
    assert result.ai_narrative.summary == "Test narrative."


@pytest.mark.asyncio
async def test_narrator_preserves_score_and_severity() -> None:
    narrator = Narrator(_FakeAI(_narrative()), Redactor(_HMAC_KEY))
    original = _make_finding()
    result = await narrator.narrate(original)
    assert result.score == original.score
    assert result.severity == original.severity


@pytest.mark.asyncio
async def test_narrator_returns_original_when_ai_returns_none() -> None:
    narrator = Narrator(_FakeAI(None), Redactor(_HMAC_KEY))
    result = await narrator.narrate(_make_finding())
    assert result.ai_narrative is None


@pytest.mark.asyncio
async def test_narrator_swallows_ai_exceptions() -> None:
    narrator = Narrator(_FakeAI(None, raise_exc=RuntimeError("boom")), Redactor(_HMAC_KEY))
    original = _make_finding()
    result = await narrator.narrate(original)
    assert result.ai_narrative is None
    assert result.finding_id == original.finding_id


# ---------------------------------------------------------------------------
# Phase A additions: freeze the fail-safe contract around the Narrator.
# These tests must keep passing as AI integration evolves.
# ---------------------------------------------------------------------------


class _TimeoutAI:
    """Mimics a request that hangs past its deadline by raising the same
    exception class our SafeHttpClient surfaces (NetworkError ultimately,
    but we use TimeoutError here so we don't depend on TIC internals)."""

    async def narrate(self, redacted):
        raise TimeoutError("simulated AI request timeout")


@pytest.mark.asyncio
async def test_narrator_timeout_returns_original_finding_without_narrative() -> None:
    """A timeout from the AI provider must surface as `ai_narrative is None`
    on the original Finding. Score, severity, IOC, matches, and enrichments
    must remain bit-identical to the input."""
    narrator = Narrator(_TimeoutAI(), Redactor(_HMAC_KEY))
    original = _make_finding()
    result = await narrator.narrate(original)
    assert result.ai_narrative is None
    assert result.score == original.score
    assert result.severity == original.severity
    assert result.ioc == original.ioc
    assert result.matches == original.matches
    assert result.enrichments == original.enrichments
    assert result.finding_id == original.finding_id


class _ScoreTamperingAI:
    """Simulates a hallucinated provider that returns a different shape.
    The narrator must never let the AI flip score/severity even if the
    provider tried to. The provider port returns AINarrative or None, so
    we test the closest realistic threat: a narrative whose `suggested_actions`
    look like score directives."""

    def __init__(self, narrative):
        self._n = narrative

    async def narrate(self, redacted):
        return self._n


@pytest.mark.asyncio
async def test_narrator_cannot_change_score_or_severity() -> None:
    """Even with a successful narrative attached, the Finding's score,
    severity, IOC, matches, and enrichments are unchanged. Only the
    `ai_narrative` field is populated."""
    from datetime import datetime, timezone

    narrative = AINarrative(
        summary="A summary.",
        false_positive_likelihood="high",  # adversarial — claims FP
        suggested_actions=["lower severity", "set score=0"],
        confidence="high",
        model="m",
        generated_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )
    narrator = Narrator(_ScoreTamperingAI(narrative), Redactor(_HMAC_KEY))
    original = _make_finding()
    result = await narrator.narrate(original)
    assert result.score == original.score
    assert result.severity == original.severity
    assert result.ioc == original.ioc
    assert result.matches == original.matches
    assert result.enrichments == original.enrichments
    assert result.ai_narrative is not None
    # The advisory text is preserved verbatim — sanitisation happens at
    # render time, not here. We just confirm no fields besides ai_narrative
    # were mutated.


class _RecordingAI:
    """Captures the redacted payload passed to the provider, so we can
    assert no raw IOC value reached the AI input layer."""

    def __init__(self) -> None:
        self.last_redacted = None

    async def narrate(self, redacted):
        self.last_redacted = redacted
        return None


@pytest.mark.asyncio
async def test_narrator_sends_only_pseudonymized_ioc_value() -> None:
    """The Finding contains the raw IOC value, but the AI must only ever see
    the HMAC pseudonym (`ioc_pseudo`). This is the core privacy invariant."""
    ai = _RecordingAI()
    narrator = Narrator(ai, Redactor(_HMAC_KEY))
    await narrator.narrate(_make_finding())
    assert ai.last_redacted is not None
    payload_json = ai.last_redacted.model_dump_json()
    assert "evil.example.com" not in payload_json
    assert ai.last_redacted.ioc_pseudo  # non-empty pseudo