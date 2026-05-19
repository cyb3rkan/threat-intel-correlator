# tests/fixtures/mock_ai_provider.py
"""Phase D: deterministic, network-free AI provider mocks.

The Narrator port (`tic.ports.ai_provider.AIProvider`) only requires an
async `narrate(redacted) -> AINarrative | None` method. These mocks
implement that contract without touching the network, without any
keys, and without leaking content from the RedactedFinding.

Available mocks:
  - `MockAIProvider`             — always returns a fixed safe narrative.
  - `MockAIProviderTimeout`      — always raises `TimeoutError`.
  - `MockAIProviderInvalidJson`  — returns None to mimic `parse_and_validate`
                                   rejecting non-JSON / schema-violating
                                   responses.
  - `MockAIProviderUnsafeAction` — returns a narrative with one unsafe and
                                   one safe `suggested_action`. The validator
                                   in the real adapter would drop the unsafe
                                   entry; here we attach the post-filter
                                   shape directly so the e2e path is
                                   exercised end-to-end.

These mocks are deliberately confined to the test tree and are NEVER
imported by production code paths.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from tic.application.redaction import RedactedFinding
from tic.domain.finding import AINarrative


def _canned_narrative(
    *,
    summary: str = "Defensive triage narrative for the redacted finding.",
    fpl: str = "low",
    actions: list[str] | None = None,
    confidence: str = "medium",
    model: str = "mock-ai-test",
) -> AINarrative:
    return AINarrative(
        summary=summary,
        false_positive_likelihood=fpl,  # type: ignore[arg-type]
        suggested_actions=actions if actions is not None else ["Review in SIEM"],
        confidence=confidence,  # type: ignore[arg-type]
        model=model,
        generated_at=datetime(2026, 5, 14, tzinfo=timezone.utc),
    )


@dataclass
class _CallLog:
    """Records each narrate() invocation's input shape — counts only."""

    calls: int = 0
    last_finding_id: str | None = None
    last_ioc_pseudo: str | None = None
    last_match_count: int = 0
    last_severity: str | None = None


@dataclass
class MockAIProvider:
    """Always returns the canned narrative. Records call metadata."""

    narrative: AINarrative = field(default_factory=_canned_narrative)
    log: _CallLog = field(default_factory=_CallLog)

    async def narrate(self, redacted: RedactedFinding) -> AINarrative | None:
        self.log.calls += 1
        self.log.last_finding_id = redacted.finding_id
        self.log.last_ioc_pseudo = redacted.ioc_pseudo
        self.log.last_match_count = redacted.match_count
        self.log.last_severity = redacted.severity
        return self.narrative


@dataclass
class MockAIProviderTimeout:
    """Always raises TimeoutError — exercises the Narrator timeout path."""

    log: _CallLog = field(default_factory=_CallLog)

    async def narrate(self, redacted: RedactedFinding) -> AINarrative | None:
        self.log.calls += 1
        raise TimeoutError("mock AI timeout")


@dataclass
class MockAIProviderInvalidJson:
    """Returns None — what the real adapter does after the response
    validator rejects invalid JSON / schema-violating output. Tests the
    `reason: schema` audit path."""

    log: _CallLog = field(default_factory=_CallLog)

    async def narrate(self, redacted: RedactedFinding) -> AINarrative | None:
        self.log.calls += 1
        return None


@dataclass
class MockAIProviderTurkish:
    """Returns a Turkish-language narrative with English technical terms.
    Used to verify the language hint contract end-to-end."""

    log: _CallLog = field(default_factory=_CallLog)

    async def narrate(self, redacted: RedactedFinding) -> AINarrative | None:
        self.log.calls += 1
        return _canned_narrative(
            summary=(
                "Bu IOC; SIEM kayıtlarında eşleşen şüpheli bir göstergeyi "
                "ifade etmektedir. severity ve score deterministik olarak "
                "korelatör tarafından üretilmiştir."
            ),
            actions=[
                "SIEM dashboard üzerinde olayı gözden geçir",
                "Verify with EDR telemetry",
            ],
        )
