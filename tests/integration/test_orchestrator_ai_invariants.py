# tests/integration/test_orchestrator_ai_invariants.py
"""Phase A: integration-level proof that the SweepOrchestrator's
deterministic outputs (score, severity, exit_code, above_threshold) are
identical whether or not AI narration is wired in.

We use fake narrators that never touch the network. The contract under
test is in `tic.application.orchestrator.SweepOrchestrator`: AI runs after
scoring and only attaches `ai_narrative` via `model_copy`. Nothing else is
mutated.
"""

from __future__ import annotations

import asyncio
import io
from datetime import UTC, datetime

from tic.application.correlation import LogLine
from tic.application.normalization import make_ioc
from tic.application.orchestrator import SweepOrchestrator
from tic.application.scoring import ScoringProfile
from tic.domain.finding import AINarrative, Finding, Severity
from tic.infra.exit_codes import ExitCode


def _ts() -> datetime:
    return datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)


def _profile() -> ScoringProfile:
    return ScoringProfile(version="1.0.0")


class _NullAudit:
    """Minimum AuditLogger surface — the orchestrator only calls .append()."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def append(self, event_type: str, payload: dict) -> None:
        self.events.append((event_type, dict(payload)))


def _render_collect(findings: list[Finding], out) -> int:
    """Render that captures findings into a list closure so the test can
    inspect post-orchestrator state without parsing rendered text."""
    out.findings_collected = list(findings)
    return len(findings)


class _CollectingOut(io.StringIO):
    findings_collected: list[Finding] = []


class _FakeNarrator:
    """Always attaches the same canned narrative. No network, no keys."""

    def __init__(self) -> None:
        self._narrative = AINarrative(
            summary="Fake narrative for invariant test.",
            false_positive_likelihood="low",
            suggested_actions=["Investigate"],
            confidence="medium",
            model="placeholder-model",
            generated_at=datetime(2025, 1, 1, tzinfo=UTC),
        )

    async def narrate(self, finding: Finding) -> Finding:
        return finding.model_copy(update={"ai_narrative": self._narrative})


class _FailingNarrator:
    """Simulates a narrator that raises mid-call. The orchestrator's
    `try/except` must isolate this and preserve the original Finding."""

    async def narrate(self, finding: Finding) -> Finding:
        raise TimeoutError("simulated AI timeout")


def _run_with_narrator(narrator) -> tuple[ExitCode, list[Finding]]:
    iocs = [make_ioc("1.2.3.4", source="test", confidence=100)]
    log_lines = [LogLine(source="fw", timestamp=_ts(), text="blocked 1.2.3.4")]
    orch = SweepOrchestrator(
        providers=[],
        narrator=narrator,
        profile=_profile(),
        audit=_NullAudit(),
        min_severity_exit=Severity.INFO,
    )
    out = _CollectingOut()
    code = asyncio.run(orch.run(iocs=iocs, log_lines=log_lines, out=out, render_fn=_render_collect))
    return code, out.findings_collected


def test_ai_on_and_ai_off_produce_identical_score_and_severity() -> None:
    """The Finding's deterministic core fields must match exactly whether
    the orchestrator runs with or without an AI narrator."""
    code_off, findings_off = _run_with_narrator(None)
    code_on, findings_on = _run_with_narrator(_FakeNarrator())

    assert code_off == code_on
    assert len(findings_off) == len(findings_on)

    for f_off, f_on in zip(findings_off, findings_on, strict=True):
        assert f_off.score == f_on.score
        assert f_off.severity == f_on.severity
        assert f_off.ioc == f_on.ioc
        assert f_off.matches == f_on.matches
        assert f_off.enrichments == f_on.enrichments
        # finding_id and correlation_id are generated per-run; we don't
        # compare those.


def test_ai_timeout_preserves_exit_code_and_score() -> None:
    """A narrator that raises must not change exit_code or any Finding
    field. The orchestrator's `try/except` keeps the sweep deterministic."""
    code_off, findings_off = _run_with_narrator(None)
    code_timeout, findings_timeout = _run_with_narrator(_FailingNarrator())

    assert code_off == code_timeout
    for f_off, f_to in zip(findings_off, findings_timeout, strict=True):
        assert f_off.score == f_to.score
        assert f_off.severity == f_to.severity
        # No narrative was attached.
        assert f_to.ai_narrative is None


def test_ai_narrative_attached_only_when_narrator_succeeds() -> None:
    """When the narrator succeeds, every Finding gets `ai_narrative`
    populated. When it fails, none do."""
    _, findings_on = _run_with_narrator(_FakeNarrator())
    _, findings_to = _run_with_narrator(_FailingNarrator())

    assert all(f.ai_narrative is not None for f in findings_on)
    assert all(f.ai_narrative is None for f in findings_to)


def test_ai_does_not_mutate_above_threshold_flag_via_audit() -> None:
    """The audit log's sweep_end event records `above_threshold`. AI on/off
    must produce the same value for this flag."""
    audit_off = _NullAudit()
    audit_on = _NullAudit()

    iocs = [make_ioc("1.2.3.4", source="test", confidence=100)]
    log_lines = [LogLine(source="fw", timestamp=_ts(), text="blocked 1.2.3.4")]

    for narrator, audit in ((None, audit_off), (_FakeNarrator(), audit_on)):
        orch = SweepOrchestrator(
            providers=[],
            narrator=narrator,
            profile=_profile(),
            audit=audit,
            min_severity_exit=Severity.INFO,
        )
        out = _CollectingOut()
        asyncio.run(orch.run(iocs=iocs, log_lines=log_lines, out=out, render_fn=_render_collect))

    end_off = next(e for e in audit_off.events if e[0] == "sweep_end")
    end_on = next(e for e in audit_on.events if e[0] == "sweep_end")
    assert end_off[1]["above_threshold"] == end_on[1]["above_threshold"]
    assert end_off[1]["findings"] == end_on[1]["findings"]


def test_sweep_end_records_ai_narratives_generated_count() -> None:
    """Phase B: the sweep_end audit event carries a metadata-only count of
    findings that received an AI narrative. AI off → 0; AI on (success
    path) → equal to the number of findings produced."""
    iocs = [make_ioc("1.2.3.4", source="test", confidence=100)]
    log_lines = [LogLine(source="fw", timestamp=_ts(), text="blocked 1.2.3.4")]

    audit_off = _NullAudit()
    audit_on = _NullAudit()

    for narrator, audit in ((None, audit_off), (_FakeNarrator(), audit_on)):
        orch = SweepOrchestrator(
            providers=[],
            narrator=narrator,
            profile=_profile(),
            audit=audit,
            min_severity_exit=Severity.INFO,
        )
        out = _CollectingOut()
        asyncio.run(orch.run(iocs=iocs, log_lines=log_lines, out=out, render_fn=_render_collect))

    end_off = next(e for e in audit_off.events if e[0] == "sweep_end")
    end_on = next(e for e in audit_on.events if e[0] == "sweep_end")
    assert end_off[1]["ai_narratives_generated"] == 0
    assert end_on[1]["ai_narratives_generated"] == end_on[1]["findings"]
    assert end_on[1]["ai_narratives_generated"] >= 1
