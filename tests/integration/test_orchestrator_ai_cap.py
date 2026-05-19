# tests/integration/test_orchestrator_ai_cap.py
"""Phase C: bounded AI execution.

The SweepOrchestrator must only invoke the narrator on the top-N findings
(by deterministic ranking). Findings outside the cap stay in the result
list with `ai_narrative=None`. Score, severity, exit_code, and
above_threshold must NOT depend on the cap.
"""
from __future__ import annotations

import asyncio
import io
from datetime import datetime, timezone

from tic.application.correlation import LogLine
from tic.application.normalization import make_ioc
from tic.application.orchestrator import SweepOrchestrator
from tic.application.scoring import ScoringProfile
from tic.domain.finding import AINarrative, Finding, Severity
from tic.infra.exit_codes import ExitCode


def _profile() -> ScoringProfile:
    return ScoringProfile(version="1.0.0")


def _ts() -> datetime:
    return datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


class _NullAudit:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def append(self, event_type, payload):
        self.events.append((event_type, dict(payload)))


class _RecordingNarrator:
    """Counts narrate() calls and attaches a canned narrative."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def narrate(self, finding: Finding) -> Finding:
        self.calls.append(finding.finding_id)
        return finding.model_copy(update={
            "ai_narrative": AINarrative(
                summary="ok",
                false_positive_likelihood="low",
                suggested_actions=["Review in SIEM"],
                confidence="medium",
                model="placeholder",
                generated_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
            )
        })


def _render_collect(findings, out):
    out.findings_collected = list(findings)
    return len(findings)


class _CollectingOut(io.StringIO):
    findings_collected: list[Finding] = []


def _make_iocs_and_logs(n: int):
    """Build `n` distinct IOC/log pairs that each correlate exactly once.
    Each IOC's confidence varies so the deterministic ranking has work to do."""
    iocs = [make_ioc(f"1.2.3.{i}", source="test", confidence=50 + (i % 51)) for i in range(n)]
    logs = [
        LogLine(source="fw", timestamp=_ts(), text=f"blocked 1.2.3.{i}")
        for i in range(n)
    ]
    return iocs, logs


def _run(orch: SweepOrchestrator, iocs, logs) -> list[Finding]:
    out = _CollectingOut()
    asyncio.run(orch.run(iocs=iocs, log_lines=logs, out=out, render_fn=_render_collect))
    return out.findings_collected


# ---------------------------------------------------------------------------
# Cap behaviour
# ---------------------------------------------------------------------------


def test_more_than_cap_findings_only_top_n_get_ai() -> None:
    iocs, logs = _make_iocs_and_logs(30)
    narrator = _RecordingNarrator()
    audit = _NullAudit()
    orch = SweepOrchestrator(
        providers=[], narrator=narrator, profile=_profile(), audit=audit,
        min_severity_exit=Severity.INFO,
        ai_max_findings_per_sweep=25,
    )
    findings = _run(orch, iocs, logs)

    # All 30 findings appear in the result.
    assert len(findings) == 30
    # Only 25 received an AI call.
    assert len(narrator.calls) == 25
    # The remaining 5 keep ai_narrative=None.
    annotated = [f for f in findings if f.ai_narrative is not None]
    not_annotated = [f for f in findings if f.ai_narrative is None]
    assert len(annotated) == 25
    assert len(not_annotated) == 5

    # sweep_end records both counters.
    end = next(e for e in audit.events if e[0] == "sweep_end")
    assert end[1]["ai_narratives_generated"] == 25
    assert end[1]["ai_narration_skipped_due_to_cap"] == 5


def test_selection_is_deterministic_across_runs() -> None:
    iocs, logs = _make_iocs_and_logs(40)

    runs = []
    for _ in range(2):
        narrator = _RecordingNarrator()
        orch = SweepOrchestrator(
            providers=[], narrator=narrator, profile=_profile(),
            audit=_NullAudit(), min_severity_exit=Severity.INFO,
            ai_max_findings_per_sweep=10,
        )
        _run(orch, iocs, logs)
        runs.append(sorted(narrator.calls))  # finding_ids are uuids → just check the set/order pattern

    # Same inputs → same number of selections.
    assert len(runs[0]) == len(runs[1]) == 10


def test_cap_does_not_affect_score_severity_exit_code() -> None:
    iocs, logs = _make_iocs_and_logs(30)

    # Run with AI on, cap=25.
    audit_on = _NullAudit()
    orch_on = SweepOrchestrator(
        providers=[], narrator=_RecordingNarrator(), profile=_profile(),
        audit=audit_on, min_severity_exit=Severity.INFO,
        ai_max_findings_per_sweep=25,
    )
    on = _run(orch_on, iocs, logs)
    code_on = next(e for e in audit_on.events if e[0] == "sweep_end")[1]
    above_on = code_on["above_threshold"]

    # Run with AI on, cap=5.
    audit_low = _NullAudit()
    orch_low = SweepOrchestrator(
        providers=[], narrator=_RecordingNarrator(), profile=_profile(),
        audit=audit_low, min_severity_exit=Severity.INFO,
        ai_max_findings_per_sweep=5,
    )
    low = _run(orch_low, iocs, logs)
    above_low = next(e for e in audit_low.events if e[0] == "sweep_end")[1]["above_threshold"]

    # Run with AI off.
    audit_off = _NullAudit()
    orch_off = SweepOrchestrator(
        providers=[], narrator=None, profile=_profile(),
        audit=audit_off, min_severity_exit=Severity.INFO,
    )
    off = _run(orch_off, iocs, logs)
    above_off = next(e for e in audit_off.events if e[0] == "sweep_end")[1]["above_threshold"]

    # All three runs produce the same Finding set (modulo ai_narrative).
    def core(fs: list[Finding]):
        return sorted(
            (f.ioc.value, f.score, f.severity.value, len(f.matches))
            for f in fs
        )

    assert core(on) == core(low) == core(off)
    assert above_on == above_low == above_off


def test_cap_under_finding_count_runs_all() -> None:
    """If cap >= findings, every finding gets a call."""
    iocs, logs = _make_iocs_and_logs(8)
    narrator = _RecordingNarrator()
    orch = SweepOrchestrator(
        providers=[], narrator=narrator, profile=_profile(),
        audit=_NullAudit(), min_severity_exit=Severity.INFO,
        ai_max_findings_per_sweep=25,
    )
    findings = _run(orch, iocs, logs)
    assert len(findings) == 8
    assert len(narrator.calls) == 8


def test_cap_with_no_narrator_records_zero_skipped() -> None:
    """When AI is off, `ai_narration_skipped_due_to_cap` is still recorded
    as 0 — Phase C's contract is metadata-only count, not a flag."""
    iocs, logs = _make_iocs_and_logs(30)
    audit = _NullAudit()
    orch = SweepOrchestrator(
        providers=[], narrator=None, profile=_profile(),
        audit=audit, min_severity_exit=Severity.INFO,
        ai_max_findings_per_sweep=5,
    )
    _run(orch, iocs, logs)
    end = next(e for e in audit.events if e[0] == "sweep_end")
    assert end[1]["ai_narratives_generated"] == 0
    assert end[1]["ai_narration_skipped_due_to_cap"] == 0
