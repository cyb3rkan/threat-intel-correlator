# tests/integration/test_orchestrator.py
from __future__ import annotations

import asyncio
import io
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

from tic.application.correlation import LogLine
from tic.application.normalization import make_ioc
from tic.application.orchestrator import SweepOrchestrator
from tic.application.scoring import ScoringProfile
from tic.domain.finding import Severity
from tic.infra.exit_codes import ExitCode


def _ts() -> datetime:
    return datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)


def _profile() -> ScoringProfile:
    return ScoringProfile(version="1.0.0")


def _audit():
    m = MagicMock()
    m.append = MagicMock()
    return m


def _render_fn(findings, out):
    out.write(f"{len(findings)} findings\n")
    return len(findings)


def test_no_matches_returns_success():
    iocs = [make_ioc("1.2.3.4", source="test")]
    log_lines = [LogLine(source="fw", timestamp=_ts(), text="nothing here")]
    orch = SweepOrchestrator(providers=[], narrator=None, profile=_profile(), audit=_audit())
    out = io.StringIO()
    code = asyncio.run(orch.run(iocs=iocs, log_lines=log_lines, out=out, render_fn=_render_fn))
    assert code == ExitCode.SUCCESS


def test_match_above_threshold_returns_findings_code():
    iocs = [make_ioc("1.2.3.4", source="test", confidence=100)]
    log_lines = [LogLine(source="fw", timestamp=_ts(), text="blocked 1.2.3.4")]
    orch = SweepOrchestrator(
        providers=[],
        narrator=None,
        profile=_profile(),
        audit=_audit(),
        min_severity_exit=Severity.INFO,
    )
    out = io.StringIO()
    code = asyncio.run(orch.run(iocs=iocs, log_lines=log_lines, out=out, render_fn=_render_fn))
    assert code == ExitCode.FINDINGS_ABOVE_THRESHOLD


def test_provider_exception_does_not_crash():
    provider = MagicMock()
    provider.name = "bad_provider"
    provider.enrich = AsyncMock(side_effect=RuntimeError("boom"))
    iocs = [make_ioc("1.2.3.4", source="test")]
    log_lines = [LogLine(source="fw", timestamp=_ts(), text="blocked 1.2.3.4")]
    orch = SweepOrchestrator(
        providers=[provider], narrator=None, profile=_profile(), audit=_audit()
    )
    out = io.StringIO()
    code = asyncio.run(orch.run(iocs=iocs, log_lines=log_lines, out=out, render_fn=_render_fn))
    assert code in (ExitCode.SUCCESS, ExitCode.FINDINGS_ABOVE_THRESHOLD)


def test_empty_iocs_returns_success():
    orch = SweepOrchestrator(providers=[], narrator=None, profile=_profile(), audit=_audit())
    out = io.StringIO()
    code = asyncio.run(orch.run(iocs=[], log_lines=[], out=out, render_fn=_render_fn))
    assert code == ExitCode.SUCCESS


def test_audit_called_on_start_and_end():
    audit = _audit()
    orch = SweepOrchestrator(providers=[], narrator=None, profile=_profile(), audit=audit)
    out = io.StringIO()
    asyncio.run(orch.run(iocs=[], log_lines=[], out=out, render_fn=_render_fn))
    calls = [call.args[0] for call in audit.append.call_args_list]
    assert "sweep_start" in calls
    assert "sweep_end" in calls
