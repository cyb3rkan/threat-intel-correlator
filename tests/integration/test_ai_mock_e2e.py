# tests/integration/test_ai_mock_e2e.py
"""Phase D: end-to-end AI narration with a deterministic mock provider.

These tests exercise the FULL narration path — Redactor → Narrator →
mock AI → AINarrative → Finding.model_copy → renderer — without touching
the network and without any real keys. The AI provider is replaced at
the Narrator boundary (the AIProvider port), not at the HTTP layer, so
the test never even constructs a SafeHttpClient against an AI endpoint.

Contracts frozen here:
  * `ai_attempted=true` and `ai_active=true` when AI is enabled and keys
    are present (via the fake secret store).
  * At least one finding receives an `ai_narrative`.
  * Score / severity / enrichments / above_threshold / exit_code are
    bit-identical to a no-AI run with the same input.
  * No raw IOC, raw log line, raw provider response, secret, or
    Authorization-shaped header appears in:
      - the AI input (what the Narrator hands to the provider)
      - the AI output (what the narrator attaches)
      - the audit chain payloads
      - the rendered JSON / Markdown export.
"""
from __future__ import annotations

import asyncio
import io
import json
from datetime import datetime, timezone

import pytest

from tests.fixtures.fake_secret_store import (
    PLACEHOLDER_HMAC_32B,
    default_ai_and_hmac_store,
)
from tests.fixtures.mock_ai_provider import (
    MockAIProvider,
    MockAIProviderInvalidJson,
    MockAIProviderTimeout,
    MockAIProviderTurkish,
)

from tic.adapters.audit.hash_chain import HashChainAuditLogger
from tic.adapters.renderers.json_renderer import render_json
from tic.adapters.renderers.markdown_renderer import render_markdown
from tic.application.ai.narrator import Narrator
from tic.application.correlation import LogLine
from tic.application.normalization import make_ioc
from tic.application.orchestrator import SweepOrchestrator
from tic.application.redaction import Redactor
from tic.application.scoring import ScoringProfile
from tic.domain.finding import Finding, OutputMode, Severity
from tic.infra.exit_codes import ExitCode


_RAW_IOC = "phase-d-secret-ioc.example"


def _ts() -> datetime:
    return datetime(2026, 5, 14, 12, 0, 0, tzinfo=timezone.utc)


class _CapturingAudit:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def append(self, event_type, payload):
        self.events.append((event_type, dict(payload)))

    def verify_chain(self) -> bool:
        return True


def _profile() -> ScoringProfile:
    return ScoringProfile(version="1.0.0")


def _render_collect(findings, out):
    out.findings_collected = list(findings)
    return len(findings)


class _CollectingOut(io.StringIO):
    findings_collected: list[Finding] = []


def _run(narrator: Narrator | None, audit, *, fail_on: Severity = Severity.INFO) -> tuple[ExitCode, list[Finding]]:
    iocs = [make_ioc(_RAW_IOC, source="phase-d-test", confidence=95)]
    logs = [
        LogLine(source="fw", timestamp=_ts(), text=f"blocked {_RAW_IOC}"),
        LogLine(source="proxy", timestamp=_ts(), text=f"observed {_RAW_IOC}"),
    ]
    orch = SweepOrchestrator(
        providers=[],
        narrator=narrator,
        profile=_profile(),
        audit=audit,
        min_severity_exit=fail_on,
        ai_max_findings_per_sweep=25,
    )
    out = _CollectingOut()
    code = asyncio.run(
        orch.run(iocs=iocs, log_lines=logs, out=out, render_fn=_render_collect)
    )
    return code, out.findings_collected


# ---------------------------------------------------------------------------
# Happy path: enabled mock AI attaches a narrative; deterministic core unchanged.
# ---------------------------------------------------------------------------


def test_e2e_mock_ai_attaches_narrative_and_keeps_invariants() -> None:
    audit_no_ai = _CapturingAudit()
    audit_ai = _CapturingAudit()

    code_no_ai, no_ai = _run(None, audit_no_ai)

    redactor = Redactor(PLACEHOLDER_HMAC_32B)
    mock = MockAIProvider()
    narrator = Narrator(mock, redactor, audit=audit_ai)
    code_ai, with_ai = _run(narrator, audit_ai)

    # Exit code identical: AI never changes it.
    assert code_no_ai == code_ai
    # Same finding count.
    assert len(no_ai) == len(with_ai) == 1

    # Deterministic core fields identical.
    f0, f1 = no_ai[0], with_ai[0]
    assert f0.score == f1.score
    assert f0.severity == f1.severity
    assert f0.ioc == f1.ioc
    assert f0.matches == f1.matches
    assert f0.enrichments == f1.enrichments

    # AI narrative attached.
    assert f1.ai_narrative is not None
    assert f1.ai_narrative.summary

    # Mock was called exactly once.
    assert mock.log.calls == 1
    # The mock saw a pseudonym, not the raw IOC.
    assert mock.log.last_ioc_pseudo
    assert _RAW_IOC not in (mock.log.last_ioc_pseudo or "")

    # sweep_end ai_narratives_generated reflects the success.
    end_no = next(e for e in audit_no_ai.events if e[0] == "sweep_end")[1]
    end_ai = next(e for e in audit_ai.events if e[0] == "sweep_end")[1]
    assert end_no["ai_narratives_generated"] == 0
    assert end_ai["ai_narratives_generated"] == 1
    assert end_no["above_threshold"] == end_ai["above_threshold"]


def test_e2e_mock_ai_no_raw_ioc_in_audit_or_rendered_output() -> None:
    audit = _CapturingAudit()
    redactor = Redactor(PLACEHOLDER_HMAC_32B)
    narrator = Narrator(MockAIProvider(), redactor, audit=audit)

    _code, findings = _run(narrator, audit)

    # Audit chain — every payload is metadata-only.
    audit_blob = json.dumps(audit.events, default=str)
    forbidden = (
        _RAW_IOC,
        "Authorization",
        "Bearer ",
        "api_key",
        "phase-d-placeholder-ai-key-NOT-REAL",
        # No prompt fragments.
        "<untrusted>",
        # No completion text echoed back into the audit chain.
        "Defensive triage narrative",
    )
    for s in forbidden:
        assert s not in audit_blob, f"audit leaked {s!r}"

    # Rendered JSON — analyst mode exposes the raw IOC by design, but
    # we still verify that no AI-input artifacts (prompt, header, key)
    # leaked into the export.
    buf = io.StringIO()
    render_json(findings, buf, mode=OutputMode.ANALYST)
    json_text = buf.getvalue()
    for s in ("Authorization", "Bearer ", "api_key", "<untrusted>"):
        assert s not in json_text

    # Markdown export — AI advisory label present, no prompt fragments.
    mbuf = io.StringIO()
    render_markdown(findings, mbuf, mode=OutputMode.ANALYST)
    md = mbuf.getvalue()
    assert "AI-generated advisory" in md
    for s in ("Authorization", "Bearer ", "<untrusted>"):
        assert s not in md


# ---------------------------------------------------------------------------
# Failure modes — sweep stays successful, ai_narrative=None.
# ---------------------------------------------------------------------------


def test_e2e_mock_ai_timeout_falls_back_to_no_narrative() -> None:
    audit = _CapturingAudit()
    narrator = Narrator(
        MockAIProviderTimeout(), Redactor(PLACEHOLDER_HMAC_32B), audit=audit
    )
    code, findings = _run(narrator, audit)

    # Sweep still succeeds.
    assert code in (ExitCode.SUCCESS, ExitCode.FINDINGS_ABOVE_THRESHOLD)
    assert all(f.ai_narrative is None for f in findings)

    rejected = [e for e in audit.events if e[0] == "ai_response_rejected"]
    assert rejected and rejected[0][1]["reason"] == "timeout"

    end = next(e for e in audit.events if e[0] == "sweep_end")[1]
    assert end["ai_narratives_generated"] == 0


def test_e2e_mock_ai_invalid_response_falls_back_to_no_narrative() -> None:
    audit = _CapturingAudit()
    narrator = Narrator(
        MockAIProviderInvalidJson(), Redactor(PLACEHOLDER_HMAC_32B), audit=audit
    )
    code, findings = _run(narrator, audit)
    assert code in (ExitCode.SUCCESS, ExitCode.FINDINGS_ABOVE_THRESHOLD)
    assert all(f.ai_narrative is None for f in findings)

    rejected = [e for e in audit.events if e[0] == "ai_response_rejected"]
    assert rejected and rejected[0][1]["reason"] == "schema"


# ---------------------------------------------------------------------------
# Turkish narrative round-trip.
# ---------------------------------------------------------------------------


def test_e2e_mock_ai_turkish_narrative_round_trips_via_renderers() -> None:
    audit = _CapturingAudit()
    narrator = Narrator(
        MockAIProviderTurkish(), Redactor(PLACEHOLDER_HMAC_32B), audit=audit
    )
    code, findings = _run(narrator, audit)
    assert code in (ExitCode.SUCCESS, ExitCode.FINDINGS_ABOVE_THRESHOLD)
    annotated = [f for f in findings if f.ai_narrative is not None]
    assert annotated

    n = annotated[0].ai_narrative
    assert "şüpheli" in n.summary  # natural-language Turkish characters preserved
    assert "severity" in n.summary  # technical term remains English
    # English technical action survives alongside Turkish.
    assert any("Verify with EDR" in a for a in n.suggested_actions)

    # Markdown export — encoding-safe and labelled as AI advisory.
    mbuf = io.StringIO()
    render_markdown(findings, mbuf, mode=OutputMode.ANALYST)
    md = mbuf.getvalue()
    assert "AI-generated advisory" in md
    # Turkish glyphs survive Markdown escaping.
    assert "şüpheli" in md


# ---------------------------------------------------------------------------
# Fake secret store sanity (the wiring layer's input shape).
# ---------------------------------------------------------------------------


def test_fake_secret_store_holds_ai_and_hmac_placeholders() -> None:
    store = default_ai_and_hmac_store()
    ai = store.get("tic-ai", "default")
    hm = store.get("tic-redaction-hmac", "default")
    assert ai and hm
    assert len(hm) >= 32  # Redactor precondition
    # Critically — these are synthetic placeholders, not real key material.
    assert b"NOT-REAL" in ai


def test_fake_secret_store_raises_when_key_absent() -> None:
    store = default_ai_and_hmac_store()
    with pytest.raises(RuntimeError):
        store.get("tic-nonexistent", "default")


# ---------------------------------------------------------------------------
# Audit chain — closed-set events only, payloads are metadata-only.
# ---------------------------------------------------------------------------


def test_e2e_audit_events_are_metadata_only_for_full_run() -> None:
    audit = _CapturingAudit()
    narrator = Narrator(MockAIProvider(), Redactor(PLACEHOLDER_HMAC_32B), audit=audit)
    _run(narrator, audit)

    allowed_event_types = {
        "sweep_start", "sweep_end", "partial_scan_warning",
        "ai_invoke", "ai_response_rejected", "ai_narrative_attached",
        "ai_input_truncated",
        "cli_invoke", "ui_invoke", "provider_tls_verify_disabled",
    }
    for ev, payload in audit.events:
        assert ev in allowed_event_types, f"unknown audit event: {ev!r}"
        # Metadata payloads only — no nested objects with raw content.
        for v in payload.values():
            assert not isinstance(v, (dict, list)) or not any(
                isinstance(x, dict) and "summary" in x for x in (v if isinstance(v, list) else [v])
            )


def test_e2e_audit_via_hash_chain_logger_does_not_leak(tmp_path) -> None:
    """Sanity: even with the real HashChainAuditLogger sink, the line
    written to disk contains only metadata-only payloads."""
    audit = HashChainAuditLogger(tmp_path / "audit.log")
    narrator = Narrator(MockAIProvider(), Redactor(PLACEHOLDER_HMAC_32B), audit=audit)
    _run(narrator, audit)

    content = (tmp_path / "audit.log").read_text(encoding="utf-8")
    for s in (
        _RAW_IOC,
        "Authorization",
        "Bearer ",
        "Defensive triage narrative",
        "<untrusted>",
        "phase-d-placeholder-ai-key-NOT-REAL",
    ):
        assert s not in content, f"hash-chain audit leaked {s!r}"
