# tests/unit/test_renderers.py
from __future__ import annotations

import io
import json
from datetime import datetime, timezone

from tic.adapters.renderers.json_renderer import render_json
from tic.adapters.renderers.terminal_renderer import render_terminal
from tic.domain.finding import AINarrative, Finding, Severity
from tic.domain.ioc import IOC, IOCType


def _finding(
    value: str = "1.2.3.4",
    ioc_type: IOCType = IOCType.IP,
    score: int = 60,
    severity: Severity = Severity.MEDIUM,
    ai_narrative: AINarrative | None = None,
) -> Finding:
    return Finding(
        finding_id="00000000-0000-4000-8000-000000000001",
        ioc=IOC(value=value, ioc_type=ioc_type, source="test"),
        matches=[],
        enrichments=[],
        score=score,
        severity=severity,
        profile_hash="a" * 64,
        correlation_id="cid",
        created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        ai_narrative=ai_narrative,
    )


def _narrative() -> AINarrative:
    return AINarrative(
        summary="Suspicious activity detected.",
        false_positive_likelihood="low",
        suggested_actions=["Block IP"],
        confidence="high",
        model="test-model",
        generated_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )


# --- terminal_renderer ---

def test_terminal_render_returns_count():
    out = io.StringIO()
    count = render_terminal([_finding(), _finding(value="evil.example.com", ioc_type=IOCType.DOMAIN)], out)
    assert count == 2


def test_terminal_render_contains_severity_badge():
    out = io.StringIO()
    render_terminal([_finding(severity=Severity.HIGH)], out)
    assert "[!]" in out.getvalue()


def test_terminal_render_critical_badge():
    out = io.StringIO()
    render_terminal([_finding(severity=Severity.CRITICAL)], out)
    assert "[!!]" in out.getvalue()


def test_terminal_render_contains_ioc_value():
    out = io.StringIO()
    render_terminal([_finding(value="8.8.8.8")], out)
    assert "8.8.8.8" in out.getvalue()


def test_terminal_render_contains_score():
    out = io.StringIO()
    render_terminal([_finding(score=75)], out)
    assert "75" in out.getvalue()


def test_terminal_render_ai_narrative_shown():
    out = io.StringIO()
    render_terminal([_finding(ai_narrative=_narrative())], out)
    output = out.getvalue()
    assert "[AI-generated advisory]" in output
    assert "Suspicious activity detected." in output


def test_terminal_render_no_narrative_no_ai_line():
    out = io.StringIO()
    render_terminal([_finding(ai_narrative=None)], out)
    assert "[AI-generated advisory]" not in out.getvalue()


def test_terminal_render_strips_ansi():
    out = io.StringIO()
    render_terminal([_finding(value="\x1b[31mevil\x1b[0m.com")], out)
    assert "\x1b" not in out.getvalue()


def test_terminal_render_empty_list():
    out = io.StringIO()
    count = render_terminal([], out)
    assert count == 0
    assert out.getvalue() == ""


# --- json_renderer ---

def test_json_render_returns_count():
    out = io.StringIO()
    count = render_json([_finding(), _finding()], out)
    assert count == 2


def test_json_render_valid_json():
    out = io.StringIO()
    render_json([_finding()], out)
    parsed = json.loads(out.getvalue())
    assert parsed["version"] == 2
    assert len(parsed["findings"]) == 1


def test_json_render_contains_ioc_value():
    out = io.StringIO()
    render_json([_finding(value="1.2.3.4")], out)
    assert "1.2.3.4" in out.getvalue()


def test_json_render_empty_list():
    out = io.StringIO()
    count = render_json([], out)
    assert count == 0
    parsed = json.loads(out.getvalue())
    assert parsed["findings"] == []


def test_json_render_sorted_keys():
    out = io.StringIO()
    render_json([_finding()], out)
    raw = out.getvalue()
    # sort_keys=True garantisi — "findings" "version"'dan önce gelir alfabetik olarak
    assert raw.index('"findings"') < raw.index('"version"')