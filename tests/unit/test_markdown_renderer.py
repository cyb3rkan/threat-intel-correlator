# tests/unit/test_markdown_renderer.py
from __future__ import annotations

import io
from datetime import UTC, datetime

from tic.adapters.renderers.markdown_renderer import (
    MarkdownRenderer,
    _md_escape,
    render_markdown,
)
from tic.domain.finding import AINarrative, Finding, Severity
from tic.domain.ioc import IOC, IOCType


def _finding(value: str = "evil.example.com", *, narrative: AINarrative | None = None) -> Finding:
    return Finding(
        finding_id="00000000-0000-4000-8000-000000000000",
        ioc=IOC(value=value, ioc_type=IOCType.DOMAIN, source="feed"),
        matches=[],
        enrichments=[],
        score=72,
        severity=Severity.HIGH,
        profile_hash="a" * 64,
        correlation_id="cid",
        created_at=datetime(2025, 1, 1, tzinfo=UTC),
        ai_narrative=narrative,
    )


def test_empty_findings_produces_zero_count() -> None:
    out = io.StringIO()
    n = render_markdown([], out)
    assert n == 0
    assert "No findings" in out.getvalue()


def test_basic_render_has_expected_structure() -> None:
    out = io.StringIO()
    n = render_markdown([_finding()], out)
    text = out.getvalue()
    assert n == 1
    assert "# Threat Intel Correlator" in text
    assert "## Summary" in text
    assert "## Findings" in text
    assert "HIGH" in text
    # Domain is rendered verbatim because dots are not inline-significant.
    assert "evil.example.com" in text


def test_md_escape_neutralizes_link_injection() -> None:
    raw = "[click](http://evil)"
    escaped = _md_escape(raw)
    # Square brackets and parentheses are escaped with backslashes.
    assert "\\[" in escaped
    assert "\\]" in escaped
    assert "\\(" in escaped
    assert "\\)" in escaped


def test_md_escape_neutralizes_image_injection() -> None:
    # Image syntax is ! followed by a link. We don't escape '!' (context-only
    # in Markdown: only meaningful immediately before '['), but escaping '['
    # alone is sufficient to break the image syntax.
    raw = "![alt](http://evil/x.png)"
    escaped = _md_escape(raw)
    assert "\\[" in escaped


def test_md_escape_neutralizes_html_brackets() -> None:
    raw = "<script>alert(1)</script>"
    escaped = _md_escape(raw)
    assert "\\<" in escaped
    assert "\\>" in escaped


def test_md_escape_strips_ansi() -> None:
    raw = "\x1b[31mRED\x1b[0m text"
    escaped = _md_escape(raw)
    assert "\x1b" not in escaped
    assert "RED" in escaped


def test_md_escape_preserves_common_punctuation() -> None:
    # Hyphens, dots, plus, exclamation are not globally meaningful in inline
    # Markdown and must pass through unchanged for readability.
    raw = "on-prem-llm-v1.2+build!"
    escaped = _md_escape(raw)
    assert escaped == raw


def test_ai_narrative_labeled_as_ai_generated() -> None:
    narrative = AINarrative(
        summary="This looks suspicious.",
        false_positive_likelihood="low",
        suggested_actions=["Investigate host", "Block at firewall"],
        confidence="medium",
        model="on-prem-llm-v1",
        generated_at=datetime(2025, 1, 1, tzinfo=UTC),
    )
    out = io.StringIO()
    render_markdown([_finding(narrative=narrative)], out)
    text = out.getvalue()
    assert "AI-generated advisory" in text
    assert "on-prem-llm-v1" in text
    assert "Investigate host" in text


def test_ai_narrative_renders_as_named_advisory_section() -> None:
    """The advisory must be a named subsection with an explicit
    review-required disclaimer, so it stays unmissable when the report
    is opened by a downstream consumer (PDF, GitHub render, etc.)."""
    narrative = AINarrative(
        summary="Defensive summary.",
        false_positive_likelihood="medium",
        suggested_actions=["review in SIEM"],
        confidence="low",
        model="m1",
        generated_at=datetime(2025, 1, 1, tzinfo=UTC),
    )
    out = io.StringIO()
    render_markdown([_finding(narrative=narrative)], out)
    text = out.getvalue()

    # Named subsection heading is present.
    assert "#### AI Narrative" in text
    # The advisory framing is explicit: review-required AND it does not
    # alter deterministic fields.
    assert "Advisory only" in text
    assert "review required" in text.lower()
    assert "does **not** alter score" in text


def test_ai_narrative_section_omitted_when_no_narrative() -> None:
    out = io.StringIO()
    render_markdown([_finding(narrative=None)], out)
    text = out.getvalue()
    assert "AI Narrative" not in text
    assert "Advisory only" not in text


def test_renderer_protocol() -> None:
    r = MarkdownRenderer()
    assert r.name == "markdown"
    out = io.StringIO()
    n = r.render([_finding()], out)
    assert n == 1
