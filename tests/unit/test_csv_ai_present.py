# tests/unit/test_csv_ai_present.py
"""Phase C: CSV exports add the `ai_present` flag column.

Policy option C remains in force: CSV NEVER includes the AI summary, the
suggested_actions, the model name, or any free-text AI content. The flag
column is a yes/no marker so downstream consumers can join CSV rows back
to the JSON export without parsing narrative text inside a spreadsheet.

CSV injection mitigation (`escape_csv_cell`) still applies to every cell.
"""
from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

from tic.domain.finding import AINarrative, Finding, Severity
from tic.domain.ioc import IOC, IOCType
from tic.ui.adapter import to_csv_bytes


def _narrative(summary: str = "Defensive summary.") -> AINarrative:
    return AINarrative(
        summary=summary,
        false_positive_likelihood="low",
        suggested_actions=["Review in SIEM"],
        confidence="medium",
        model="placeholder-model",
        generated_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )


def _finding(*, narrative: AINarrative | None = None) -> Finding:
    return Finding(
        finding_id="00000000-0000-4000-8000-000000000001",
        ioc=IOC(value="evil.example.com", ioc_type=IOCType.DOMAIN, source="feed"),
        matches=[],
        enrichments=[],
        score=72,
        severity=Severity.HIGH,
        profile_hash="a" * 64,
        correlation_id="cid",
        created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        ai_narrative=narrative,
    )


def test_csv_header_contains_ai_present() -> None:
    text = to_csv_bytes([_finding()], "analyst").decode()
    header = text.splitlines()[0]
    assert "ai_present" in header


def test_csv_row_marks_yes_when_narrative_present() -> None:
    text = to_csv_bytes([_finding(narrative=_narrative())], "analyst").decode()
    rows = list(csv.reader(io.StringIO(text)))
    header = rows[0]
    body = rows[1]
    idx = header.index("ai_present")
    assert body[idx] == "yes"


def test_csv_row_marks_no_when_no_narrative() -> None:
    text = to_csv_bytes([_finding(narrative=None)], "analyst").decode()
    rows = list(csv.reader(io.StringIO(text)))
    header = rows[0]
    body = rows[1]
    idx = header.index("ai_present")
    assert body[idx] == "no"


def test_csv_still_omits_ai_summary_and_actions() -> None:
    """Policy option C — text content stays out of CSV regardless of the
    new flag column."""
    summary = "CSV-leak-canary-string-phase-c"
    action = "CSV-action-canary-phase-c"
    n = AINarrative(
        summary=summary,
        false_positive_likelihood="low",
        suggested_actions=[action],
        confidence="medium",
        model="placeholder-model",
        generated_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )
    text = to_csv_bytes([_finding(narrative=n)], "analyst").decode()
    assert summary not in text
    assert action not in text
    # The model name is still kept out, by policy.
    assert "placeholder-model" not in text


def test_csv_injection_protection_still_applies_to_other_cells() -> None:
    """Defence-in-depth: a hostile IOC value that starts with `=` must
    still be neutralised by the formula-injection prefix. This is
    unrelated to AI but Phase C must not have broken it."""
    f = Finding(
        finding_id="00000000-0000-4000-8000-000000000002",
        ioc=IOC(value="=BAD()", ioc_type=IOCType.DOMAIN, source="feed"),
        matches=[],
        enrichments=[],
        score=50,
        severity=Severity.MEDIUM,
        profile_hash="b" * 64,
        correlation_id="cid",
        created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )
    text = to_csv_bytes([f], "analyst").decode()
    # IOC value cell should be prefixed with a single-quote per
    # `escape_csv_cell`. The literal "=BAD()" must not appear at a cell
    # start position.
    assert "'=BAD()" in text
