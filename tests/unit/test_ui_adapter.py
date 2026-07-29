# tests/unit/test_ui_adapter.py
"""Unit tests for the Streamlit UI adapter (no streamlit import).

These tests reuse fixtures from tests/conftest.py:
  - tmp_settings: Settings with working_dir = tmp_path
  - csv_feed_factory / log_with_ip / make_finding
"""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tic.domain.errors import SecurityViolationError
from tic.domain.finding import Finding, Severity
from tic.domain.ioc import IOC, IOCType
from tic.ui import adapter

# ---------------------------------------------------------------------------
# Upload staging
# ---------------------------------------------------------------------------


def test_make_upload_dir_inside_working_dir(tmp_settings) -> None:
    wd = tmp_settings.paths.working_dir
    up = adapter.make_upload_dir(wd)
    assert up.exists()
    assert up.is_dir()
    # Must live under <working_dir>/.tic-ui-uploads/<uuid>
    assert up.parent.name == adapter.UI_UPLOAD_DIRNAME
    assert wd in up.parents or up.parent.parent == wd


def test_stage_upload_uuid_name_and_safe_extension(tmp_settings) -> None:
    wd = tmp_settings.paths.working_dir
    up = adapter.make_upload_dir(wd)
    target = adapter.stage_upload(
        b"value\n1.2.3.4\n",
        upload_dir=up,
        working_dir=wd,
        original_filename="../../etc/passwd.csv",
    )
    # Original name (and its traversal segments) is discarded.
    assert "passwd" not in target.name
    assert "etc" not in str(target)
    assert target.suffix == ".csv"
    assert target.read_bytes() == b"value\n1.2.3.4\n"
    # Path is contained in working_dir.
    assert wd.resolve() in target.resolve().parents


def test_stage_upload_strips_unsafe_extension(tmp_settings) -> None:
    wd = tmp_settings.paths.working_dir
    up = adapter.make_upload_dir(wd)
    target = adapter.stage_upload(b"x", upload_dir=up, working_dir=wd, original_filename="evil.exe")
    assert target.suffix == ""  # .exe is not on SAFE_EXTENSIONS


def test_stage_upload_rejects_dir_outside_working_dir(tmp_settings, tmp_path_factory) -> None:
    wd = tmp_settings.paths.working_dir
    outside = tmp_path_factory.mktemp("outside")
    with pytest.raises(SecurityViolationError):
        adapter.stage_upload(b"x", upload_dir=outside, working_dir=wd, original_filename="a.csv")


def test_cleanup_upload_dir_removes_tree(tmp_settings) -> None:
    wd = tmp_settings.paths.working_dir
    up = adapter.make_upload_dir(wd)
    (up / "blob").write_bytes(b"x")
    adapter.cleanup_upload_dir(up)
    assert not up.exists()


# ---------------------------------------------------------------------------
# AI feasibility
# ---------------------------------------------------------------------------


def test_ai_supported_default_false(tmp_settings) -> None:
    assert adapter.ai_supported(tmp_settings) is False


# ---------------------------------------------------------------------------
# Public-row projection contains only safe fields
# ---------------------------------------------------------------------------


def _finding_with_value(
    value: str,
    default_profile,
    score: int = 50,
    severity: Severity = Severity.MEDIUM,
    ioc_type: IOCType = IOCType.DOMAIN,
) -> Finding:
    ioc = IOC(value=value, ioc_type=ioc_type, source="test", confidence=80)
    return Finding(
        finding_id="00000000-0000-4000-8000-000000000001",
        ioc=ioc,
        matches=[],
        enrichments=[],
        score=score,
        severity=severity,
        profile_hash=default_profile.profile_hash(),
        correlation_id="cid",
        created_at=datetime(2025, 1, 1, tzinfo=UTC),
    )


def test_public_rows_only_exposes_safe_keys(default_profile) -> None:
    f = _finding_with_value("evil.example.com", default_profile)
    rows = adapter.public_rows([f], "analyst")
    assert len(rows) == 1
    expected_keys = {
        "severity",
        "score",
        "type",
        "value",
        "matches",
        "providers",
        "ai",
        "finding_id",
    }
    assert set(rows[0].keys()) == expected_keys


# ---------------------------------------------------------------------------
# JSON export does not leak raw fields
# ---------------------------------------------------------------------------


def test_to_json_bytes_omits_raw_log_and_truncated_raw(default_profile) -> None:
    f = _finding_with_value("evil.example.com", default_profile)
    blob = adapter.to_json_bytes([f], "analyst")
    text = blob.decode("utf-8")
    # PublicFinding never carries these.
    assert "truncated_raw" not in text
    assert "raw_line_hash" not in text
    assert "log_source" not in text
    # Sanity: it parses and contains the finding.
    payload = json.loads(text)
    assert payload["findings"][0]["ioc_value"] == "evil.example.com"


# ---------------------------------------------------------------------------
# CSV export: formula injection mitigation + QUOTE_ALL
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "trigger,ioc_type",
    [
        ("=cmd|' /C calc'!A0", IOCType.DOMAIN),
        ("+1.2.3.4", IOCType.DOMAIN),
        ("-2.3.4.5", IOCType.DOMAIN),
        ("@evil.example.com", IOCType.DOMAIN),
    ],
)
def test_to_csv_escapes_formula_triggers(default_profile, trigger: str, ioc_type: IOCType) -> None:
    # Note: tab/CR are stripped earlier by IOC normalization, so we only assert
    # the CSV-level mitigation for prefixes that can survive normalization.
    f = _finding_with_value(trigger, default_profile, ioc_type=ioc_type)
    blob = adapter.to_csv_bytes([f], "analyst")
    text = blob.decode("utf-8")
    rows = list(csv.reader(io.StringIO(text)))
    # Header + 1 data row.
    assert len(rows) == 2
    data = rows[1]
    # The ioc_value column lives at index 4 (see _CSV_COLUMNS in adapter).
    assert data[4].startswith("'"), f"value cell not escaped: {data[4]!r}"


def test_to_csv_uses_quote_all(default_profile) -> None:
    f = _finding_with_value("evil.example.com", default_profile)
    blob = adapter.to_csv_bytes([f], "analyst")
    text = blob.decode("utf-8")
    # Every cell wrapped in double quotes.
    first_line = text.splitlines()[0]
    cells = first_line.split(",")
    assert all(c.startswith('"') and c.endswith('"') for c in cells)


def test_to_markdown_bytes_renders(default_profile) -> None:
    f = _finding_with_value("evil.example.com", default_profile)
    md = adapter.to_markdown_bytes([f], "analyst").decode("utf-8")
    assert "Threat Intel Correlator" in md
    assert "evil" in md  # value is markdown-escaped but still present


# ---------------------------------------------------------------------------
# End-to-end via run_sweep (no providers, no AI)
# ---------------------------------------------------------------------------


def test_run_sweep_end_to_end(tmp_settings, csv_feed_factory, log_with_ip) -> None:
    feed = csv_feed_factory(["1.2.3.4"])
    req = adapter.SweepRequest(
        feed_path=feed,
        feed_format="csv",
        log_path=log_with_ip,
        output_mode="analyst",
        fail_on="critical",
        with_ai=False,
    )
    result = adapter.run_sweep(req, tmp_settings)
    assert isinstance(result, adapter.SweepResult)
    assert len(result.findings) == 1
    assert result.findings[0].ioc.value == "1.2.3.4"
    # public_rows mirrors the finding count.
    rows = adapter.public_rows(result.findings, "analyst")
    assert len(rows) == 1


def test_run_sweep_translates_tic_error_to_runtime_error(tmp_settings) -> None:
    # Feed path outside working_dir → SecurityViolationError inside parser →
    # adapter must convert this to a friendly RuntimeError without leaking traceback.
    bogus = Path("/definitely/not/in/working_dir/feed.csv")
    req = adapter.SweepRequest(
        feed_path=bogus,
        feed_format="csv",
        log_path=bogus,
        output_mode="analyst",
        fail_on="high",
        with_ai=False,
    )
    with pytest.raises(RuntimeError) as exc:
        adapter.run_sweep(req, tmp_settings)
    msg = str(exc.value)
    # The friendly message must not contain the absolute path or stack details.
    assert "/definitely/not/in/working_dir" not in msg
    assert "Traceback" not in msg


def test_output_mode_summary_truncates_value(default_profile) -> None:
    f = _finding_with_value("evil.example.com", default_profile)
    rows = adapter.public_rows([f], "summary")
    assert rows[0]["value"].endswith("…")
    assert len(rows[0]["value"]) <= 9


def test_output_mode_hash_pseudonymizes_value(default_profile) -> None:
    # R5: hash mode now requires a real HMAC key — pass one explicitly.
    f = _finding_with_value("evil.example.com", default_profile)
    rows = adapter.public_rows([f], "hash", hmac_key=b"unit-test-key-32-bytes-padded!!!")
    assert rows[0]["value"].startswith("hmac:")
    assert "evil.example.com" not in rows[0]["value"]


def test_output_mode_hash_without_key_raises_config_error(default_profile) -> None:
    """R5 regression: rendering hash mode with no key must NOT silently
    fall back to a deterministic zero-key — it raises ConfigError."""
    from tic.domain.errors import ConfigError

    f = _finding_with_value("evil.example.com", default_profile)
    with pytest.raises(ConfigError):
        adapter.public_rows([f], "hash")  # no hmac_key
