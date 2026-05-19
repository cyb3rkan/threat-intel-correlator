# tests/e2e/test_sweep_e2e.py
"""End-to-end sweep tests. External deps mocked; full pipeline runs."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from tic.cli.commands import sweep as sweep_cmd
from tic.infra.config import PathsConfig, Settings

runner = CliRunner(mix_stderr=False)


def _settings(tmp_path):
    return Settings(
        paths=PathsConfig(
            working_dir=tmp_path,
            cache_dir=tmp_path,
            audit_log_path=tmp_path / "audit.log",
        )
    )  # type: ignore[call-arg]


class _DummyCache:
    def get(self, *_):
        return None

    def set(self, *_):
        pass

    def purge_expired(self):
        return 0

    def close(self):
        pass


@pytest.fixture()
def feed(tmp_path):
    p = tmp_path / "feed.csv"
    p.write_text("value,confidence\n1.2.3.4,90\n", encoding="utf-8")
    return p


@pytest.fixture()
def log_match(tmp_path):
    p = tmp_path / "logs.ndjson"
    p.write_text(
        json.dumps({"@timestamp": "2025-01-01T00:00:00Z", "src_ip": "1.2.3.4"}) + "\n",
        encoding="utf-8",
    )
    return p


@pytest.fixture()
def log_no_match(tmp_path):
    p = tmp_path / "no.ndjson"
    p.write_text(
        json.dumps({"@timestamp": "2025-01-01T00:00:00Z", "src_ip": "8.8.8.8"}) + "\n",
        encoding="utf-8",
    )
    return p


def _patches(tmp_path):
    return [
        patch("tic.cli.commands.sweep.load_settings", return_value=_settings(tmp_path)),
        patch("tic.cli.commands.sweep.build_secret_store", return_value=None),
        patch("tic.cli.commands.sweep.build_cache", return_value=_DummyCache()),
        patch("tic.cli.commands.sweep.build_providers", return_value=[]),
        patch("tic.cli.commands.sweep.build_narrator", return_value=None),
        patch("tic.cli.commands.sweep.close_all"),
        # Hash output_mode requires a redaction HMAC key (R5). Provide a
        # deterministic fake key to keep the existing hash test green; this
        # is test fixture data, not a real secret.
        patch(
            "tic.cli.commands.sweep.try_load_redaction_hmac",
            return_value=b"unit-test-hmac-key-32-bytes-padded!!",
        ),
    ]


def test_match_produces_terminal_output(tmp_path, feed, log_match):
    with (
        _patches(tmp_path)[0],
        _patches(tmp_path)[1],
        _patches(tmp_path)[2],
        _patches(tmp_path)[3],
        _patches(tmp_path)[4],
        _patches(tmp_path)[5],
        _patches(tmp_path)[6],
    ):
        result = runner.invoke(
            sweep_cmd.app,
            [
                "--feed",
                str(feed),
                "--logs",
                str(log_match),
                "--format",
                "terminal",
                "--fail-on",
                "critical",
            ],
        )
    assert result.exit_code == 0, result.output
    assert "1.2.3.4" in result.stdout


def test_json_output_parseable(tmp_path, feed, log_match):
    with (
        _patches(tmp_path)[0],
        _patches(tmp_path)[1],
        _patches(tmp_path)[2],
        _patches(tmp_path)[3],
        _patches(tmp_path)[4],
        _patches(tmp_path)[5],
        _patches(tmp_path)[6],
    ):
        result = runner.invoke(
            sweep_cmd.app,
            [
                "--feed",
                str(feed),
                "--logs",
                str(log_match),
                "--format",
                "json",
                "--fail-on",
                "critical",
            ],
        )
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    assert "findings" in parsed
    assert len(parsed["findings"]) >= 1
    f = parsed["findings"][0]
    assert "ioc_value" in f and "score" in f and "severity" in f


def test_no_match_exits_zero(tmp_path, feed, log_no_match):
    with (
        _patches(tmp_path)[0],
        _patches(tmp_path)[1],
        _patches(tmp_path)[2],
        _patches(tmp_path)[3],
        _patches(tmp_path)[4],
        _patches(tmp_path)[5],
        _patches(tmp_path)[6],
    ):
        result = runner.invoke(
            sweep_cmd.app,
            [
                "--feed",
                str(feed),
                "--logs",
                str(log_no_match),
                "--format",
                "json",
                "--fail-on",
                "high",
            ],
        )
    assert result.exit_code == 0
    assert json.loads(result.stdout)["findings"] == []


def test_fail_on_info_exits_one(tmp_path, feed, log_match):
    with (
        _patches(tmp_path)[0],
        _patches(tmp_path)[1],
        _patches(tmp_path)[2],
        _patches(tmp_path)[3],
        _patches(tmp_path)[4],
        _patches(tmp_path)[5],
        _patches(tmp_path)[6],
    ):
        result = runner.invoke(
            sweep_cmd.app,
            [
                "--feed",
                str(feed),
                "--logs",
                str(log_match),
                "--format",
                "json",
                "--fail-on",
                "info",
            ],
        )
    assert result.exit_code == 1


def test_invalid_format_exits_config_error(tmp_path, feed, log_no_match):
    result = runner.invoke(
        sweep_cmd.app, ["--feed", str(feed), "--logs", str(log_no_match), "--format", "avro"]
    )
    assert result.exit_code == 2


def test_summary_mode_truncates_ioc(tmp_path, feed, log_match):
    with (
        _patches(tmp_path)[0],
        _patches(tmp_path)[1],
        _patches(tmp_path)[2],
        _patches(tmp_path)[3],
        _patches(tmp_path)[4],
        _patches(tmp_path)[5],
        _patches(tmp_path)[6],
    ):
        result = runner.invoke(
            sweep_cmd.app,
            [
                "--feed",
                str(feed),
                "--logs",
                str(log_match),
                "--format",
                "json",
                "--fail-on",
                "critical",
                "--output-mode",
                "summary",
            ],
        )
    assert result.exit_code == 0
    f = json.loads(result.stdout)["findings"][0]
    assert f["ioc_value"].endswith("…")
    assert "1.2.3.4" not in f["ioc_value"]


def test_hash_mode_uses_hmac_prefix(tmp_path, feed, log_match):
    with (
        _patches(tmp_path)[0],
        _patches(tmp_path)[1],
        _patches(tmp_path)[2],
        _patches(tmp_path)[3],
        _patches(tmp_path)[4],
        _patches(tmp_path)[5],
        _patches(tmp_path)[6],
    ):
        result = runner.invoke(
            sweep_cmd.app,
            [
                "--feed",
                str(feed),
                "--logs",
                str(log_match),
                "--format",
                "json",
                "--fail-on",
                "critical",
                "--output-mode",
                "hash",
            ],
        )
    assert result.exit_code == 0
    f = json.loads(result.stdout)["findings"][0]
    assert f["ioc_value"].startswith("hmac:")


def test_deterministic_output(tmp_path, feed, log_match):
    outputs = []
    for _ in range(2):
        with (
            _patches(tmp_path)[0],
            _patches(tmp_path)[1],
            _patches(tmp_path)[2],
            _patches(tmp_path)[3],
            _patches(tmp_path)[4],
            _patches(tmp_path)[5],
            _patches(tmp_path)[6],
        ):
            result = runner.invoke(
                sweep_cmd.app,
                [
                    "--feed",
                    str(feed),
                    "--logs",
                    str(log_match),
                    "--format",
                    "json",
                    "--fail-on",
                    "critical",
                ],
            )
        findings = json.loads(result.stdout)["findings"]
        outputs.append([(f["score"], f["severity"], f["ioc_value"]) for f in findings])
    assert outputs[0] == outputs[1]


# --- R5 regression: hash mode requires the redaction HMAC key ---


def test_hash_mode_without_hmac_key_exits_with_friendly_error(tmp_path, feed, log_match):
    """When the redaction HMAC key is missing, hash mode must fail closed
    with a friendly message — never silently fall back to a deterministic
    zero-key. CLI exit code must reflect the config error."""
    patches = [
        patch("tic.cli.commands.sweep.load_settings", return_value=_settings(tmp_path)),
        patch("tic.cli.commands.sweep.build_secret_store", return_value=None),
        patch("tic.cli.commands.sweep.build_cache", return_value=_DummyCache()),
        patch("tic.cli.commands.sweep.build_providers", return_value=[]),
        patch("tic.cli.commands.sweep.build_narrator", return_value=None),
        patch("tic.cli.commands.sweep.close_all"),
        patch("tic.cli.commands.sweep.try_load_redaction_hmac", return_value=None),
    ]
    with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
        result = runner.invoke(
            sweep_cmd.app,
            [
                "--feed",
                str(feed),
                "--logs",
                str(log_match),
                "--format",
                "json",
                "--fail-on",
                "critical",
                "--output-mode",
                "hash",
            ],
        )
    assert result.exit_code != 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "Hash output mode requires" in combined
    assert "tic config set-key redaction-hmac" in combined
    # Stay tight: the bad fallback would have produced an "hmac:" prefix in
    # findings; with the fix there should be no findings JSON at all.
    assert "hmac:" not in combined
