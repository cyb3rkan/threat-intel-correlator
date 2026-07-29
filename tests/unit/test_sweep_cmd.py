# tests/unit/test_sweep_cmd.py
"""Unit tests for the `tic sweep` command argument parsing.

These tests cover argument validation paths (invalid format, invalid severity)
without running the full sweep pipeline. The full pipeline is exercised by
the e2e suite.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from tic.cli.commands import sweep
from tic.infra.exit_codes import ExitCode

runner = CliRunner()


def _make_files(tmp_path: Path) -> tuple[Path, Path]:
    feed = tmp_path / "feed.csv"
    feed.write_text("value\n1.2.3.4\n", encoding="utf-8")
    logs = tmp_path / "logs.ndjson"
    logs.write_text("", encoding="utf-8")
    return feed, logs


def test_unknown_feed_format_fails(tmp_path: Path) -> None:
    feed, logs = _make_files(tmp_path)
    result = runner.invoke(
        sweep.app,
        [
            "--feed",
            str(feed),
            "--feed-format",
            "xml-soap",
            "--logs",
            str(logs),
        ],
    )
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)


def test_unknown_output_format_fails(tmp_path: Path) -> None:
    feed, logs = _make_files(tmp_path)
    result = runner.invoke(
        sweep.app,
        [
            "--feed",
            str(feed),
            "--logs",
            str(logs),
            "--format",
            "yaml",
        ],
    )
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)


def test_unknown_fail_on_severity_fails(tmp_path: Path) -> None:
    feed, logs = _make_files(tmp_path)
    result = runner.invoke(
        sweep.app,
        [
            "--feed",
            str(feed),
            "--logs",
            str(logs),
            "--fail-on",
            "extreme",
        ],
    )
    assert result.exit_code == int(ExitCode.CONFIG_ERROR)


def test_missing_feed_path_fails(tmp_path: Path) -> None:
    logs = tmp_path / "logs.ndjson"
    logs.write_text("", encoding="utf-8")
    result = runner.invoke(
        sweep.app,
        [
            "--feed",
            str(tmp_path / "does-not-exist.csv"),
            "--logs",
            str(logs),
        ],
    )
    # Typer's `exists=True` returns a Click usage error (exit code 2).
    assert result.exit_code != 0
