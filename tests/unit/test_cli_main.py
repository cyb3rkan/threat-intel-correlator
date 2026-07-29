# tests/unit/test_cli_main.py
"""Smoke tests for CLI subcommand routing."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from tic.cli.main import app
from tic.security.ansi_strip import strip_terminal_controls

# Force a wide terminal so Rich never wraps option names (e.g. "--feed") across
# lines. Without this, narrow CI terminals split flags mid-word and substring
# asserts flake. mix_stderr collapses stderr into stdout for older Typer/Click.
runner = CliRunner()


@pytest.fixture(autouse=True)
def _wide_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.setenv("TERM", "dumb")


def _help(args: list[str]) -> str:
    """Invoke `args` and return ANSI-stripped stdout for stable substring checks."""
    r = runner.invoke(app, args)
    assert r.exit_code == 0, r.stdout
    return strip_terminal_controls(r.stdout)


def test_root_help_lists_subcommands():
    out = _help(["--help"])
    assert "sweep" in out
    assert "audit" in out
    assert "cache" in out
    assert "config" in out


def test_sweep_help_works():
    out = _help(["sweep", "--help"])
    assert "--feed" in out
    assert "--output-mode" in out


def test_audit_help_lists_commands():
    out = _help(["audit", "--help"])
    assert "verify" in out
    assert "tail" in out


def test_cache_help_lists_commands():
    out = _help(["cache", "--help"])
    assert "purge" in out
    assert "stats" in out


def test_config_help_lists_commands():
    out = _help(["config", "--help"])
    assert "show" in out
    assert "set-key" in out


def test_unknown_subcommand_nonzero():
    r = runner.invoke(app, ["nonsense"])
    assert r.exit_code != 0
