# tests/unit/test_cli_main.py
"""Smoke tests for CLI subcommand routing."""

from __future__ import annotations

from typer.testing import CliRunner

from tic.cli.main import app

runner = CliRunner()


def test_root_help_lists_subcommands():
    r = runner.invoke(app, ["--help"])
    assert r.exit_code == 0
    assert "sweep" in r.stdout
    assert "audit" in r.stdout
    assert "cache" in r.stdout
    assert "config" in r.stdout


def test_sweep_help_works():
    r = runner.invoke(app, ["sweep", "--help"])
    assert r.exit_code == 0
    assert "--feed" in r.stdout
    assert "--output-mode" in r.stdout


def test_audit_help_lists_commands():
    r = runner.invoke(app, ["audit", "--help"])
    assert r.exit_code == 0
    assert "verify" in r.stdout
    assert "tail" in r.stdout


def test_cache_help_lists_commands():
    r = runner.invoke(app, ["cache", "--help"])
    assert r.exit_code == 0
    assert "purge" in r.stdout
    assert "stats" in r.stdout


def test_config_help_lists_commands():
    r = runner.invoke(app, ["config", "--help"])
    assert r.exit_code == 0
    assert "show" in r.stdout
    assert "set-key" in r.stdout


def test_unknown_subcommand_nonzero():
    r = runner.invoke(app, ["nonsense"])
    assert r.exit_code != 0
