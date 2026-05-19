# tests/unit/test_audit_cmd.py
from __future__ import annotations
from pathlib import Path
from unittest.mock import patch
import pytest
from typer.testing import CliRunner
from tic.adapters.audit.hash_chain import HashChainAuditLogger
from tic.cli.commands import audit_cmd
from tic.infra.config import PathsConfig, Settings

runner = CliRunner(mix_stderr=False)

def _settings(tmp_path, audit_path):
    return Settings(paths=PathsConfig(working_dir=tmp_path, cache_dir=tmp_path, audit_log_path=audit_path))  # type: ignore[call-arg]

@pytest.fixture
def log(tmp_path):
    p = tmp_path / "audit.log"
    a = HashChainAuditLogger(p)
    for i in range(3): a.append("evt", {"i": i})
    return p

def test_verify_ok(log, tmp_path):
    with patch("tic.cli.commands.audit_cmd.load_settings", return_value=_settings(tmp_path, log)):
        r = runner.invoke(audit_cmd.app, ["verify"])
    assert r.exit_code == 0 and "OK" in r.stdout

def test_verify_detects_tamper(log, tmp_path):
    lines = log.read_text().splitlines()
    lines[0] = lines[0].replace('"i":0', '"i":99')
    log.write_text("\n".join(lines) + "\n")
    with patch("tic.cli.commands.audit_cmd.load_settings", return_value=_settings(tmp_path, log)):
        r = runner.invoke(audit_cmd.app, ["verify"])
    assert r.exit_code != 0

def test_tail_default(log, tmp_path):
    with patch("tic.cli.commands.audit_cmd.load_settings", return_value=_settings(tmp_path, log)):
        r = runner.invoke(audit_cmd.app, ["tail"])
    assert r.exit_code == 0 and r.stdout.count("evt") == 3

def test_tail_n1(log, tmp_path):
    with patch("tic.cli.commands.audit_cmd.load_settings", return_value=_settings(tmp_path, log)):
        r = runner.invoke(audit_cmd.app, ["tail", "-n", "1"])
    assert r.exit_code == 0 and r.stdout.count("evt") == 1

def test_tail_empty(tmp_path):
    empty = tmp_path / "audit.log"; empty.touch()
    with patch("tic.cli.commands.audit_cmd.load_settings", return_value=_settings(tmp_path, empty)):
        r = runner.invoke(audit_cmd.app, ["tail"])
    assert r.exit_code == 0

def test_tail_strips_ansi(tmp_path):
    log = tmp_path / "audit.log"
    log.write_text("\x1b[31mNOT-JSON\x1b[0m\n")
    with patch("tic.cli.commands.audit_cmd.load_settings", return_value=_settings(tmp_path, log)):
        r = runner.invoke(audit_cmd.app, ["tail"])
    assert "\x1b" not in r.stdout and "NOT-JSON" in r.stdout
