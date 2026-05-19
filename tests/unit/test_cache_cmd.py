# tests/unit/test_cache_cmd.py
from __future__ import annotations
import time
from pathlib import Path
from unittest.mock import patch
import pytest
from typer.testing import CliRunner
from tic.adapters.cache.sqlite_cache import SqliteCache
from tic.cli.commands import cache_cmd
from tic.infra.config import PathsConfig, Settings

runner = CliRunner(mix_stderr=False)

def _s(tmp_path):
    return Settings(paths=PathsConfig(working_dir=tmp_path, cache_dir=tmp_path, audit_log_path=tmp_path/"a.log"))  # type: ignore[call-arg]

@pytest.fixture
def filled_cache(tmp_path):
    c = SqliteCache(tmp_path / "tic-cache.sqlite", allowed_root=tmp_path)
    c.set("abuseipdb", "1.2.3.4", b"v1", ttl_seconds=1)
    c.set("virustotal", "evil.com", b"v2", ttl_seconds=3600)
    time.sleep(1.1)
    return tmp_path

def test_purge_requires_confirm(filled_cache):
    with patch("tic.cli.commands.cache_cmd.load_settings", return_value=_s(filled_cache)):
        r = runner.invoke(cache_cmd.app, ["purge"], input="n\n")
    assert r.exit_code == 0

def test_purge_with_yes(filled_cache):
    with patch("tic.cli.commands.cache_cmd.load_settings", return_value=_s(filled_cache)):
        r = runner.invoke(cache_cmd.app, ["purge", "--yes"])
    assert r.exit_code == 0 and "Purged 1" in r.stdout

def test_stats(filled_cache):
    with patch("tic.cli.commands.cache_cmd.load_settings", return_value=_s(filled_cache)):
        r = runner.invoke(cache_cmd.app, ["stats"])
    assert r.exit_code == 0 and "abuseipdb" in r.stdout

def test_stats_no_db(tmp_path):
    with patch("tic.cli.commands.cache_cmd.load_settings", return_value=_s(tmp_path)):
        r = runner.invoke(cache_cmd.app, ["stats"])
    assert r.exit_code == 0 and "0" in r.stdout
