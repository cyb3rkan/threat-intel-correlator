# tests/unit/test_config_cmd.py
from __future__ import annotations

from unittest.mock import patch

from typer.testing import CliRunner

from tic.cli.commands import config_cmd
from tic.infra.config import PathsConfig, ProviderConfig, Settings

runner = CliRunner()


def _s(tmp_path):
    return Settings(
        paths=PathsConfig(
            working_dir=tmp_path, cache_dir=tmp_path, audit_log_path=tmp_path / "a.log"
        ),
        providers={"abuseipdb": ProviderConfig(keyring_service="tic-ab", keyring_user="default")},
    )  # type: ignore[call-arg]


def test_show_prints_paths(tmp_path):
    with patch("tic.cli.commands.config_cmd.load_settings", return_value=_s(tmp_path)):
        r = runner.invoke(config_cmd.app, ["show"])
    assert r.exit_code == 0 and str(tmp_path) in r.stdout


def test_set_key_stdin(tmp_path):
    with (
        patch("tic.cli.commands.config_cmd.load_settings", return_value=_s(tmp_path)),
        patch("tic.cli.commands.config_cmd.keyring.set_password") as mock_set,
    ):
        r = runner.invoke(config_cmd.app, ["set-key", "abuseipdb"], input="my-secret\n")
    assert r.exit_code == 0
    mock_set.assert_called_once_with("tic-ab", "default", "my-secret")
    assert "my-secret" not in r.stdout


def test_set_key_empty_rejected(tmp_path):
    with (
        patch("tic.cli.commands.config_cmd.load_settings", return_value=_s(tmp_path)),
        patch("tic.cli.commands.config_cmd.keyring.set_password") as mock_set,
    ):
        r = runner.invoke(config_cmd.app, ["set-key", "abuseipdb"], input="\n")
    assert r.exit_code != 0
    mock_set.assert_not_called()


def test_delete_key_yes(tmp_path):
    with (
        patch("tic.cli.commands.config_cmd.load_settings", return_value=_s(tmp_path)),
        patch("tic.cli.commands.config_cmd.keyring.delete_password") as mock_del,
    ):
        r = runner.invoke(config_cmd.app, ["delete-key", "abuseipdb", "--yes"])
    assert r.exit_code == 0
    mock_del.assert_called_once()


def test_delete_key_decline(tmp_path):
    with (
        patch("tic.cli.commands.config_cmd.load_settings", return_value=_s(tmp_path)),
        patch("tic.cli.commands.config_cmd.keyring.delete_password") as mock_del,
    ):
        r = runner.invoke(config_cmd.app, ["delete-key", "abuseipdb"], input="n\n")
    assert r.exit_code == 0
    mock_del.assert_not_called()
