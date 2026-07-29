# tests/unit/test_keyring_store.py
from __future__ import annotations

from unittest.mock import patch

import pytest
from keyring.errors import KeyringError

from tic.adapters.secrets.keyring_store import KeyringSecretStore
from tic.domain.errors import AuthError, ConfigError


def test_returns_bytes_on_success():
    with patch(
        "tic.adapters.secrets.keyring_store.keyring.get_password", return_value="supersecret"
    ):
        store = KeyringSecretStore()
        result = store.get("my-service", "my-user")
    assert result == b"supersecret"
    assert isinstance(result, bytes)


def test_raises_config_error_when_none():
    with patch("tic.adapters.secrets.keyring_store.keyring.get_password", return_value=None):
        store = KeyringSecretStore()
        with pytest.raises(ConfigError):
            store.get("svc", "usr")


def test_raises_config_error_when_empty_string():
    with patch("tic.adapters.secrets.keyring_store.keyring.get_password", return_value=""):
        store = KeyringSecretStore()
        with pytest.raises(ConfigError):
            store.get("svc", "usr")


def test_raises_auth_error_on_keyring_error():
    with patch(
        "tic.adapters.secrets.keyring_store.keyring.get_password",
        side_effect=KeyringError("backend failure"),
    ):
        store = KeyringSecretStore()
        with pytest.raises(AuthError):
            store.get("svc", "usr")


def test_encodes_unicode_correctly():
    with patch("tic.adapters.secrets.keyring_store.keyring.get_password", return_value="şifrém"):
        store = KeyringSecretStore()
        result = store.get("svc", "usr")
    assert result == "şifrém".encode()
