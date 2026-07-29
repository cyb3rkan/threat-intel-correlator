# tests/unit/test_env_secret_store.py
"""Part 4: env-var-backed SecretStore for container runtime + backend selection."""
from __future__ import annotations

import pytest

from tic.adapters.secrets.env_store import EnvSecretStore, env_var_name
from tic.adapters.secrets.keyring_store import KeyringSecretStore
from tic.cli._wiring import build_secret_store
from tic.domain.errors import AuthError, ConfigError


def test_mapping_convention_is_uniform() -> None:
    assert env_var_name("tic-virustotal", "default") == "TIC_SECRET__TIC_VIRUSTOTAL__DEFAULT"
    assert env_var_name("tic-abuseipdb", "default") == "TIC_SECRET__TIC_ABUSEIPDB__DEFAULT"
    assert (
        env_var_name("tic-redaction-hmac", "default")
        == "TIC_SECRET__TIC_REDACTION_HMAC__DEFAULT"
    )
    assert env_var_name("tic-audit-hmac", "default") == "TIC_SECRET__TIC_AUDIT_HMAC__DEFAULT"
    # non-alphanumerics collapse to underscore; case-folded.
    assert env_var_name("My.Svc", "u-1") == "TIC_SECRET__MY_SVC__U_1"


def test_resolves_all_four_secret_types(monkeypatch: pytest.MonkeyPatch) -> None:
    # provider x2 (VT/AbuseIPDB), redaction-HMAC, and the Part-2 audit-HMAC must
    # all resolve from env, else prod sign:true halts the container.
    cases = {
        ("tic-virustotal", "default"): b"vt-key-value",
        ("tic-abuseipdb", "default"): b"abuse-key-value",
        ("tic-redaction-hmac", "default"): b"redaction-hmac-secret-bytes",
        ("tic-audit-hmac", "default"): b"audit-hmac-secret-bytes",
    }
    for (svc, usr), val in cases.items():
        monkeypatch.setenv(env_var_name(svc, usr), val.decode())
    store = EnvSecretStore()
    for (svc, usr), val in cases.items():
        assert store.get(svc, usr) == val


def test_missing_variable_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TIC_SECRET__TIC_MISP__DEFAULT", raising=False)
    with pytest.raises(AuthError):
        EnvSecretStore().get("tic-misp", "default")


def test_empty_variable_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TIC_SECRET__TIC_VIRUSTOTAL__DEFAULT", "")
    with pytest.raises(AuthError):
        EnvSecretStore().get("tic-virustotal", "default")


def test_backend_env_selects_env_store(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TIC_SECRET_BACKEND", "env")
    assert isinstance(build_secret_store(), EnvSecretStore)


def test_backend_default_is_keyring(monkeypatch: pytest.MonkeyPatch) -> None:
    # Local/dev path must be unchanged: no env var -> keyring.
    monkeypatch.delenv("TIC_SECRET_BACKEND", raising=False)
    assert isinstance(build_secret_store(), KeyringSecretStore)


def test_backend_keyring_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TIC_SECRET_BACKEND", "keyring")
    assert isinstance(build_secret_store(), KeyringSecretStore)


def test_backend_unknown_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TIC_SECRET_BACKEND", "vault")
    with pytest.raises(ConfigError):
        build_secret_store()
