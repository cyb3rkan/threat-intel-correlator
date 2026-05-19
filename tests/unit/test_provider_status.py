# tests/unit/test_provider_status.py
"""Unit tests for the public-safe provider status helper.

Covers:
- not_configured / disabled / endpoint_missing / no_keyring_key / ok
- AI disabled / allowlist empty / no key / ok
- Leakage check: API keys, keyring service/user names, full endpoints,
  allowed_hosts, model names, file paths must never appear in the output.
"""

from __future__ import annotations

import json
from pathlib import Path

from tic.api._provider_status import build_provider_status
from tic.infra.config import (
    AIConfig,
    PathsConfig,
    ProviderConfig,
    Settings,
)

_FAKE_KEY = b"unit-test-key-not-a-real-secret-32"


class _FakeSecretStore:
    """In-memory secret store. Returns the configured map; raises for misses."""

    def __init__(self, store: dict[tuple[str, str], bytes] | None = None) -> None:
        self._store = store or {}

    def get(self, service: str, user: str) -> bytes:
        v = self._store.get((service, user))
        if v is None:
            raise RuntimeError("missing")
        return v


def _settings(**overrides) -> Settings:
    base = {
        "paths": PathsConfig(
            working_dir=Path.cwd(),
            cache_dir=Path.cwd(),
            audit_log_path=Path.cwd() / "audit.log",
        ),
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Provider matrix
# ---------------------------------------------------------------------------


def test_no_providers_configured_returns_not_configured_for_all_known() -> None:
    s = _settings()
    out = build_provider_status(s, _FakeSecretStore())
    names = {p["name"] for p in out["providers"]}
    assert names == {"abuseipdb", "virustotal", "misp"}
    for p in out["providers"]:
        assert p["configured"] is False
        assert p["enabled"] is False
        assert p["key_present"] is False
        assert p["ready"] is False
        assert p["reason"] == "not_configured"
        assert isinstance(p["supported_ioc_types"], list)
        assert p["endpoint_kind"] in {"public", "internal", "none"}


def test_disabled_provider_reports_disabled() -> None:
    s = _settings(
        providers={
            "abuseipdb": ProviderConfig(
                enabled=False,
                keyring_service="svc",
                keyring_user="u",
            )
        }
    )
    out = build_provider_status(s, _FakeSecretStore({("svc", "u"): _FAKE_KEY}))
    p = next(p for p in out["providers"] if p["name"] == "abuseipdb")
    assert p["configured"] is True
    assert p["enabled"] is False
    assert p["ready"] is False
    assert p["reason"] == "disabled"


def test_misp_without_endpoint_reports_endpoint_missing() -> None:
    s = _settings(
        providers={
            "misp": ProviderConfig(
                enabled=True,
                keyring_service="svc",
                keyring_user="u",
                endpoint=None,
            )
        }
    )
    out = build_provider_status(s, _FakeSecretStore({("svc", "u"): _FAKE_KEY}))
    p = next(p for p in out["providers"] if p["name"] == "misp")
    assert p["reason"] == "endpoint_missing"
    assert p["endpoint_kind"] == "none"
    assert p["ready"] is False


def test_provider_without_key_reports_no_keyring_key() -> None:
    s = _settings(
        providers={
            "virustotal": ProviderConfig(
                enabled=True,
                keyring_service="svc-vt",
                keyring_user="u",
            )
        }
    )
    out = build_provider_status(s, _FakeSecretStore())  # empty
    p = next(p for p in out["providers"] if p["name"] == "virustotal")
    assert p["reason"] == "no_keyring_key"
    assert p["key_present"] is False
    assert p["ready"] is False


def test_provider_ready_when_enabled_with_key_and_endpoint() -> None:
    s = _settings(
        providers={
            "misp": ProviderConfig(
                enabled=True,
                keyring_service="svc-misp",
                keyring_user="u",
                endpoint="https://misp.internal",
            )
        }
    )
    out = build_provider_status(
        s,
        _FakeSecretStore({("svc-misp", "u"): _FAKE_KEY}),
    )
    p = next(p for p in out["providers"] if p["name"] == "misp")
    assert p["configured"] is True
    assert p["enabled"] is True
    assert p["key_present"] is True
    assert p["ready"] is True
    assert p["reason"] == "ok"
    assert p["endpoint_kind"] == "internal"


def test_endpoint_kind_public_for_abuseipdb_and_virustotal() -> None:
    s = _settings(
        providers={
            "abuseipdb": ProviderConfig(enabled=True, keyring_service="a", keyring_user="u"),
            "virustotal": ProviderConfig(enabled=True, keyring_service="v", keyring_user="u"),
        }
    )
    out = build_provider_status(
        s,
        _FakeSecretStore({("a", "u"): _FAKE_KEY, ("v", "u"): _FAKE_KEY}),
    )
    kinds = {
        p["name"]: p["endpoint_kind"]
        for p in out["providers"]
        if p["name"] in {"abuseipdb", "virustotal"}
    }
    assert kinds == {"abuseipdb": "public", "virustotal": "public"}


# ---------------------------------------------------------------------------
# AI matrix
# ---------------------------------------------------------------------------


def test_ai_disabled_by_default() -> None:
    out = build_provider_status(_settings(), _FakeSecretStore())
    assert out["ai"]["enabled"] is False
    assert out["ai"]["ready"] is False
    assert out["ai"]["reason"] == "ai_disabled"


def test_ai_enabled_with_no_endpoints_reports_allowlist_empty() -> None:
    s = _settings(ai=AIConfig(enabled=True, endpoint_allowlist=[]))
    out = build_provider_status(s, _FakeSecretStore())
    assert out["ai"]["reason"] == "endpoint_allowlist_empty"
    assert out["ai"]["ready"] is False


def test_ai_enabled_with_endpoint_but_no_key_reports_no_key() -> None:
    s = _settings(
        ai=AIConfig(
            enabled=True,
            endpoint_allowlist=["https://ai.example.test/v1/chat"],
            keyring_service="ai-svc",
            keyring_user="u",
        )
    )
    out = build_provider_status(s, _FakeSecretStore())
    assert out["ai"]["reason"] == "no_keyring_key"
    assert out["ai"]["endpoint_count"] == 1
    assert out["ai"]["key_present"] is False


def test_ai_ready_when_enabled_endpoint_and_key_present() -> None:
    s = _settings(
        ai=AIConfig(
            enabled=True,
            endpoint_allowlist=["https://ai.example.test/v1/chat"],
            keyring_service="ai-svc",
            keyring_user="u",
        )
    )
    out = build_provider_status(
        s,
        _FakeSecretStore({("ai-svc", "u"): _FAKE_KEY}),
    )
    assert out["ai"]["ready"] is True
    assert out["ai"]["reason"] == "ok"


# ---------------------------------------------------------------------------
# Leakage guards
# ---------------------------------------------------------------------------

_BANNED_SUBSTRINGS = (
    "Authorization",
    "Bearer",
    "x-apikey",
    "api_key",
    "apikey",
    "secret",
    "password",
    "ai-svc",  # keyring service name leak
    "svc-misp",  # keyring service name leak
    "misp.internal",  # full endpoint leak
    "ai.example.test",  # full endpoint leak
    "1.2.3.4",  # allowed_hosts leak
    "gpt",  # model leak
    "model",  # field name (we deliberately don't expose the field at all)
    "/home/",  # file path leak
    "C:\\",
    "Traceback",
)


def test_response_does_not_leak_secrets_or_internals() -> None:
    s = _settings(
        ai=AIConfig(
            enabled=True,
            endpoint_allowlist=["https://ai.example.test/v1/chat"],
            keyring_service="ai-svc",
            keyring_user="u",
            model="gpt-test-model",
        ),
        providers={
            "misp": ProviderConfig(
                enabled=True,
                keyring_service="svc-misp",
                keyring_user="u",
                endpoint="https://misp.internal",
                allowed_hosts=["1.2.3.4"],
            ),
        },
    )
    out = build_provider_status(
        s,
        _FakeSecretStore(
            {
                ("ai-svc", "u"): b"super-secret-ai-key-do-not-leak",
                ("svc-misp", "u"): b"super-secret-misp-key-do-not-leak",
            }
        ),
    )
    serialised = json.dumps(out)
    for banned in _BANNED_SUBSTRINGS:
        assert banned.lower() not in serialised.lower(), f"leaked: {banned}"
    # And of course the actual secret bytes:
    assert "super-secret" not in serialised
    assert "do-not-leak" not in serialised


def test_redaction_hmac_status_only_reports_presence_boolean() -> None:
    s = _settings()
    out = build_provider_status(
        s,
        _FakeSecretStore(
            {(s.redaction_hmac_keyring_service, s.redaction_hmac_keyring_user): _FAKE_KEY}
        ),
    )
    assert out["redaction_hmac"] == {"key_present": True}


def test_verify_tls_false_does_not_leak_into_response() -> None:
    """ProviderConfig.verify_tls is an internal security toggle. The public
    status endpoint must not surface it (no field, no boolean false leak).
    """
    s = _settings(
        providers={
            "misp": ProviderConfig(
                enabled=True,
                keyring_service="svc-misp",
                keyring_user="u",
                endpoint="https://misp.internal",
                allowed_hosts=["misp.internal"],
                verify_tls=False,
            ),
        },
    )
    out = build_provider_status(
        s,
        _FakeSecretStore({("svc-misp", "u"): _FAKE_KEY}),
    )
    serialised = json.dumps(out).lower()
    # The field itself must not appear
    assert "verify_tls" not in serialised
    assert "verifytls" not in serialised
    # And allowed_hosts entries must not leak either
    assert "misp.internal" not in serialised


def test_provider_status_top_level_shape_is_stable() -> None:
    out = build_provider_status(_settings(), _FakeSecretStore())
    assert set(out.keys()) == {"providers", "ai", "redaction_hmac"}
    for p in out["providers"]:
        assert set(p.keys()) == {
            "name",
            "configured",
            "enabled",
            "key_present",
            "supported_ioc_types",
            "endpoint_kind",
            "ready",
            "reason",
        }
    assert set(out["ai"].keys()) == {"enabled", "endpoint_count", "key_present", "ready", "reason"}
    assert set(out["redaction_hmac"].keys()) == {"key_present"}
