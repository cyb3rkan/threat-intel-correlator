# tests/integration/test_api_provider_status.py
"""Integration tests for GET /api/providers/status.

The endpoint MUST:
- Return 200 with stable shape under default config.
- Never include keys, keyring service/user names, full endpoint URLs,
  allowed_hosts, model names, file paths, or tracebacks in the response
  body.
- Not require a sweep to be runnable (no provider instantiation).
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from tic.infra.config import (
    AIConfig,
    PathsConfig,
    ProviderConfig,
    Settings,
)


_FAKE_KEY = b"unit-test-key-not-a-real-secret-32"


class _FakeSecretStore:
    def __init__(self, store=None):
        self._store = store or {}

    def get(self, service: str, user: str) -> bytes:
        v = self._store.get((service, user))
        if v is None:
            raise RuntimeError("missing")
        return v


def _settings(tmp_path: Path, **overrides) -> Settings:
    base = {
        "paths": PathsConfig(
            working_dir=tmp_path,
            cache_dir=tmp_path,
            audit_log_path=tmp_path / "audit.log",
        ),
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


def _client(settings: Settings, secret_store) -> TestClient:
    """Build a TestClient with adapter.get_settings + build_secret_store
    monkey-patched. We import the FastAPI app fresh per test for isolation."""
    from tic.api import main as api_main
    with patch.object(api_main.adapter, "get_settings", return_value=settings), \
         patch.object(api_main, "build_secret_store", return_value=secret_store):
        yield_client = TestClient(api_main.app)
        return yield_client


def test_status_returns_200_and_stable_shape(tmp_path):
    s = _settings(tmp_path)
    from tic.api import main as api_main
    with patch.object(api_main.adapter, "get_settings", return_value=s), \
         patch.object(api_main, "build_secret_store", return_value=_FakeSecretStore()):
        c = TestClient(api_main.app)
        r = c.get("/api/providers/status")
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) == {"providers", "ai", "redaction_hmac"}
    names = {p["name"] for p in body["providers"]}
    assert names == {"abuseipdb", "virustotal", "misp"}
    for p in body["providers"]:
        assert set(p.keys()) == {
            "name", "configured", "enabled", "key_present",
            "supported_ioc_types", "endpoint_kind", "ready", "reason",
        }
    assert set(body["ai"].keys()) == {"enabled", "endpoint_count", "key_present", "ready", "reason"}


def test_status_endpoint_does_not_leak_secrets(tmp_path):
    """End-to-end leak guard: configure 'real-looking' values, ensure none
    of them appear in the JSON response body."""
    s = _settings(
        tmp_path,
        ai=AIConfig(
            enabled=True,
            endpoint_allowlist=["https://ai.example.test/v1/chat"],
            keyring_service="secret-ai-svc",
            keyring_user="prod-user",
            model="gpt-test-model",
        ),
        providers={
            "misp": ProviderConfig(
                enabled=True,
                keyring_service="secret-misp-svc",
                keyring_user="prod-user",
                endpoint="https://misp.internal.example",
                allowed_hosts=["misp.internal.example"],
            ),
            "virustotal": ProviderConfig(
                enabled=True,
                keyring_service="secret-vt-svc",
                keyring_user="prod-user",
            ),
        },
    )
    secret_store = _FakeSecretStore({
        ("secret-ai-svc", "prod-user"): b"AI_KEY_DO_NOT_LEAK",
        ("secret-misp-svc", "prod-user"): b"MISP_KEY_DO_NOT_LEAK",
        ("secret-vt-svc", "prod-user"): b"VT_KEY_DO_NOT_LEAK",
    })

    from tic.api import main as api_main
    with patch.object(api_main.adapter, "get_settings", return_value=s), \
         patch.object(api_main, "build_secret_store", return_value=secret_store):
        c = TestClient(api_main.app)
        r = c.get("/api/providers/status")
    assert r.status_code == 200
    body = r.text  # raw JSON string for substring guard

    banned = [
        # Keys
        "AI_KEY_DO_NOT_LEAK",
        "MISP_KEY_DO_NOT_LEAK",
        "VT_KEY_DO_NOT_LEAK",
        # Keyring service / user names
        "secret-ai-svc",
        "secret-misp-svc",
        "secret-vt-svc",
        "prod-user",
        # Full endpoints
        "ai.example.test",
        "misp.internal.example",
        # Model name
        "gpt-test-model",
        # File path
        str(tmp_path),
        # Traceback markers
        "Traceback",
    ]
    for needle in banned:
        assert needle not in body, f"leak: {needle}"


def test_status_reports_ready_for_fully_configured_providers(tmp_path):
    s = _settings(
        tmp_path,
        providers={
            "abuseipdb": ProviderConfig(enabled=True, keyring_service="a", keyring_user="u"),
            "virustotal": ProviderConfig(enabled=True, keyring_service="v", keyring_user="u"),
            "misp": ProviderConfig(
                enabled=True,
                keyring_service="m",
                keyring_user="u",
                endpoint="https://misp.example.test",
            ),
        },
        ai=AIConfig(
            enabled=True,
            endpoint_allowlist=["https://ai.example.test/v1/chat"],
            keyring_service="ai",
            keyring_user="u",
        ),
    )
    secret_store = _FakeSecretStore({
        ("a", "u"): _FAKE_KEY,
        ("v", "u"): _FAKE_KEY,
        ("m", "u"): _FAKE_KEY,
        ("ai", "u"): _FAKE_KEY,
        (s.redaction_hmac_keyring_service, s.redaction_hmac_keyring_user): _FAKE_KEY,
    })
    from tic.api import main as api_main
    with patch.object(api_main.adapter, "get_settings", return_value=s), \
         patch.object(api_main, "build_secret_store", return_value=secret_store):
        c = TestClient(api_main.app)
        r = c.get("/api/providers/status")
    body = r.json()
    assert all(p["ready"] for p in body["providers"])
    assert body["ai"]["ready"] is True
    assert body["redaction_hmac"]["key_present"] is True


def test_status_reports_safe_state_when_ai_unavailable(tmp_path):
    """AI requested in settings but no key → reason=no_keyring_key, ready=false.
    Frontend uses this to surface a safe inline reason. No leaks."""
    s = _settings(
        tmp_path,
        ai=AIConfig(
            enabled=True,
            endpoint_allowlist=["https://ai.example.test/v1/chat"],
            keyring_service="ai",
            keyring_user="u",
        ),
    )
    from tic.api import main as api_main
    with patch.object(api_main.adapter, "get_settings", return_value=s), \
         patch.object(api_main, "build_secret_store", return_value=_FakeSecretStore()):
        c = TestClient(api_main.app)
        r = c.get("/api/providers/status")
    body = r.json()
    assert body["ai"]["ready"] is False
    assert body["ai"]["reason"] == "no_keyring_key"
    # Endpoint URL must not appear:
    assert "ai.example.test" not in r.text


def test_status_settles_for_minimal_default_config(tmp_path):
    """Smoke: the default empty config should still return a valid response
    (no providers configured, AI disabled, redaction key absent)."""
    from tic.api import main as api_main
    s = _settings(tmp_path)
    with patch.object(api_main.adapter, "get_settings", return_value=s), \
         patch.object(api_main, "build_secret_store", return_value=_FakeSecretStore()):
        c = TestClient(api_main.app)
        r = c.get("/api/providers/status")
    assert r.status_code == 200
    body = r.json()
    assert body["ai"]["reason"] == "ai_disabled"
    assert all(p["reason"] == "not_configured" for p in body["providers"])
    assert body["redaction_hmac"]["key_present"] is False
