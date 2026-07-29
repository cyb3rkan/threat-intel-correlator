# tests/unit/test_wiring.py
"""Tests for _wiring factory functions."""

from __future__ import annotations

import pytest

from tic.adapters.cache.sqlite_cache import SqliteCache
from tic.cli import _wiring
from tic.domain.errors import ConfigError
from tic.infra.config import AIConfig, HttpClientConfig, PathsConfig, ProviderConfig, Settings


class _FakeStore:
    def __init__(self, mapping):
        self._m = mapping

    def get(self, service, user):
        try:
            return self._m[(service, user)]
        except KeyError as e:
            raise RuntimeError(f"no key for {service}/{user}") from e


def _settings(tmp_path, providers=None):
    return Settings(
        paths=PathsConfig(
            working_dir=tmp_path, cache_dir=tmp_path, audit_log_path=tmp_path / "a.log"
        ),
        providers=providers or {},
        http=HttpClientConfig(),
    )  # type: ignore[call-arg]


@pytest.fixture()
def cache(tmp_path):
    return SqliteCache(tmp_path / "c.db", allowed_root=tmp_path)


def test_unknown_provider_raises(tmp_path, cache):
    s = _settings(tmp_path, {"typo": ProviderConfig(keyring_service="x", keyring_user="y")})
    with pytest.raises(ConfigError):
        _wiring.build_providers(s, secret_store=_FakeStore({}), cache=cache)


def test_disabled_provider_skipped(tmp_path, cache):
    s = _settings(
        tmp_path,
        {"abuseipdb": ProviderConfig(enabled=False, keyring_service="x", keyring_user="y")},
    )
    assert (
        _wiring.build_providers(s, secret_store=_FakeStore({("x", "y"): b"k"}), cache=cache) == []
    )


def test_missing_key_skipped(tmp_path, cache):
    s = _settings(tmp_path, {"abuseipdb": ProviderConfig(keyring_service="x", keyring_user="y")})
    assert _wiring.build_providers(s, secret_store=_FakeStore({}), cache=cache) == []


def test_abuseipdb_built(tmp_path, cache):
    s = _settings(tmp_path, {"abuseipdb": ProviderConfig(keyring_service="x", keyring_user="y")})
    out = _wiring.build_providers(s, secret_store=_FakeStore({("x", "y"): b"k"}), cache=cache)
    assert len(out) == 1 and out[0].name == "abuseipdb"


def test_narrator_disabled(tmp_path):
    s = Settings(
        paths=PathsConfig(
            working_dir=tmp_path, cache_dir=tmp_path, audit_log_path=tmp_path / "a.log"
        ),
        ai=AIConfig(enabled=False),
    )  # type: ignore[call-arg]
    assert _wiring.build_narrator(s, secret_store=_FakeStore({})) is None


def test_narrator_no_endpoint(tmp_path):
    s = Settings(
        paths=PathsConfig(
            working_dir=tmp_path, cache_dir=tmp_path, audit_log_path=tmp_path / "a.log"
        ),
        ai=AIConfig(enabled=True, endpoint_allowlist=[]),
    )  # type: ignore[call-arg]
    assert _wiring.build_narrator(s, secret_store=_FakeStore({})) is None


# ---------------------------------------------------------------------------
# Phase A additions: freeze AI fail-safe wiring behaviour.
#
# Contracts:
#   - ai.enabled=false  → build_narrator returns None and never touches keyring
#   - ai.enabled=true, key missing → returns None, sweep can still proceed
#   - keyring exception → returns None, error type only is logged (no secrets)
# ---------------------------------------------------------------------------


class _RecordingStore:
    """Records every (service, user) probe so we can assert no probe was
    issued when ai.enabled=false."""

    def __init__(self, mapping=None):
        self._m = mapping or {}
        self.calls: list[tuple[str, str]] = []

    def get(self, service, user):
        self.calls.append((service, user))
        try:
            return self._m[(service, user)]
        except KeyError as e:
            raise RuntimeError(f"no key for {service}/{user}") from e


def test_narrator_disabled_does_not_touch_keyring(tmp_path):
    """If ai.enabled is false, build_narrator must short-circuit before any
    keyring probe. We confirm by recording calls on a fake store."""
    s = Settings(
        paths=PathsConfig(
            working_dir=tmp_path, cache_dir=tmp_path, audit_log_path=tmp_path / "a.log"
        ),
        ai=AIConfig(enabled=False, endpoint_allowlist=["https://placeholder.test"]),
    )  # type: ignore[call-arg]
    store = _RecordingStore({})
    assert _wiring.build_narrator(s, secret_store=store) is None
    assert store.calls == []


def test_narrator_key_missing_returns_none_safely(tmp_path):
    """ai.enabled=true and endpoint_allowlist non-empty, but the keyring has
    no key — wiring must catch the exception and return None. The sweep
    must still be runnable (no exception propagates to the caller)."""
    s = Settings(
        paths=PathsConfig(
            working_dir=tmp_path, cache_dir=tmp_path, audit_log_path=tmp_path / "a.log"
        ),
        ai=AIConfig(
            enabled=True,
            endpoint_allowlist=["https://placeholder.test/v1/chat/completions"],
            model="placeholder-model",
        ),
    )  # type: ignore[call-arg]
    # No mapping → keyring lookup raises → wiring returns None.
    assert _wiring.build_narrator(s, secret_store=_FakeStore({})) is None


def test_narrator_redaction_hmac_missing_returns_none_safely(tmp_path):
    """The AI key exists but the redaction HMAC key does not. build_narrator
    must still fail closed (returning None) — never construct a Redactor
    with a weak/empty key."""
    s = Settings(
        paths=PathsConfig(
            working_dir=tmp_path, cache_dir=tmp_path, audit_log_path=tmp_path / "a.log"
        ),
        ai=AIConfig(
            enabled=True,
            endpoint_allowlist=["https://placeholder.test/v1/chat/completions"],
            model="placeholder-model",
        ),
    )  # type: ignore[call-arg]
    # Only AI key present — redaction HMAC missing.
    store = _FakeStore({("tic-ai", "default"): b"placeholder-test-key"})
    assert _wiring.build_narrator(s, secret_store=store) is None


# ---------------------------------------------------------------------------
# verify_tls audit / log behaviour
#
# We capture log events by patching the module-level structlog binding
# instead of using structlog.testing.capture_logs(). The latter is sensitive
# to structlog's cache_logger_on_first_use=True setting and can miss events
# when full-suite runs cache loggers earlier in the session.
# ---------------------------------------------------------------------------


class _FakeAudit:
    """In-memory AuditLogger double. Records appended events for inspection."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def append(self, event_type, payload):
        self.events.append((event_type, dict(payload)))

    def verify_chain(self):
        return True


class _LogRecorder:
    """Drop-in replacement for the structlog bound logger used by _wiring.
    Only the methods we exercise (warning) are implemented."""

    def __init__(self) -> None:
        self.records: list[tuple[str, dict]] = []

    def warning(self, event, **kw):
        self.records.append((event, kw))

    # Other levels we don't expect in this path but stub for safety.
    def info(self, event, **kw):
        self.records.append((event, kw))

    def debug(self, event, **kw):
        self.records.append((event, kw))

    def error(self, event, **kw):
        self.records.append((event, kw))


def test_verify_tls_default_true_does_not_emit_warning_or_audit(tmp_path, cache, monkeypatch):
    rec = _LogRecorder()
    monkeypatch.setattr(_wiring, "_log", rec)
    s = _settings(
        tmp_path,
        {
            "abuseipdb": ProviderConfig(
                enabled=True,
                keyring_service="x",
                keyring_user="y",
            ),
        },
    )
    audit = _FakeAudit()
    out = _wiring.build_providers(
        s,
        secret_store=_FakeStore({("x", "y"): b"k"}),
        cache=cache,
        audit=audit,
    )
    assert len(out) == 1
    assert all(ev != "provider_tls_verify_disabled" for ev, _ in rec.records)
    assert all(e[0] != "provider_tls_verify_disabled" for e in audit.events)


def test_misp_verify_tls_false_emits_warning_and_audit_event(tmp_path, cache, monkeypatch):
    rec = _LogRecorder()
    monkeypatch.setattr(_wiring, "_log", rec)
    s = _settings(
        tmp_path,
        {
            "misp": ProviderConfig(
                enabled=True,
                keyring_service="m",
                keyring_user="y",
                endpoint="https://misp.internal",
                allowed_hosts=["misp.internal"],
                verify_tls=False,
            ),
        },
    )
    audit = _FakeAudit()
    _wiring.build_providers(
        s,
        secret_store=_FakeStore({("m", "y"): b"k"}),
        cache=cache,
        audit=audit,
    )

    # Warning log present
    warned = [r for r in rec.records if r[0] == "provider_tls_verify_disabled"]
    assert warned, f"expected warning, got {rec.records}"
    assert warned[0][1]["provider"] == "misp"

    # Tamper-evident audit event present with the right payload
    tls_events = [e for e in audit.events if e[0] == "provider_tls_verify_disabled"]
    assert len(tls_events) == 1
    payload = tls_events[0][1]
    assert payload["provider"] == "misp"
    assert payload["allowed_hosts"] == ["misp.internal"]

    # No secret material in event/log
    import json as _json

    blob = _json.dumps(
        {"logs": [(ev, kw) for ev, kw in rec.records], "audit": audit.events},
        default=str,
    )
    assert "Authorization" not in blob


def test_build_providers_without_audit_still_works(tmp_path, cache):
    """audit is optional — legacy callers pass nothing."""
    s = _settings(
        tmp_path,
        {
            "misp": ProviderConfig(
                enabled=True,
                keyring_service="m",
                keyring_user="y",
                endpoint="https://misp.internal",
                verify_tls=False,
            ),
        },
    )
    out = _wiring.build_providers(
        s,
        secret_store=_FakeStore({("m", "y"): b"k"}),
        cache=cache,
    )
    assert len(out) == 1 and out[0].name == "misp"
