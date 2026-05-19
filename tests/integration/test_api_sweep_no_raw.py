# tests/integration/test_api_sweep_no_raw.py
"""Regression: /api/sweep response must never include raw provider/log data.

Rules:
- 'truncated_raw' must not appear anywhere in the response body.
- 'raw' substrings tied to provider payloads must not appear.
- File paths from the working dir must not appear.
- AI requested but unavailable must surface as ai_attempted/ai_active flags
  (not raise) and never echo the AI key.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient


def _make_env() -> dict[str, str]:
    work = tempfile.mkdtemp(prefix="tic-test-work-")
    cache = tempfile.mkdtemp(prefix="tic-test-cache-")
    audit = Path(tempfile.mkdtemp(prefix="tic-test-audit-")) / "audit.log"
    return {
        "TIC_PATHS__WORKING_DIR": work,
        "TIC_PATHS__CACHE_DIR": cache,
        "TIC_PATHS__AUDIT_LOG_PATH": str(audit),
    }


def _build_csv() -> bytes:
    return b"value,confidence,source,tags\n198.51.100.23,80,sample,doc;ipv4\n"


def _build_ndjson() -> bytes:
    line = json.dumps(
        {"@timestamp": "2025-01-12T08:14:02Z", "source": "fw", "dst_ip": "198.51.100.23"}
    )
    return (line + "\n").encode()


def test_sweep_response_omits_truncated_raw(monkeypatch):
    for k, v in _make_env().items():
        monkeypatch.setenv(k, v)
    # Hash mode is not exercised here — no HMAC key needed.
    from tic.api.main import app
    c = TestClient(app)
    r = c.post(
        "/api/sweep",
        files={
            "feed_file": ("iocs.csv", _build_csv(), "text/csv"),
            "log_file": ("events.ndjson", _build_ndjson(), "application/x-ndjson"),
        },
        data={
            "feed_format": "csv",
            "output_mode": "analyst",
            "fail_on": "high",
            "with_ai": "false",
        },
    )
    assert r.status_code == 200, r.text
    body = r.text
    # Hard ban: any raw provider snapshots must not surface here.
    assert "truncated_raw" not in body
    assert "Traceback" not in body
    # Path leak (working dir) must not be echoed.
    assert os.environ["TIC_PATHS__WORKING_DIR"] not in body
    parsed = r.json()
    # PublicEnrichment shape only — no 'truncated_raw' key in any enrichment.
    for f in parsed["findings"]:
        for e in f.get("enrichments", []):
            assert "truncated_raw" not in e


def test_sweep_with_ai_unavailable_returns_safe_flags(monkeypatch):
    for k, v in _make_env().items():
        monkeypatch.setenv(k, v)
    # ai.enabled stays false (default) → adapter never tries to load the key.
    # The API must still succeed and report ai_attempted=false / ai_active=false.
    from tic.api.main import app
    c = TestClient(app)
    r = c.post(
        "/api/sweep",
        files={
            "feed_file": ("iocs.csv", _build_csv(), "text/csv"),
            "log_file": ("events.ndjson", _build_ndjson(), "application/x-ndjson"),
        },
        data={
            "feed_format": "csv",
            "output_mode": "analyst",
            "fail_on": "high",
            "with_ai": "true",  # request AI even though disabled
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ai_attempted"] is False
    assert body["ai_active"] is False
    # Key never present in the response
    assert "Bearer" not in r.text
    assert "Authorization" not in r.text


def test_sweep_hash_mode_without_redaction_key_returns_friendly_error(monkeypatch):
    """R5 regression at the API layer: hash mode without HMAC must fail
    with a 4xx and a friendly message — never leak a zero-key fallback.

    Test isolation: the developer's real OS keyring may already contain a
    tic-redaction-hmac entry. We force a "no key" state by patching the
    adapter-level helper, so CI behaves the same as a freshly provisioned
    workstation. We patch the symbol *at the import site* used by the
    adapter to avoid any chance of the live keyring being consulted.
    """
    for k, v in _make_env().items():
        monkeypatch.setenv(k, v)
    # Force "no key" regardless of host keyring state.
    monkeypatch.setattr(
        "tic.ui.adapter.try_load_redaction_hmac",
        lambda settings, secret_store: None,
    )
    from tic.api.main import app
    c = TestClient(app)
    r = c.post(
        "/api/sweep",
        files={
            "feed_file": ("iocs.csv", _build_csv(), "text/csv"),
            "log_file": ("events.ndjson", _build_ndjson(), "application/x-ndjson"),
        },
        data={
            "feed_format": "csv",
            "output_mode": "hash",
            "fail_on": "high",
            "with_ai": "false",
        },
    )
    # adapter raises ConfigError → run_sweep wraps as RuntimeError → API 400.
    assert r.status_code == 400, r.text
    body = r.json()
    assert "Hash output mode requires" in body["detail"]
    # No traceback in detail.
    assert "Traceback" not in r.text
    # No "hmac:" pseudonym leaked from a zero-key fallback.
    assert "hmac:" not in r.text


def test_api_responses_carry_correlation_id_header(monkeypatch):
    """Every response, success or error, must carry X-TIC-Correlation-Id
    so analysts can correlate frontend errors with backend logs.

    The header is a UUIDv4 — non-secret. It must NOT appear in the body
    (the public response contract has no correlation_id field).
    """
    for k, v in _make_env().items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(
        "tic.ui.adapter.try_load_redaction_hmac",
        lambda settings, secret_store: None,
    )
    from tic.api.main import app
    c = TestClient(app)

    # Success path
    r = c.get("/api/health")
    assert r.status_code == 200
    cid = r.headers.get("x-tic-correlation-id")
    assert cid and len(cid) >= 32  # UUID-like
    assert "correlation_id" not in r.text  # body shape unchanged

    # Error path (hash mode without key → 400)
    r2 = c.post(
        "/api/sweep",
        files={
            "feed_file": ("iocs.csv", _build_csv(), "text/csv"),
            "log_file": ("events.ndjson", _build_ndjson(), "application/x-ndjson"),
        },
        data={
            "feed_format": "csv",
            "output_mode": "hash",
            "fail_on": "high",
            "with_ai": "false",
        },
    )
    assert r2.status_code == 400
    assert r2.headers.get("x-tic-correlation-id")
    assert r2.headers["x-tic-correlation-id"] != cid  # fresh per-request


def test_with_ai_true_when_ai_disabled_no_http_client_opened(monkeypatch):
    """Phase A reinforcement of the existing contract: when ai.enabled=false
    and the operator passes with_ai=true, the wiring must NEVER attempt to
    build an OpenAICompatProvider or open an httpx client for AI. We patch
    the AI provider class to flag any construction attempt and assert it
    was not invoked.

    This complements `test_with_ai_true_when_ai_disabled_is_safe_and_silent`
    by checking the *mechanism*, not just the response shape."""
    for k, v in _make_env().items():
        monkeypatch.setenv(k, v)

    constructed: list[bool] = []

    class _Sentinel:
        def __init__(self, *_a, **_kw):
            constructed.append(True)
            raise AssertionError("AI provider must not be constructed when ai.enabled=false")

    monkeypatch.setattr(
        "tic.adapters.ai_providers.openai_compat.OpenAICompatProvider",
        _Sentinel,
    )

    from tic.api.main import app
    c = TestClient(app)
    r = c.post(
        "/api/sweep",
        files={
            "feed_file": ("iocs.csv", _build_csv(), "text/csv"),
            "log_file": ("events.ndjson", _build_ndjson(), "application/x-ndjson"),
        },
        data={
            "feed_format": "csv",
            "output_mode": "analyst",
            "fail_on": "high",
            "with_ai": "true",
        },
    )
    assert r.status_code == 200, r.text
    assert constructed == [], "AI provider was constructed despite ai.enabled=false"
    body = r.json()
    assert body["ai_attempted"] is False
    assert body["ai_active"] is False


def test_with_ai_true_when_ai_disabled_is_safe_and_silent(monkeypatch):
    """Contract test ahead of AI narration: when `ai.enabled=false`,
    requesting `with_ai=true` must NOT raise, must NOT mention the AI
    key, must NOT leak raw data, and must return ai_attempted=False,
    ai_active=False. This freezes the contract that the AI integration
    must preserve when it lands."""
    for k, v in _make_env().items():
        monkeypatch.setenv(k, v)
    from tic.api.main import app
    c = TestClient(app)
    r = c.post(
        "/api/sweep",
        files={
            "feed_file": ("iocs.csv", _build_csv(), "text/csv"),
            "log_file": ("events.ndjson", _build_ndjson(), "application/x-ndjson"),
        },
        data={
            "feed_format": "csv",
            "output_mode": "analyst",
            "fail_on": "high",
            "with_ai": "true",  # operator asks for AI, but AI is disabled
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ai_attempted"] is False
    assert body["ai_active"] is False
    # Findings still come back with no AI narrative
    for f in body["findings"]:
        assert f["ai_narrative"] is None
    blob = r.text
    # No secret leakage
    assert "Authorization" not in blob
    assert "Bearer" not in blob
    assert "ai_key" not in blob.lower()
    # No raw boundary fields leaked
    assert "truncated_raw" not in blob
    assert "Traceback" not in blob
