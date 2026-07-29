# tests/integration/test_api_app_wiring.py
"""App-level wiring regression tests for the local FastAPI surface.

These exercise the *real* application object (``tic.api.main.app``) through
``TestClient`` and pin down the Part-1 wiring guarantees that previously
shipped unverified:

  1. ``SecurityHeadersMiddleware`` is registered and stamps hardened headers on
     every response — success, error, and the rate limiter's 429.
  2. ``RateLimitMiddleware`` is registered, throttles per client IP (not via a
     single global counter), and returns 429 + ``Retry-After``.
  3. The ops router (``/api/health``, ``/api/ready``, ``/api/metrics``) is the
     single source of truth for liveness/readiness; the old inline
     ``/api/health`` is gone.
  4. CORS only reflects configured origins.

No test here weakens the default 127.0.0.1 bind (that is a property of the
uvicorn invocation, not of the app object).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

from tic.api.rate_limit import RateLimitMiddleware, _PerClientLimiter
from tic.api.security_headers import SecurityHeadersMiddleware

_REQUIRED_SECURITY_HEADERS = (
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Cache-Control",
)


def _existing_paths_env() -> dict[str, str]:
    """Env pointing every TIC path at an existing tempdir (readiness = ok)."""
    work = tempfile.mkdtemp(prefix="tic-wire-work-")
    cache = tempfile.mkdtemp(prefix="tic-wire-cache-")
    audit = Path(tempfile.mkdtemp(prefix="tic-wire-audit-")) / "audit.log"
    return {
        "TIC_PATHS__WORKING_DIR": work,
        "TIC_PATHS__CACHE_DIR": cache,
        "TIC_PATHS__AUDIT_LOG_PATH": str(audit),
    }


def _client(monkeypatch, env: dict[str, str]) -> TestClient:
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    from tic.api.main import app

    return TestClient(app)


def _assert_security_headers(headers) -> None:
    for name in _REQUIRED_SECURITY_HEADERS:
        assert name in headers, f"missing security header: {name}"
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert "no-store" in headers["Cache-Control"]


def _csv_feed() -> bytes:
    return b"value,confidence,source,tags\n203.0.113.7,80,sample,doc;ipv4\n"


def _ndjson_log() -> bytes:
    line = json.dumps(
        {"@timestamp": "2025-01-12T08:14:02Z", "source": "fw", "dst_ip": "203.0.113.7"}
    )
    return (line + "\n").encode()


# --------------------------------------------------------------------------
# 1. Security headers on every response (success, error, sweep)
# --------------------------------------------------------------------------


def test_security_headers_on_health(monkeypatch):
    client = _client(monkeypatch, _existing_paths_env())
    r = client.get("/api/health")
    assert r.status_code == 200
    _assert_security_headers(r.headers)


def test_security_headers_on_error_response(monkeypatch):
    client = _client(monkeypatch, _existing_paths_env())
    r = client.get("/api/this-route-does-not-exist")
    assert r.status_code == 404
    _assert_security_headers(r.headers)


def test_security_headers_on_successful_sweep(monkeypatch):
    client = _client(monkeypatch, _existing_paths_env())
    r = client.post(
        "/api/sweep",
        files={
            "feed_file": ("iocs.csv", _csv_feed(), "text/csv"),
            "log_file": ("events.ndjson", _ndjson_log(), "application/x-ndjson"),
        },
        data={
            "feed_format": "csv",
            "output_mode": "analyst",
            "fail_on": "high",
            "with_ai": "false",
        },
    )
    assert r.status_code == 200, r.text
    _assert_security_headers(r.headers)


# --------------------------------------------------------------------------
# 2. Rate limiting: 429 + Retry-After, keyed per client IP
# --------------------------------------------------------------------------


def _mini_app(*, sweep_limit: int = 10, read_limit: int = 2) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        RateLimitMiddleware,
        sweep_limit=sweep_limit,
        read_limit=read_limit,
        window_seconds=60.0,
    )

    @app.get("/ping")
    def ping() -> dict[str, str]:
        return {"pong": "ok"}

    return app


def test_rate_limit_returns_429_with_retry_after():
    client = TestClient(_mini_app(read_limit=2))
    assert client.get("/ping").status_code == 200
    assert client.get("/ping").status_code == 200
    r = client.get("/ping")
    assert r.status_code == 429
    assert r.headers["Retry-After"] == "60"
    assert r.headers["X-RateLimit-Limit"] == "2"
    assert "detail" in r.json()


def test_rate_limit_keyed_per_client_ip():
    # Exercise the per-client core directly: client A exhausting its budget
    # must not affect client B. A single global counter would fail this.
    limiter = _PerClientLimiter(limit=1, window_seconds=60.0)
    now = 1_000.0
    assert limiter.allow("10.0.0.1", now) is True
    assert limiter.allow("10.0.0.1", now) is False
    assert limiter.allow("10.0.0.2", now) is True


def test_rate_limit_key_is_peer_not_forwarded_for():
    # X-Forwarded-For is attacker-controlled in a local-first deployment and
    # must be ignored in favour of the transport peer address.
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": [(b"x-forwarded-for", b"9.9.9.9")],
        "client": ("10.1.2.3", 55555),
    }
    request = Request(scope)
    assert RateLimitMiddleware._client_key(request) == "10.1.2.3"


# --------------------------------------------------------------------------
# 3. Ops router is the single source for liveness / readiness / metrics
# --------------------------------------------------------------------------


def test_health_served_by_router_not_inline(monkeypatch):
    client = _client(monkeypatch, _existing_paths_env())
    body = client.get("/api/health").json()
    # Router liveness exposes uptime_seconds; the removed inline handler
    # exposed a static "version" field instead — good discriminator.
    assert "uptime_seconds" in body
    assert "version" not in body


def test_ready_ok_returns_200(monkeypatch):
    client = _client(monkeypatch, _existing_paths_env())
    r = client.get("/api/ready")
    assert r.status_code == 200
    assert r.json()["status"] == "ready"


def test_ready_degraded_returns_503(monkeypatch):
    env = _existing_paths_env()
    # Absolute (passes validation) but non-existent -> readiness degrades.
    env["TIC_PATHS__CACHE_DIR"] = str(
        Path(tempfile.gettempdir()) / "tic-wire-absent-cache-zzz"
    )
    client = _client(monkeypatch, env)
    r = client.get("/api/ready")
    assert r.status_code == 503
    assert r.json()["status"] == "degraded"


def test_metrics_returns_prometheus_text(monkeypatch):
    client = _client(monkeypatch, _existing_paths_env())
    r = client.get("/api/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")


# --------------------------------------------------------------------------
# 4. CORS only reflects configured origins
# --------------------------------------------------------------------------


def test_cors_allows_configured_origin(monkeypatch):
    client = _client(monkeypatch, _existing_paths_env())
    r = client.get("/api/health", headers={"Origin": "http://127.0.0.1:3000"})
    assert r.headers.get("access-control-allow-origin") == "http://127.0.0.1:3000"


def test_cors_rejects_unconfigured_origin(monkeypatch):
    client = _client(monkeypatch, _existing_paths_env())
    r = client.get("/api/health", headers={"Origin": "http://evil.example.com"})
    assert r.headers.get("access-control-allow-origin") != "http://evil.example.com"


# --------------------------------------------------------------------------
# Wiring introspection (the three middleware/router registrations exist)
# --------------------------------------------------------------------------


def test_app_registers_part1_middleware_and_routes(monkeypatch):
    client = _client(monkeypatch, _existing_paths_env())
    app = client.app
    registered = {m.cls for m in app.user_middleware}
    assert SecurityHeadersMiddleware in registered
    assert RateLimitMiddleware in registered
    paths = {getattr(route, "path", None) for route in app.routes}
    assert {"/api/health", "/api/ready", "/api/metrics"} <= paths
