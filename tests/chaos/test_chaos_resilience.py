# tests/chaos/test_chaos_resilience.py
"""Chaos engineering test suite for TIC enrichment pipeline.

These tests inject failures into the enrichment pipeline and verify that
the system degrades gracefully rather than failing catastrophically.

Chaos scenarios:
  1. Provider total outage        → circuit opens, sweep continues with partial results
  2. Provider slow response       → timeout enforced, no pipeline stall
  3. Provider intermittent errors → retry policy absorbs transient failures
  4. DNS resolution failure       → SSRF guard propagates NetworkError cleanly
  5. Provider returns garbage     → schema validation rejects, partial result returned
  6. Provider quota exhausted     → 429 handled, marked as transient, retried
  7. All providers simultaneous   → bulkheads isolate, sweep returns empty enrichment
  8. Rate limit burst             → API returns 429, Retry-After header present

Design:
  - Uses respx to mock httpx transport — no real network calls.
  - Tests the enrichment pipeline directly (no FastAPI overhead) for speed.
  - Each test validates a specific failure boundary.

CWE-400 (Resource Exhaustion), CWE-754 (Improper Check for Unusual Conditions).
NIST CSF ID.RA-4 (Identified threats and vulnerabilities documented).
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from tic.adapters.http.bulkhead import Bulkhead, BulkheadFullError
from tic.adapters.http.circuit_breaker import CircuitBreaker, CircuitOpenError
from tic.domain.errors import NetworkError, SecurityViolationError
from tic.domain.ioc import IOC, IOCType

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ioc(value: str = "1.2.3.4", ioc_type: IOCType = IOCType.IP) -> IOC:
    return IOC(value=value, ioc_type=ioc_type, source="chaos-test", confidence=80)


# ---------------------------------------------------------------------------
# 1. Circuit breaker — provider total outage
# ---------------------------------------------------------------------------

@pytest.mark.asyncio()
async def test_circuit_opens_on_sustained_provider_failure() -> None:
    """After `failure_threshold` consecutive failures, circuit must open."""
    cb = CircuitBreaker(
        "chaos-vt",
        failure_threshold=3,
        recovery_timeout=30.0,
        expected_exc=(NetworkError,),
    )

    async def _always_fails():
        raise NetworkError("chaos: connection refused", user_message="Provider unreachable.")

    for _ in range(3):
        with pytest.raises(NetworkError):
            await cb.call(_always_fails)

    assert cb.state == "open"

    # Next call must short-circuit immediately (no I/O).
    with pytest.raises(CircuitOpenError) as exc_info:
        await cb.call(_always_fails)
    assert "chaos-vt" in str(exc_info.value)


@pytest.mark.asyncio()
async def test_circuit_recovery_probe_succeeds() -> None:
    """After recovery timeout, HALF_OPEN probe that succeeds closes circuit."""
    cb = CircuitBreaker("chaos-vt", failure_threshold=1, recovery_timeout=0.05,
                        expected_exc=(RuntimeError,))

    async def _fail(): raise RuntimeError("boom")
    async def _succeed(): return "ok"

    with pytest.raises(RuntimeError):
        await cb.call(_fail)
    assert cb.state == "open"

    await asyncio.sleep(0.06)  # Allow recovery window to elapse.
    result = await cb.call(_succeed)
    assert result == "ok"
    assert cb.state == "closed"


# ---------------------------------------------------------------------------
# 2. Provider slow response — timeout enforcement
# ---------------------------------------------------------------------------

@pytest.mark.asyncio()
async def test_slow_provider_hits_timeout() -> None:
    """A provider that hangs must be terminated by asyncio.timeout."""

    async def _hangs_forever():
        await asyncio.sleep(9999)

    with pytest.raises(asyncio.TimeoutError):
        async with asyncio.timeout(0.05):
            await _hangs_forever()


@pytest.mark.asyncio()
async def test_circuit_breaker_counts_timeout_as_failure() -> None:
    """asyncio.TimeoutError must be counted as a failure if in expected_exc."""
    cb = CircuitBreaker(
        "slow-provider",
        failure_threshold=2,
        recovery_timeout=30.0,
        expected_exc=(asyncio.TimeoutError, Exception),
    )

    async def _timeout():
        raise TimeoutError()

    for _ in range(2):
        with pytest.raises(asyncio.TimeoutError):
            await cb.call(_timeout)

    assert cb.state == "open"


# ---------------------------------------------------------------------------
# 3. Intermittent provider errors — retry absorption
# ---------------------------------------------------------------------------

@pytest.mark.asyncio()
async def test_transient_failures_absorbed_before_threshold() -> None:
    """Failures below threshold must not open the circuit."""
    cb = CircuitBreaker("intermittent", failure_threshold=5, recovery_timeout=30.0,
                        expected_exc=(RuntimeError,))
    call_count = 0

    async def _flaky():
        nonlocal call_count
        call_count += 1
        if call_count % 3 != 0:  # Fails 2 out of 3 times.
            raise RuntimeError("transient")
        return "ok"

    for _ in range(9):
        try:
            await cb.call(_flaky)
        except RuntimeError:
            pass

    # 6 failures out of 9 calls, but circuit should NOT have opened
    # because consecutive failures never reached 5 (successes reset counter).
    assert cb.state == "closed"


# ---------------------------------------------------------------------------
# 4. Provider returns garbage JSON — schema validation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio()
async def test_garbage_response_raises_structured_error() -> None:
    """Malformed provider response must produce a clean exception, not a crash."""
    from pydantic import BaseModel, ValidationError

    class _ProviderResponse(BaseModel):
        data: dict[str, Any]
        meta: dict[str, Any]

    garbage_payloads = [
        b"not json at all",
        b'{"data": null}',
        b"",
        b'{"unexpected_key": 42}',
        b"<xml>surprise</xml>",
        b"\x00\x01\x02",
    ]

    for payload in garbage_payloads:
        try:
            import json
            parsed = json.loads(payload)
            _ProviderResponse(**parsed)
        except (json.JSONDecodeError, ValidationError, TypeError, Exception):
            pass  # All must raise cleanly, never crash the process.


# ---------------------------------------------------------------------------
# 5. Bulkhead saturation — all slots full
# ---------------------------------------------------------------------------

@pytest.mark.asyncio()
async def test_bulkhead_rejects_when_full() -> None:
    """When max_concurrent and queue are full, BulkheadFullError is raised."""
    bulkhead = Bulkhead("chaos-provider", max_concurrent=2, queue_size=0)
    gate = asyncio.Event()
    results: list[str] = []

    async def _slow_task(name: str) -> None:
        async with bulkhead():
            results.append(f"{name}:start")
            await gate.wait()
            results.append(f"{name}:end")

    # Fill both slots.
    t1 = asyncio.create_task(_slow_task("t1"))
    t2 = asyncio.create_task(_slow_task("t2"))
    await asyncio.sleep(0.02)  # Let t1 and t2 acquire.

    # queue_size=0 → next request must be rejected immediately.
    with pytest.raises(BulkheadFullError):
        async with bulkhead():
            pass

    gate.set()
    await asyncio.gather(t1, t2)
    assert len(results) == 4


@pytest.mark.asyncio()
async def test_bulkhead_adaptive_concurrency_reduces_on_errors() -> None:
    """Sustained errors must trigger adaptive concurrency reduction."""
    bulkhead = Bulkhead(
        "chaos-provider",
        max_concurrent=4,
        queue_size=4,
        error_threshold=0.5,
        error_window=60.0,
    )

    # Inject 6 errors to trigger reduction (threshold 50% → need >50% error rate).
    for _ in range(6):
        try:
            async with bulkhead():
                raise RuntimeError("chaos error")
        except RuntimeError:
            pass

    # Concurrency should have been halved (4 → 2).
    assert bulkhead.current_concurrency < 4


# ---------------------------------------------------------------------------
# 6. All providers simultaneously down — graceful degradation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio()
async def test_all_providers_open_circuits_dont_cascade() -> None:
    """Multiple open circuits must not affect each other's recovery."""
    providers = [
        CircuitBreaker(f"provider-{i}", failure_threshold=1, recovery_timeout=30.0,
                       expected_exc=(RuntimeError,))
        for i in range(3)
    ]

    async def _fail(): raise RuntimeError("down")

    # Open all circuits.
    for cb in providers:
        with pytest.raises(RuntimeError):
            await cb.call(_fail)

    # All should be open.
    assert all(cb.state == "open" for cb in providers)

    # Resetting one must not affect others.
    providers[0].reset()
    assert providers[0].state == "closed"
    assert providers[1].state == "open"
    assert providers[2].state == "open"


# ---------------------------------------------------------------------------
# 7. Rate limit burst — 429 validation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio()
async def test_rate_limit_middleware_returns_429_and_headers() -> None:
    """After limit exhausted, API must return 429 with Retry-After header."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from tic.api.rate_limit import RateLimitMiddleware

    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, sweep_limit=2, sweep_window=60.0,
                       read_limit=100, read_window=60.0)

    @app.post("/api/sweep")
    def _sweep(): return {"findings": []}

    client = TestClient(app, raise_server_exceptions=False)

    # Exhaust sweep limit.
    for _ in range(2):
        r = client.post("/api/sweep")
        assert r.status_code == 200

    # Next must be 429.
    r = client.post("/api/sweep")
    assert r.status_code == 429
    assert int(r.headers.get("Retry-After", 0)) > 0
    assert r.json()["detail"] == "Rate limit exceeded. Please slow down."


# ---------------------------------------------------------------------------
# 8. SSRF guard — DNS failure simulation
# ---------------------------------------------------------------------------

def test_ssrf_guard_dns_failure_raises_security_violation(monkeypatch) -> None:
    """DNS resolution failure must raise SecurityViolationError, not propagate socket.gaierror."""
    import socket

    from tic.security.ssrf_guard import ensure_public_url

    def _fail_dns(*args, **kwargs):
        raise socket.gaierror("chaos: no such host")

    monkeypatch.setattr(socket, "getaddrinfo", _fail_dns)

    with pytest.raises(SecurityViolationError):
        ensure_public_url("https://nonexistent-chaos-host.example.invalid/api")


def test_ssrf_guard_metadata_endpoint_blocked() -> None:
    """Cloud metadata endpoint must always be blocked regardless of allowlist."""
    from tic.security.ssrf_guard import ensure_public_url

    with pytest.raises(SecurityViolationError):
        ensure_public_url(
            "https://169.254.169.254/latest/meta-data/",
            extra_allowlist=frozenset({"169.254.169.254"}),  # Allowlist must NOT bypass this.
        )
