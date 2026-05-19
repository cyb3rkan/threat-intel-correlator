# tests/unit/test_openai_compat_provider.py
"""Unit tests for the OpenAI-compatible AI provider adapter.

Phase A scope: only constructor-level safety checks. No real HTTP calls, no
real API keys. The adapter must refuse to be built against an endpoint that
is not in the configured allowlist — this is the second gate (after the
wiring-level enabled/endpoint_allowlist short-circuit) that keeps a
misconfigured deployment from talking to an arbitrary host.
"""
from __future__ import annotations

import pytest

from tic.adapters.ai_providers.openai_compat import OpenAICompatProvider
from tic.infra.config import AIConfig, HttpClientConfig


class _DummyHttp:
    """Stand-in for SafeHttpClient. The constructor under test does not
    invoke any network methods, so an empty placeholder is sufficient."""

    async def post(self, *_a, **_kw):  # pragma: no cover — never called
        raise AssertionError("network must not be touched in Phase A tests")


def _ai_cfg(allowlist: list[str]) -> AIConfig:
    return AIConfig(
        enabled=True,
        endpoint_allowlist=allowlist,
        model="placeholder-model",
        max_output_tokens=128,
        max_input_chars=2048,
        request_timeout_seconds=10.0,
    )


def test_endpoint_not_in_allowlist_raises_value_error() -> None:
    """If the caller hands the adapter an endpoint that is not on the
    AI allowlist, construction must fail — never silently fall through."""
    cfg = _ai_cfg(["https://allowed.test/v1/chat/completions"])
    with pytest.raises(ValueError, match="not in allowlist"):
        OpenAICompatProvider(
            http=_DummyHttp(),
            cfg=cfg,
            api_key=b"placeholder-not-a-real-key",
            endpoint="https://attacker.example/v1/chat/completions",
        )


def test_empty_allowlist_rejects_any_endpoint() -> None:
    """An empty allowlist must reject every endpoint, even an empty string
    — this guards against a config bug where the allowlist failed to load."""
    cfg = _ai_cfg([])
    with pytest.raises(ValueError):
        OpenAICompatProvider(
            http=_DummyHttp(),
            cfg=cfg,
            api_key=b"placeholder-not-a-real-key",
            endpoint="https://allowed.test/v1/chat/completions",
        )


def test_endpoint_in_allowlist_constructs_successfully() -> None:
    """Positive control: when the endpoint matches the allowlist, the
    adapter constructs without raising. We do NOT invoke .narrate() — that
    would require a working HTTP layer and a real model."""
    endpoint = "https://allowed.test/v1/chat/completions"
    cfg = _ai_cfg([endpoint])
    provider = OpenAICompatProvider(
        http=_DummyHttp(),
        cfg=cfg,
        api_key=b"placeholder-not-a-real-key",
        endpoint=endpoint,
    )
    assert provider.name == "openai-compat"


def test_ai_config_rejects_non_https_endpoint() -> None:
    """The AIConfig validator must reject http:// endpoints at load time, so
    plaintext exfiltration is impossible even by misconfiguration."""
    with pytest.raises(ValueError, match="https"):
        AIConfig(
            enabled=True,
            endpoint_allowlist=["http://insecure.test/v1/chat/completions"],
            model="m",
        )


def test_http_client_config_does_not_lower_tls_for_ai() -> None:
    """Sanity: the default HttpClientConfig keeps verify_tls=True. The AI
    adapter never overrides this, so AI traffic always validates TLS even
    if a provider opts out (MISP local-lab pattern)."""
    cfg = HttpClientConfig()
    assert cfg.verify_tls is True


# ---------------------------------------------------------------------------
# Phase B: explicit per-request timeout via asyncio.timeout.
#
# We do not invoke a real HTTP layer. The fake client just sleeps longer
# than the configured timeout; the adapter must return None (fail-safe)
# rather than crash the sweep.
# ---------------------------------------------------------------------------


import asyncio  # noqa: E402

import pytest  # noqa: E402

from tic.application.redaction import Redactor  # noqa: E402
from tic.domain.finding import Finding, Severity  # noqa: E402
from tic.domain.ioc import IOC, IOCType  # noqa: E402
from datetime import datetime, timezone  # noqa: E402


class _SlowHttp:
    """Sleeps past the configured AI request timeout. The asyncio.timeout
    wrapper in the adapter must cancel us and surface a None result."""

    def __init__(self, sleep_seconds: float = 1.0) -> None:
        self._sleep = sleep_seconds

    async def post(self, *_a, **_kw):
        await asyncio.sleep(self._sleep)
        raise AssertionError("unreachable — adapter should have timed out")


def _redacted_finding():
    f = Finding(
        finding_id="00000000-0000-4000-8000-000000000000",
        ioc=IOC(value="evil.example.com", ioc_type=IOCType.DOMAIN, source="feed"),
        matches=[],
        enrichments=[],
        score=50,
        severity=Severity.MEDIUM,
        profile_hash="a" * 64,
        correlation_id="cid",
        created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )
    return Redactor(b"0" * 32).redact(f)


@pytest.mark.asyncio
async def test_request_timeout_returns_none() -> None:
    """If the HTTP call exceeds `cfg.request_timeout_seconds`, the adapter
    must return None and never propagate the asyncio.TimeoutError."""
    endpoint = "https://allowed.test/v1/chat/completions"
    cfg = AIConfig(
        enabled=True,
        endpoint_allowlist=[endpoint],
        model="placeholder-model",
        max_output_tokens=128,
        max_input_chars=2048,
        request_timeout_seconds=1.0,  # adapter floor
    )
    provider = OpenAICompatProvider(
        http=_SlowHttp(sleep_seconds=5.0),
        cfg=cfg,
        api_key=b"placeholder-not-a-real-key",
        endpoint=endpoint,
    )
    result = await provider.narrate(_redacted_finding())
    assert result is None


class _RaisingHttp:
    async def post(self, *_a, **_kw):
        raise RuntimeError("simulated transport failure")


@pytest.mark.asyncio
async def test_transport_failure_returns_none() -> None:
    """Any non-timeout transport error from SafeHttpClient must also
    surface as None — the sweep keeps going without a narrative."""
    endpoint = "https://allowed.test/v1/chat/completions"
    cfg = AIConfig(
        enabled=True,
        endpoint_allowlist=[endpoint],
        model="placeholder-model",
        request_timeout_seconds=10.0,
    )
    provider = OpenAICompatProvider(
        http=_RaisingHttp(),
        cfg=cfg,
        api_key=b"placeholder-not-a-real-key",
        endpoint=endpoint,
    )
    result = await provider.narrate(_redacted_finding())
    assert result is None
