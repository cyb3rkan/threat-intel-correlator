# tests/unit/test_otel_decorators.py
"""Finding E-1: exercise the OTel span decorators (were 0% covered).

These decorators run in production on every enrichment / provider call. The
tests use a recording spy tracer so we can assert three things that matter:

  1. The wrapped function's result is returned unchanged (success path).
  2. Exceptions propagate and are recorded, not swallowed (error path).
  3. The privacy invariant: the raw IOC *value* is NEVER set as a span
     attribute — only the low-cardinality ioc.type / provider / outcome.
"""
from __future__ import annotations

import contextlib
from typing import Any

import pytest

from tic.infra.otel import decorators


class _SpySpan:
    def __init__(self) -> None:
        self.attributes: dict[str, Any] = {}
        self.exceptions: list[BaseException] = []

    def __enter__(self) -> _SpySpan:
        return self

    def __exit__(self, *_: Any) -> None:
        return None

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def record_exception(self, exc: BaseException) -> None:
        self.exceptions.append(exc)


class _SpyTracer:
    def __init__(self) -> None:
        self.spans: list[_SpySpan] = []
        self.names: list[str] = []

    def start_as_current_span(self, name: str, **_kwargs: Any) -> _SpySpan:
        self.names.append(name)
        span = _SpySpan()
        self.spans.append(span)
        return span


class _IOC:
    ioc_type = "ipv4"
    value = "203.0.113.7"  # must never appear in span attributes


class _Result:
    from_cache = True
    status_code = 200


@pytest.fixture()
def spy(monkeypatch: pytest.MonkeyPatch) -> _SpyTracer:
    tracer = _SpyTracer()
    # trace_enrichment / trace_provider_call use the module-level _tracer;
    # trace_cache calls get_tracer() at runtime. Patch both entry points.
    monkeypatch.setattr(decorators, "_tracer", tracer)
    monkeypatch.setattr(decorators, "get_tracer", lambda _name: tracer)
    return tracer


async def test_trace_enrichment_success_returns_result_and_hides_ioc_value(
    spy: _SpyTracer,
) -> None:
    @decorators.trace_enrichment("virustotal")
    async def enrich(self: Any, ioc: Any) -> Any:
        return _Result()

    result = await enrich(object(), _IOC())

    assert isinstance(result, _Result)
    span = spy.spans[0]
    assert span.attributes["provider"] == "virustotal"
    assert span.attributes["ioc.type"] == "ipv4"
    assert span.attributes["outcome"] == "ok"
    assert span.attributes["from_cache"] is True
    # Privacy invariant: the raw indicator value is never exported.
    assert _IOC.value not in span.attributes.values()


async def test_trace_enrichment_error_path_records_and_reraises(spy: _SpyTracer) -> None:
    @decorators.trace_enrichment("abuseipdb")
    async def enrich(self: Any, ioc: Any) -> Any:
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        await enrich(object(), _IOC())

    span = spy.spans[0]
    assert span.attributes["outcome"] == "error"
    assert span.attributes["error.type"] == "ValueError"
    assert span.exceptions and isinstance(span.exceptions[0], ValueError)


async def test_trace_provider_call_success_records_status(spy: _SpyTracer) -> None:
    @decorators.trace_provider_call("virustotal", "lookup_ip")
    async def call(*_a: Any, **_k: Any) -> Any:
        return _Result()

    result = await call()

    assert isinstance(result, _Result)
    span = spy.spans[0]
    assert spy.names[0] == "provider/virustotal/lookup_ip"
    assert span.attributes["operation"] == "lookup_ip"
    assert span.attributes["http.status_code"] == 200


async def test_trace_provider_call_error_path_reraises(spy: _SpyTracer) -> None:
    @decorators.trace_provider_call("misp", "search")
    async def call(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("net down")

    with pytest.raises(RuntimeError, match="net down"):
        await call()

    span = spy.spans[0]
    assert span.attributes["error.type"] == "RuntimeError"


def test_trace_cache_records_hit_and_miss(spy: _SpyTracer) -> None:
    @decorators.trace_cache("get")
    def cache_get(key: str) -> Any:
        return "value" if key == "present" else None

    assert cache_get("present") == "value"
    assert spy.spans[-1].attributes["cache.hit"] is True

    assert cache_get("absent") is None
    assert spy.spans[-1].attributes["cache.hit"] is False


def test_noop_span_is_a_safe_context_manager() -> None:
    """The real no-op path (SDK absent) must be usable as a with/as block."""
    from tic.infra.otel.setup import get_tracer

    tracer = get_tracer("tic.test")
    with tracer.start_as_current_span("x") as span, contextlib.suppress(Exception):
        span.set_attribute("k", "v")
        span.record_exception(RuntimeError("ignored"))
