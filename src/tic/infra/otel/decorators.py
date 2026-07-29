# src/tic/infra/otel/decorators.py
"""OTel span decorators for enrichment pipeline instrumentation.

Usage:
    from tic.infra.otel.decorators import trace_enrichment, trace_provider_call

    @trace_enrichment("virustotal")
    async def enrich(self, ioc: IOC) -> EnrichmentResult:
        ...

    @trace_provider_call("virustotal", "lookup_ip")
    async def _lookup_ip(self, ioc: IOC) -> dict:
        ...

Privacy contract:
  IOC values are NEVER added as span attributes. Only IOC type (enum string),
  provider name, and outcome (hit/miss/error/circuit_open) are exported.
  This ensures trace data cannot leak sensitive indicator values to external
  telemetry backends.
"""
from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from tic.infra.otel.setup import get_tracer

_tracer = get_tracer("tic.enrichment")


def trace_enrichment(provider_name: str) -> Callable[..., Any]:
    """Decorate an async enrich() method with a root enrichment span."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        async def wrapper(self: Any, ioc: Any) -> Any:
            span_name = f"enrich/{provider_name}"
            with _tracer.start_as_current_span(span_name) as span:
                # Low-cardinality safe attributes — NO ioc.value.
                span.set_attribute("provider", provider_name)
                span.set_attribute("ioc.type", str(getattr(ioc, "ioc_type", "unknown")))
                try:
                    result = await fn(self, ioc)
                    span.set_attribute("outcome", "ok")
                    span.set_attribute("from_cache", getattr(result, "from_cache", False))
                    return result
                except Exception as exc:
                    span.record_exception(exc)
                    span.set_attribute("outcome", "error")
                    span.set_attribute("error.type", type(exc).__name__)
                    raise

        return wrapper

    return decorator


def trace_provider_call(provider_name: str, operation: str) -> Callable[..., Any]:
    """Decorate a low-level provider HTTP call with a child span."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            span_name = f"provider/{provider_name}/{operation}"
            with _tracer.start_as_current_span(span_name) as span:
                span.set_attribute("provider", provider_name)
                span.set_attribute("operation", operation)
                try:
                    result = await fn(*args, **kwargs)
                    span.set_attribute("http.status_code", getattr(result, "status_code", 0))
                    return result
                except Exception as exc:
                    span.record_exception(exc)
                    span.set_attribute("error.type", type(exc).__name__)
                    raise

        return wrapper

    return decorator


def trace_cache(operation: str) -> Callable[..., Any]:
    """Decorate cache get/set operations."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            tracer = get_tracer("tic.cache")
            with tracer.start_as_current_span(f"cache/{operation}") as span:
                span.set_attribute("cache.operation", operation)
                result = fn(*args, **kwargs)
                span.set_attribute("cache.hit", result is not None)
                return result

        return wrapper

    return decorator
