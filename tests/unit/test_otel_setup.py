# tests/unit/test_otel_setup.py
"""Tests for OpenTelemetry setup (graceful degradation without SDK)."""
from __future__ import annotations

from tic.infra.otel.setup import (
    _NoOpSpan,
    _NoOpTracer,
    configure_otel,
    current_trace_context,
    get_tracer,
)


def test_get_tracer_returns_something() -> None:
    """get_tracer must return a usable object regardless of OTel availability."""
    tracer = get_tracer("test")
    assert tracer is not None


def test_noop_span_context_manager() -> None:
    """NoOp span must work as context manager without error."""
    span = _NoOpSpan()
    with span as s:
        s.set_attribute("key", "value")
        s.record_exception(ValueError("test"))
        s.set_status("ok")


def test_noop_tracer_start_span() -> None:
    tracer = _NoOpTracer()
    with tracer.start_as_current_span("test-span") as span:
        span.set_attribute("test", True)


def test_configure_otel_safe_without_sdk() -> None:
    """configure_otel must not raise even if opentelemetry-sdk is absent."""
    configure_otel(
        service_name="tic-test",
        service_version="0.0.1",
        environment="test",
    )


def test_current_trace_context_returns_dict() -> None:
    ctx = current_trace_context()
    assert isinstance(ctx, dict)
    # With no active span, context is empty or has trace_id/span_id.
    for key in ctx:
        assert isinstance(ctx[key], str)


def test_noop_span_context_has_zero_ids() -> None:
    span = _NoOpSpan()
    assert span.context.trace_id == 0
    assert span.context.span_id == 0
