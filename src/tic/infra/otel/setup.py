# src/tic/infra/otel/setup.py
"""OpenTelemetry SDK bootstrap (optional dependency, graceful degradation).

If opentelemetry-sdk is installed:
  - TracerProvider configured with OTLP export (if TIC_OTEL_ENDPOINT set)
    or console export (if TIC_OTEL_CONSOLE=1).
  - Service name, version, and environment set via resource attributes.
  - Trace/span IDs injected into structlog context for log-trace correlation.

If not installed:
  - All calls return no-op stubs. Zero runtime cost. Zero import errors.

Environment variables:
  TIC_OTEL_ENDPOINT      OTLP gRPC endpoint (e.g. http://localhost:4317)
  TIC_OTEL_CONSOLE       Set to 1 for console span export (dev/debug)
  TIC_OTEL_SAMPLE_RATE   Float 0.0–1.0 (default 1.0 for local tool)
  TIC_OTEL_DISABLED      Set to 1 to force no-op even if SDK present

CWE-778 (Insufficient Logging of Security Events) — OTel tracing surfaces
enrichment pipeline timing anomalies that structured logs alone cannot.
"""
from __future__ import annotations

import os
from typing import Any

_DISABLED = os.environ.get("TIC_OTEL_DISABLED", "").strip().lower() in {"1", "true", "yes"}


def _try_import_otel() -> bool:
    try:
        import opentelemetry  # noqa: F401
        return True
    except ImportError:
        return False


_OTEL_AVAILABLE = not _DISABLED and _try_import_otel()


class _NoOpSpan:
    """Null-object span — safe to use in with/as blocks."""

    def __enter__(self) -> _NoOpSpan:
        return self

    def __exit__(self, *_: Any) -> None:
        pass

    def set_attribute(self, key: str, value: Any) -> None:  # noqa: ARG002
        pass

    def record_exception(self, exc: Exception) -> None:  # noqa: ARG002
        pass

    def set_status(self, *_: Any) -> None:
        pass

    @property
    def context(self) -> _NoOpContext:
        return _NoOpContext()


class _NoOpContext:
    trace_id: int = 0
    span_id: int = 0


class _NoOpTracer:
    def start_as_current_span(
        self, name: str, **_kwargs: Any
    ) -> _NoOpSpan:
        return _NoOpSpan()

    def start_span(self, name: str, **_kwargs: Any) -> _NoOpSpan:
        return _NoOpSpan()


_noop_tracer = _NoOpTracer()


def get_tracer(name: str) -> Any:
    """Return an OTel Tracer or a no-op stub if SDK is unavailable."""
    if not _OTEL_AVAILABLE:
        return _noop_tracer
    from opentelemetry import trace
    return trace.get_tracer(name, schema_url="https://opentelemetry.io/schemas/1.23.1")


def configure_otel(
    *,
    service_name: str = "threat-intel-correlator",
    service_version: str = "0.1.0",
    environment: str = "local",
) -> None:
    """Bootstrap OTel SDK. Safe to call multiple times (idempotent).

    Call once at process startup (CLI main, API lifespan).
    """
    if not _OTEL_AVAILABLE:
        return

    import opentelemetry.sdk.trace as sdk_trace
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    resource = Resource.create(
        {
            "service.name": service_name,
            "service.version": service_version,
            "deployment.environment": environment,
        }
    )

    provider = sdk_trace.TracerProvider(resource=resource)

    # OTLP export (Grafana Tempo, Jaeger, etc.)
    endpoint = os.environ.get("TIC_OTEL_ENDPOINT", "").strip()
    if endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
            provider.add_span_processor(
                BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint))
            )
        except ImportError:
            # opentelemetry-exporter-otlp not installed; skip silently.
            pass

    # Console export for local debug.
    if os.environ.get("TIC_OTEL_CONSOLE", "").strip().lower() in {"1", "true"}:
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))

    trace.set_tracer_provider(provider)


def current_trace_context() -> dict[str, str]:
    """Return {trace_id, span_id} for structlog injection.

    Returns empty dict if OTel is unavailable or no active span.
    """
    if not _OTEL_AVAILABLE:
        return {}
    try:
        from opentelemetry import trace
        span = trace.get_current_span()
        ctx = span.get_span_context()
        if ctx and ctx.is_valid:
            return {
                "otel_trace_id": format(ctx.trace_id, "032x"),
                "otel_span_id": format(ctx.span_id, "016x"),
            }
    except Exception:  # noqa: BLE001
        pass
    return {}
