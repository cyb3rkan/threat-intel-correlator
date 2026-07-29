# ADR-005: OpenTelemetry Instrumentation Strategy

**Status:** Accepted | **Date:** 2025-01

## Context
TIC has one real distributed boundary: HTTP calls to external enrichment providers. OTel instrumentation should measure this boundary without mandating the SDK as a hard dependency (break minimal install story).

## Decision
- OTel SDK is **optional** — all instrumentation degrades to no-ops if `opentelemetry-sdk` is absent.
- `TIC_OTEL_ENDPOINT` enables OTLP export (Tempo/Jaeger). Default: disabled.
- IOC values are **never** added as span attributes — only low-cardinality enums (provider name, IOC type, outcome).
- Trace IDs are injected into structlog context for log-trace correlation in Grafana/Loki.

## Consequences
- Zero-dependency install preserved.
- Analysts running without an OTel collector lose no functionality.
- Trace-log correlation possible for operators who deploy an OTel collector.
