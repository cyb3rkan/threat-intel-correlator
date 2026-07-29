"""OpenTelemetry instrumentation for TIC.

Architecture note:
  TIC is a local-first tool with one real distributed boundary: the HTTP
  calls to external enrichment providers (VT, AbuseIPDB, MISP). OTel
  instrumentation focuses on this boundary — measuring enrichment latency,
  cache effectiveness, and circuit-breaker events. There is no cross-process
  trace propagation because TIC has no downstream services.

Design decisions:
  - OTel SDK is optional. If opentelemetry-sdk is not installed, all
    instrumentation silently no-ops via the NoOp provider. This preserves
    the zero-dependency install story for minimal deployments.
  - OTLP export is opt-in via TIC_OTEL_ENDPOINT env var.
  - Trace IDs are correlated with structlog correlation IDs so log lines
    can be joined with traces in a Grafana/Loki stack.
  - No user data in span attributes — IOC values are never exported.
    Only provider name, IOC type (enum), cache status, and HTTP status
    code are used as low-cardinality attributes.
"""
