# ADR-006: Bulkhead Isolation with Adaptive Concurrency

**Status:** Accepted | **Date:** 2025-01

## Context
VT, AbuseIPDB, and MISP are independent services. A slow VT should not starve AbuseIPDB requests. When a provider is struggling, flooding it with concurrent requests accelerates its failure.

## Decision
- Each provider gets an independent semaphore-bounded `Bulkhead`.
- `queue_size` determines how many requests can wait (default 8). Beyond this → fast-fail `BulkheadFullError`.
- Adaptive concurrency: if error rate over `error_window` seconds exceeds `error_threshold`, `max_concurrent` is halved. Recovery after `recovery_time` seconds.

## Consequences
- Provider failures are isolated — failure domain does not expand.
- Provider is protected from overload during degradation (back-pressure applied).
- Adds one lock acquisition per enrichment call (~µs overhead).
