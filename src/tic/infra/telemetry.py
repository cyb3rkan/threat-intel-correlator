# src/tic/infra/telemetry.py
"""In-memory metrics registry.

Scope (MVP):
- Counters and gauges only; no OpenTelemetry dependency.
- Label values MUST be low-cardinality and drawn from developer-controlled
  enums (provider names, IOC types, etc.). NEVER use user-supplied strings
  as label values — that risks cardinality explosion and data leakage into
  telemetry backends.
- Read via `snapshot()` at shutdown or on demand; metrics are not streamed.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class _Snapshot:
    counters: dict[str, int] = field(default_factory=dict)
    gauges: dict[str, float] = field(default_factory=dict)


class MetricsRegistry:
    """Thread-safe in-memory counters and gauges."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], int] = defaultdict(int)
        self._gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}

    @staticmethod
    def _key(name: str, labels: dict[str, str] | None) -> tuple[str, tuple[tuple[str, str], ...]]:
        if not labels:
            return (name, ())
        return (name, tuple(sorted(labels.items())))

    def inc(self, name: str, *, labels: dict[str, str] | None = None, by: int = 1) -> None:
        if by < 0:
            raise ValueError("inc delta must be non-negative")
        k = self._key(name, labels)
        with self._lock:
            self._counters[k] += by

    def gauge(self, name: str, value: float, *, labels: dict[str, str] | None = None) -> None:
        k = self._key(name, labels)
        with self._lock:
            self._gauges[k] = value

    def snapshot(self) -> _Snapshot:
        with self._lock:
            counters = {self._flatten(k): v for k, v in self._counters.items()}
            gauges = {self._flatten(k): v for k, v in self._gauges.items()}
        return _Snapshot(counters=counters, gauges=gauges)

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._gauges.clear()

    @staticmethod
    def _flatten(k: tuple[str, tuple[tuple[str, str], ...]]) -> str:
        name, labels = k
        if not labels:
            return name
        lbl = ",".join(f"{kk}={vv}" for kk, vv in labels)
        return f"{name}{{{lbl}}}"


_default_registry = MetricsRegistry()


def get_registry() -> MetricsRegistry:
    """Return the process-wide default registry."""
    return _default_registry
