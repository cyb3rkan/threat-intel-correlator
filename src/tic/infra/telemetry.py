# src/tic/infra/telemetry.py
"""In-memory metrics registry: RED/USE counters, gauges, and histograms, with a
Prometheus text exposition renderer.

Thread-safe and process-local; the default registry backs the local API's
``/api/metrics`` endpoint. Label values are rendered in Prometheus form
(``name{label="value"}``).
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

_Key = tuple[str, tuple[tuple[str, str], ...]]

# Quantiles exposed for histograms in the Prometheus "summary" form.
_QUANTILES = (0.5, 0.95, 0.99)


def _quantile(ordered: list[float], q: float) -> float:
    """Nearest-rank quantile of an already-sorted list."""
    if not ordered:
        return 0.0
    idx = min(len(ordered) - 1, int(q * len(ordered)))
    return ordered[idx]


@dataclass
class _Snapshot:
    counters: dict[str, int] = field(default_factory=dict)
    gauges: dict[str, float] = field(default_factory=dict)
    histograms: dict[str, list[float]] = field(default_factory=dict)


class MetricsRegistry:
    """Thread-safe in-memory counters, gauges, and histograms."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[_Key, int] = defaultdict(int)
        self._gauges: dict[_Key, float] = {}
        self._histograms: dict[_Key, list[float]] = defaultdict(list)

    @staticmethod
    def _key(name: str, labels: dict[str, str] | None) -> _Key:
        if not labels:
            return (name, ())
        return (name, tuple(sorted(labels.items())))

    # -- primitives --------------------------------------------------------

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

    def observe_duration(
        self, name: str, seconds: float, *, labels: dict[str, str] | None = None
    ) -> None:
        k = self._key(name, labels)
        with self._lock:
            self._histograms[k].append(seconds)

    @contextmanager
    def timer(self, name: str, *, labels: dict[str, str] | None = None) -> Iterator[None]:
        start = time.perf_counter()
        try:
            yield
        finally:
            self.observe_duration(name, time.perf_counter() - start, labels=labels)

    # -- RED / USE helpers -------------------------------------------------

    def record_provider_request(self, provider: str, ioc_type: str) -> None:
        self.inc(
            "tic_provider_requests_total",
            labels={"provider": provider, "ioc_type": ioc_type},
        )
        self.inc("tic_enrichment_requests_total")  # SLO denominator

    def record_provider_error(self, provider: str, error_type: str) -> None:
        self.inc(
            "tic_provider_errors_total",
            labels={"provider": provider, "error_type": error_type},
        )
        self.inc("tic_enrichment_errors_total")  # SLO numerator

    def record_cache_hit(self, provider: str) -> None:
        self.inc("tic_cache_hits_total", labels={"provider": provider})

    def record_cache_miss(self, provider: str) -> None:
        self.inc("tic_cache_misses_total", labels={"provider": provider})

    def record_finding(self, severity: str) -> None:
        self.inc("tic_findings_total", labels={"severity": severity})

    # -- snapshot / reset --------------------------------------------------

    def snapshot(self) -> _Snapshot:
        with self._lock:
            counters = {self._flatten(k): v for k, v in self._counters.items()}
            gauges = {self._flatten(k): v for k, v in self._gauges.items()}
            histograms = {self._flatten(k): list(v) for k, v in self._histograms.items()}
        return _Snapshot(counters=counters, gauges=gauges, histograms=histograms)

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()

    # -- prometheus text exposition ---------------------------------------

    def to_prometheus_text(self) -> str:
        with self._lock:
            counters = list(self._counters.items())
            gauges = list(self._gauges.items())
            histograms = {k: list(v) for k, v in self._histograms.items()}

        lines: list[str] = []
        typed: set[str] = set()

        for k, cval in sorted(counters, key=lambda kv: self._flatten(kv[0])):
            if k[0] not in typed:
                lines.append(f"# TYPE {k[0]} counter")
                typed.add(k[0])
            lines.append(f"{self._flatten(k)} {cval}")

        for k, gval in sorted(gauges, key=lambda kv: self._flatten(kv[0])):
            if k[0] not in typed:
                lines.append(f"# TYPE {k[0]} gauge")
                typed.add(k[0])
            lines.append(f"{self._flatten(k)} {gval:.6g}")

        for k, samples in sorted(histograms.items(), key=lambda kv: self._flatten(kv[0])):
            lines.extend(self._histogram_lines(k[0], k[1], samples))

        return "\n".join(lines) + "\n" if lines else "# no metrics yet\n"

    def _histogram_lines(
        self, name: str, labels: tuple[tuple[str, str], ...], samples: list[float]
    ) -> list[str]:
        ordered = sorted(samples)
        lines = [f"# TYPE {name} summary"]
        for q in _QUANTILES:
            pairs = tuple(sorted((*labels, ("quantile", str(q)))))
            lines.append(f"{name}{self._fmt_labels(pairs)} {_quantile(ordered, q):.6g}")
        base = self._fmt_labels(labels)
        lines.append(f"{name}_sum{base} {sum(ordered):.6g}")
        lines.append(f"{name}_count{base} {len(ordered)}")
        return lines

    @staticmethod
    def _fmt_labels(pairs: tuple[tuple[str, str], ...]) -> str:
        if not pairs:
            return ""
        inner = ",".join(f'{k}="{v}"' for k, v in pairs)
        return f"{{{inner}}}"

    @classmethod
    def _flatten(cls, k: _Key) -> str:
        name, labels = k
        return f"{name}{cls._fmt_labels(labels)}"


_default_registry = MetricsRegistry()


def get_registry() -> MetricsRegistry:
    """Return the process-wide default registry."""
    return _default_registry
