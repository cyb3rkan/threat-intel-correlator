# tests/unit/test_telemetry.py
from __future__ import annotations

import threading

import pytest

from tic.infra.telemetry import MetricsRegistry, get_registry


def test_counter_inc_and_snapshot() -> None:
    r = MetricsRegistry()
    r.inc("requests", by=1)
    r.inc("requests", by=4)
    snap = r.snapshot()
    assert snap.counters["requests"] == 5


def test_labeled_counters_are_distinct() -> None:
    r = MetricsRegistry()
    r.inc("http", labels={"method": "GET"})
    r.inc("http", labels={"method": "POST"})
    r.inc("http", labels={"method": "GET"})
    snap = r.snapshot()
    assert snap.counters["http{method=GET}"] == 2
    assert snap.counters["http{method=POST}"] == 1


def test_gauge_overwrites() -> None:
    r = MetricsRegistry()
    r.gauge("queue_depth", 5.0)
    r.gauge("queue_depth", 3.0)
    snap = r.snapshot()
    assert snap.gauges["queue_depth"] == 3.0


def test_negative_inc_rejected() -> None:
    r = MetricsRegistry()
    with pytest.raises(ValueError):
        r.inc("x", by=-1)


def test_label_ordering_is_canonical() -> None:
    r = MetricsRegistry()
    r.inc("m", labels={"b": "2", "a": "1"})
    r.inc("m", labels={"a": "1", "b": "2"})
    snap = r.snapshot()
    assert snap.counters["m{a=1,b=2}"] == 2


def test_thread_safety() -> None:
    r = MetricsRegistry()
    n = 1000
    workers = 8

    def _bump() -> None:
        for _ in range(n):
            r.inc("x")

    threads = [threading.Thread(target=_bump) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert r.snapshot().counters["x"] == n * workers


def test_reset() -> None:
    r = MetricsRegistry()
    r.inc("a")
    r.gauge("b", 1.0)
    r.reset()
    snap = r.snapshot()
    assert snap.counters == {}
    assert snap.gauges == {}


def test_default_registry_is_singleton() -> None:
    assert get_registry() is get_registry()
