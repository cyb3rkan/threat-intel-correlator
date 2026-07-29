# tests/unit/test_telemetry_extended.py
"""Extended tests for the updated MetricsRegistry (RED/USE + Prometheus text)."""
from __future__ import annotations

import time

import pytest

from tic.infra.telemetry import MetricsRegistry


@pytest.fixture()
def registry() -> MetricsRegistry:
    r = MetricsRegistry()
    return r


def test_record_provider_request(registry: MetricsRegistry) -> None:
    registry.record_provider_request("virustotal", "ip")
    snap = registry.snapshot()
    key = 'tic_provider_requests_total{ioc_type="ip",provider="virustotal"}'
    assert snap.counters.get(key, 0) == 1
    # SLO denominator also incremented.
    assert snap.counters.get("tic_enrichment_requests_total", 0) == 1


def test_record_provider_error(registry: MetricsRegistry) -> None:
    registry.record_provider_error("virustotal", "NetworkError")
    snap = registry.snapshot()
    assert snap.counters.get("tic_enrichment_errors_total", 0) == 1


def test_cache_hit_miss(registry: MetricsRegistry) -> None:
    registry.record_cache_hit("virustotal")
    registry.record_cache_miss("abuseipdb")
    snap = registry.snapshot()
    assert snap.counters.get('tic_cache_hits_total{provider="virustotal"}', 0) == 1
    assert snap.counters.get('tic_cache_misses_total{provider="abuseipdb"}', 0) == 1


def test_timer_context_manager(registry: MetricsRegistry) -> None:
    with registry.timer("tic_test_duration_seconds"):
        time.sleep(0.01)
    snap = registry.snapshot()
    samples = snap.histograms.get("tic_test_duration_seconds", [])
    assert len(samples) == 1
    assert samples[0] >= 0.01


def test_prometheus_text_output(registry: MetricsRegistry) -> None:
    registry.inc("tic_test_counter_total")
    registry.gauge("tic_test_gauge", 42.0)
    text = registry.to_prometheus_text()
    assert "tic_test_counter_total" in text
    assert "tic_test_gauge" in text
    assert "42" in text
    assert "# TYPE" in text


def test_prometheus_histogram_quantiles(registry: MetricsRegistry) -> None:
    for i in range(100):
        registry.observe_duration("tic_latency_seconds", i * 0.001)
    text = registry.to_prometheus_text()
    assert 'quantile="0.5"' in text
    assert 'quantile="0.95"' in text
    assert 'quantile="0.99"' in text
    assert "_count" in text
    assert "_sum" in text


def test_record_finding_severity(registry: MetricsRegistry) -> None:
    for sev in ["critical", "high", "medium", "low", "info"]:
        registry.record_finding(sev)
    snap = registry.snapshot()
    assert snap.counters.get('tic_findings_total{severity="critical"}', 0) == 1
    assert snap.counters.get('tic_findings_total{severity="high"}', 0) == 1


def test_reset_clears_all(registry: MetricsRegistry) -> None:
    registry.inc("tic_test")
    registry.gauge("tic_gauge", 1.0)
    registry.observe_duration("tic_dur", 1.0)
    registry.reset()
    snap = registry.snapshot()
    assert snap.counters == {}
    assert snap.gauges == {}
    assert snap.histograms == {}


def test_inc_negative_raises(registry: MetricsRegistry) -> None:
    with pytest.raises(ValueError, match="non-negative"):
        registry.inc("counter", by=-1)
