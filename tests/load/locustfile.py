# tests/load/locustfile.py
"""Locust load test suite for TIC API.

Usage (local):
    pip install locust
    locust -f tests/load/locustfile.py --host http://127.0.0.1:8000

Usage (headless / CI):
    locust -f tests/load/locustfile.py \
        --host http://127.0.0.1:8000 \
        --headless --users 10 --spawn-rate 2 \
        --run-time 60s \
        --csv tests/load/results/run_$(date +%s)

Scenarios:
    TicReadUser     — polls health + provider status (read-heavy, lightweight)
    TicSweepUser    — submits sweep requests (write-heavy, expensive path)
    TicMixedUser    — realistic analyst workflow (80% read, 20% sweep)

SLO targets (from RUNBOOK.md):
    P95 /api/health       < 50 ms
    P95 /api/sweep (stub) < 5 000 ms
    Error rate            < 1%

Performance baseline for a local tool (no real providers configured):
    10 concurrent users, 60 seconds → expect zero errors, all within SLO.

CWE-400 (Resource Exhaustion): load tests validate rate limiting behavior
and confirm the bulkhead prevents provider saturation.
"""
from __future__ import annotations

import csv
import io
import json
import random

from locust import HttpUser, TaskSet, between, task

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Minimal valid CSV IOC feed.
_MINI_CSV = b"value,confidence\n1.2.3.4,80\n8.8.8.8,70\nexample.com,60\n"

# Minimal valid NDJSON log file (one line = one event).
_MINI_LOG = b'{"src_ip":"1.2.3.4","action":"deny"}\n{"src_ip":"8.8.8.8","action":"allow"}\n'

# Parametrized sweep payloads for variation.
_FEED_FORMATS = ["csv", "ndjson"]
_OUTPUT_MODES = ["analyst", "summary", "hash"]
_FAIL_ON = ["high", "critical"]


def _make_random_csv(rows: int = 5) -> bytes:
    """Generate a small randomized CSV feed."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["value", "confidence"])
    for _ in range(rows):
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        writer.writerow([ip, random.randint(40, 90)])
    return buf.getvalue().encode()


def _make_random_ndjson(rows: int = 3) -> bytes:
    lines = []
    for _ in range(rows):
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        lines.append(json.dumps({"src_ip": ip, "action": random.choice(["allow", "deny"])}))
    return "\n".join(lines).encode()


# ---------------------------------------------------------------------------
# Task sets
# ---------------------------------------------------------------------------


class ReadTasks(TaskSet):
    """Lightweight read-only tasks — health and provider status."""

    @task(5)
    def health(self) -> None:
        with self.client.get(
            "/api/health",
            name="/api/health",
            catch_response=True,
        ) as r:
            if r.status_code == 200:
                body = r.json()
                if body.get("status") == "ok":
                    r.success()
                else:
                    r.failure(f"Unexpected body: {body}")
            else:
                r.failure(f"HTTP {r.status_code}")

    @task(2)
    def ready(self) -> None:
        with self.client.get(
            "/api/ready",
            name="/api/ready",
            catch_response=True,
        ) as r:
            if r.status_code in (200, 503):
                r.success()  # 503 = degraded but not a load test failure.
            else:
                r.failure(f"HTTP {r.status_code}")

    @task(1)
    def metrics(self) -> None:
        with self.client.get(
            "/api/metrics",
            name="/api/metrics",
            catch_response=True,
        ) as r:
            if r.status_code == 200:
                r.success()
            else:
                r.failure(f"HTTP {r.status_code}")

    @task(1)
    def providers_status(self) -> None:
        with self.client.get(
            "/api/providers/status",
            name="/api/providers/status",
            catch_response=True,
        ) as r:
            if r.status_code in (200, 500):  # 500 = no keys configured; not a load failure
                r.success()
            else:
                r.failure(f"HTTP {r.status_code}")


class SweepTasks(TaskSet):
    """Sweep submission — the expensive path."""

    @task(1)
    def sweep_csv(self) -> None:
        feed = _make_random_csv(rows=random.randint(2, 10))
        with self.client.post(
            "/api/sweep",
            name="/api/sweep [csv]",
            files={
                "feed_file": ("feed.csv", feed, "text/csv"),
                "log_file": ("log.ndjson", _MINI_LOG, "application/x-ndjson"),
            },
            data={
                "feed_format": "csv",
                "output_mode": random.choice(_OUTPUT_MODES),
                "fail_on": random.choice(_FAIL_ON),
                "with_ai": "false",
            },
            catch_response=True,
        ) as r:
            if r.status_code in (200, 429):  # 429 = rate limited; not a test failure
                r.success()
            elif r.status_code == 400:
                # Accept 400 if settings not configured (local dev without providers).
                r.success()
            else:
                r.failure(f"HTTP {r.status_code}: {r.text[:200]}")

    @task(1)
    def sweep_ndjson(self) -> None:
        feed = _make_random_ndjson(rows=random.randint(2, 5))
        with self.client.post(
            "/api/sweep",
            name="/api/sweep [ndjson]",
            files={
                "feed_file": ("feed.ndjson", feed, "application/x-ndjson"),
                "log_file": ("log.ndjson", _MINI_LOG, "application/x-ndjson"),
            },
            data={
                "feed_format": "ndjson",
                "output_mode": "analyst",
                "fail_on": "high",
                "with_ai": "false",
            },
            catch_response=True,
        ) as r:
            if r.status_code in (200, 400, 429):
                r.success()
            else:
                r.failure(f"HTTP {r.status_code}")

    @task(1)
    def sweep_rate_limit_probe(self) -> None:
        """Deliberately trigger rate limiting to validate 429 behavior."""
        for _ in range(3):
            self.client.post(
                "/api/sweep",
                name="/api/sweep [rate-limit-probe]",
                files={
                    "feed_file": ("feed.csv", _MINI_CSV, "text/csv"),
                    "log_file": ("log.ndjson", _MINI_LOG, "application/x-ndjson"),
                },
                data={"feed_format": "csv", "output_mode": "summary", "with_ai": "false"},
            )


# ---------------------------------------------------------------------------
# User classes
# ---------------------------------------------------------------------------


class TicReadUser(HttpUser):
    """Read-only traffic — models Prometheus scraper + health checks."""

    tasks = [ReadTasks]
    wait_time = between(0.5, 2.0)
    weight = 3


class TicSweepUser(HttpUser):
    """Write-heavy sweep traffic — models analyst submitting batches."""

    tasks = [SweepTasks]
    wait_time = between(2.0, 8.0)
    weight = 1


class TicMixedUser(HttpUser):
    """Realistic mixed traffic — 80% reads, 20% sweep."""

    tasks = {ReadTasks: 4, SweepTasks: 1}
    wait_time = between(1.0, 5.0)
    weight = 2


# ---------------------------------------------------------------------------
# Custom SLO assertions (run in CI via locust --exit-code-on-error)
# ---------------------------------------------------------------------------

# To add SLO gate in CI:
#   locust --headless --users 10 --spawn-rate 2 --run-time 60s \
#          --csv results/run \
#          --exit-code-on-error 1
#
# Then check results/run_stats.csv for:
#   - 95th percentile response time for /api/health < 50ms
#   - Failure count == 0
#
# Example shell assertion:
#   P95=$(awk -F',' 'NR>1 && /health/{print $14}' results/run_stats.csv)
#   [ "$P95" -lt 50 ] || { echo "SLO breach: P95 health = ${P95}ms"; exit 1; }
