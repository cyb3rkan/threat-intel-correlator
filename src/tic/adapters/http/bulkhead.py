# src/tic/adapters/http/bulkhead.py
"""Bulkhead isolation for provider adapter calls.

Pattern: each enrichment provider runs in its own semaphore-bounded pool.
If VT is slow, it cannot starve AbuseIPDB requests (and vice versa).
This implements the Bulkhead pattern from Michael Nygard's "Release It!"

Usage:
    bulkhead = Bulkhead(name="virustotal", max_concurrent=4, queue_size=8)

    async with bulkhead:
        result = await _do_vt_call(ioc)

    # Or as a decorator:
    @bulkhead.wrap
    async def enrich(ioc): ...

Design:
  - max_concurrent: semaphore slots (matches ProviderConfig.concurrency).
  - queue_size: soft queue cap; requests beyond this are rejected with
    BulkheadFullError (fast-fail, prevents timeout pile-up).
  - Adaptive concurrency: if error rate exceeds threshold, max_concurrent
    is halved until recovery. This prevents a struggling provider from
    consuming all slots and stalling.

NIST CSF DE.AE-4 (Impact of events determined), RC.RP-1 (Recovery planning).
Reliability: bulkhead prevents failure domain expansion across providers.
"""
from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncGenerator, Callable
from typing import Any

from tic.domain.errors import TICError
from tic.infra.logging import get_logger
from tic.infra.telemetry import get_registry

_log = get_logger(__name__)


class BulkheadFullError(TICError):
    """Raised when the bulkhead queue is at capacity (fast-fail)."""

    def __init__(self, name: str) -> None:
        super().__init__(
            f"bulkhead '{name}' is full",
            user_message=f"Provider '{name}' is overloaded. Request rejected.",
        )
        self.provider_name = name


class Bulkhead:
    """Semaphore-bounded bulkhead with adaptive concurrency.

    Args:
        name:            Provider identifier (for logging/metrics).
        max_concurrent:  Maximum in-flight requests (initial value).
        queue_size:      Maximum waiting requests before fast-fail.
        error_window:    Seconds over which to measure error rate.
        error_threshold: Error fraction (0.0–1.0) triggering concurrency reduction.
        recovery_time:   Seconds before attempting to restore full concurrency.
    """

    def __init__(
        self,
        name: str,
        *,
        max_concurrent: int = 4,
        queue_size: int = 8,
        error_window: float = 60.0,
        error_threshold: float = 0.5,
        recovery_time: float = 120.0,
    ) -> None:
        self._name = name
        self._max_concurrent = max_concurrent
        self._queue_size = queue_size
        self._error_window = error_window
        self._error_threshold = error_threshold
        self._recovery_time = recovery_time

        self._sem = asyncio.Semaphore(max_concurrent)
        self._waiters = 0   # Tasks waiting to acquire semaphore.
        self._active = 0    # Tasks currently holding semaphore.
        self._lock = asyncio.Lock()

        # Adaptive concurrency tracking.
        self._request_times: list[float] = []
        self._error_times: list[float] = []
        self._reduced_at: float | None = None
        self._current_max = max_concurrent

        self._registry = get_registry()

    @property
    def current_concurrency(self) -> int:
        return self._current_max

    @contextlib.asynccontextmanager
    async def __call__(self) -> AsyncGenerator[None, None]:
        """Async context manager: acquire bulkhead slot or fast-fail."""
        # Fast-fail if active slots + queue is at capacity.
        if self._active + self._waiters >= self._max_concurrent + self._queue_size:
            self._registry.inc(
                "tic_bulkhead_rejected_total", labels={"provider": self._name}
            )
            _log.warning("bulkhead_queue_full", provider=self._name, waiters=self._waiters)
            raise BulkheadFullError(self._name)

        self._waiters += 1
        self._registry.gauge(
            "tic_bulkhead_queue_depth", self._waiters, labels={"provider": self._name}
        )

        try:
            await self._sem.acquire()
        finally:
            self._waiters -= 1

        self._active += 1
        try:
            self._registry.gauge(
                "tic_bulkhead_active", float(self._active), labels={"provider": self._name}
            )
            yield
        except Exception:
            self._record_error()
            raise
        else:
            self._record_success()
        finally:
            self._active -= 1
            self._sem.release()
            await self._maybe_restore_concurrency()

    def wrap(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Decorator: wrap an async function with bulkhead protection."""
        import functools

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            async with self():
                return await fn(*args, **kwargs)

        return wrapper

    def _record_success(self) -> None:
        now = time.monotonic()
        self._request_times.append(now)
        self._evict_old(now)

    def _record_error(self) -> None:
        now = time.monotonic()
        self._request_times.append(now)
        self._error_times.append(now)
        self._evict_old(now)
        self._maybe_reduce_concurrency()

    def _evict_old(self, now: float) -> None:
        cutoff = now - self._error_window
        # bisect avoids rebuilding the whole list when the common case is
        # that only the head is stale (lists are appended in time order).
        import bisect
        idx = bisect.bisect_left(self._request_times, cutoff)
        if idx:
            del self._request_times[:idx]
        idx = bisect.bisect_left(self._error_times, cutoff)
        if idx:
            del self._error_times[:idx]

    def _maybe_reduce_concurrency(self) -> None:
        if not self._request_times:
            return
        rate = len(self._error_times) / len(self._request_times)
        if rate >= self._error_threshold and self._current_max > 1:
            new_max = max(1, self._current_max // 2)
            if new_max < self._current_max:
                self._current_max = new_max
                self._reduced_at = time.monotonic()
                _log.warning(
                    "bulkhead_concurrency_reduced",
                    provider=self._name,
                    new_max=new_max,
                    error_rate=round(rate, 2),
                )
                self._registry.gauge(
                    "tic_bulkhead_concurrency",
                    float(new_max),
                    labels={"provider": self._name},
                )

    async def _maybe_restore_concurrency(self) -> None:
        if (
            self._reduced_at is not None
            and time.monotonic() - self._reduced_at >= self._recovery_time
            and self._current_max < self._max_concurrent
        ):
            # Only restore if recent error rate is low.
            now = time.monotonic()
            self._evict_old(now)
            rate = (
                len(self._error_times) / len(self._request_times)
                if self._request_times
                else 0.0
            )
            if rate < self._error_threshold / 2:
                self._current_max = min(self._max_concurrent, self._current_max * 2)
                self._reduced_at = None
                _log.info(
                    "bulkhead_concurrency_restored",
                    provider=self._name,
                    new_max=self._current_max,
                )
                self._registry.gauge(
                    "tic_bulkhead_concurrency",
                    float(self._current_max),
                    labels={"provider": self._name},
                )
