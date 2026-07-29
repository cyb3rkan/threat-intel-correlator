# tests/unit/test_bulkhead.py
"""Tests for the Bulkhead isolation pattern."""
from __future__ import annotations

import asyncio

import pytest

from tic.adapters.http.bulkhead import Bulkhead, BulkheadFullError


@pytest.mark.asyncio()
async def test_bulkhead_allows_requests_within_limit() -> None:
    bulkhead = Bulkhead("test", max_concurrent=3, queue_size=5)
    results = []

    async def _task(n: int) -> None:
        async with bulkhead():
            results.append(n)

    await asyncio.gather(*(_task(i) for i in range(3)))
    assert sorted(results) == [0, 1, 2]


@pytest.mark.asyncio()
async def test_bulkhead_fast_fails_when_queue_full() -> None:
    bulkhead = Bulkhead("test", max_concurrent=1, queue_size=0)
    gate = asyncio.Event()

    async def _hold():
        async with bulkhead():
            await gate.wait()

    t = asyncio.create_task(_hold())
    await asyncio.sleep(0.02)  # Let task acquire slot.

    with pytest.raises(BulkheadFullError):
        async with bulkhead():
            pass

    gate.set()
    await t


@pytest.mark.asyncio()
async def test_bulkhead_decorator() -> None:
    bulkhead = Bulkhead("test", max_concurrent=2, queue_size=4)
    results = []

    @bulkhead.wrap
    async def _work(n: int) -> int:
        results.append(n)
        return n * 2

    vals = await asyncio.gather(*(_work(i) for i in range(4)))
    assert sorted(vals) == [0, 2, 4, 6]
    assert sorted(results) == [0, 1, 2, 3]


@pytest.mark.asyncio()
async def test_bulkhead_records_errors_for_adaptive_concurrency() -> None:
    bulkhead = Bulkhead("test", max_concurrent=4, queue_size=4,
                        error_threshold=0.5, error_window=60.0)

    # Inject enough errors to trigger reduction.
    for _ in range(10):
        try:
            async with bulkhead():
                raise RuntimeError("injected")
        except RuntimeError:
            pass

    assert bulkhead.current_concurrency < 4


def test_bulkhead_error_name_in_exception() -> None:
    """BulkheadFullError must include provider name."""
    exc = BulkheadFullError("my-provider")
    assert "my-provider" in str(exc)
    assert exc.provider_name == "my-provider"
