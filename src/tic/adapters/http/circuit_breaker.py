# src/tic/adapters/http/circuit_breaker.py
"""Async circuit breaker for outbound provider calls.

After ``failure_threshold`` consecutive failures (counting only exceptions in
``expected_exc``) the breaker opens and subsequent calls short-circuit with
:class:`CircuitOpenError` instead of doing I/O. After ``recovery_timeout`` the
next call is allowed through as a half-open probe: success closes the breaker,
failure re-opens it. A single success in the closed state resets the
consecutive-failure counter.

State (failure count, breaker state, opened-at) lives behind the StateStore
port, so a Redis-backed store can share breaker state across replicas. The
default in-memory store is per-breaker-instance, i.e. ordinary in-process
behavior. The read-decide-update sequence is guarded by an ``asyncio.Lock`` so
it stays consistent under concurrent calls within a process.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, TypeVar

from tic.adapters.state.memory_store import InMemoryStateStore
from tic.infra.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from tic.ports.state_store import StateStore

_log = get_logger(__name__)

_T = TypeVar("_T")

_CLOSED = "closed"
_OPEN = "open"
_HALF_OPEN = "half_open"


class CircuitOpenError(Exception):
    """Raised when a call is attempted while the breaker is open."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"circuit breaker {name!r} is open")


class CircuitBreaker:
    """A named, async, StateStore-backed circuit breaker."""

    def __init__(  # noqa: PLR0913
        self,
        name: str,
        *,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        expected_exc: tuple[type[BaseException], ...] = (Exception,),
        store: StateStore | None = None,
    ) -> None:
        self._name = name
        self._threshold = max(1, failure_threshold)
        self._recovery = recovery_timeout
        self._expected = expected_exc
        self._store: StateStore = store if store is not None else InMemoryStateStore()
        self._lock = asyncio.Lock()
        self._k_state = f"cb:{name}:state"
        self._k_failures = f"cb:{name}:failures"
        self._k_opened = f"cb:{name}:opened_at"

    @property
    def name(self) -> str:
        return self._name

    def _raw_state(self) -> str:
        return self._store.get(self._k_state) or _CLOSED

    def _recovery_elapsed(self) -> bool:
        opened = self._store.get(self._k_opened)
        if opened is None:
            return True
        return (time.monotonic() - float(opened)) >= self._recovery

    @property
    def state(self) -> str:
        """Current state, reflecting an elapsed recovery window as half_open.

        Pure read: does not mutate storage. An open breaker whose
        ``recovery_timeout`` has elapsed reads as ``half_open`` (the next call
        would be a probe).
        """
        st = self._raw_state()
        if st == _OPEN and self._recovery_elapsed():
            return _HALF_OPEN
        return st

    def _open(self) -> None:
        self._store.set(self._k_state, _OPEN)
        self._store.set(self._k_opened, str(time.monotonic()))
        self._store.delete(self._k_failures)
        _log.warning("circuit_open", breaker=self._name)

    def _close(self) -> None:
        self._store.set(self._k_state, _CLOSED)
        self._store.delete(self._k_failures)
        self._store.delete(self._k_opened)

    def reset(self) -> None:
        """Force the breaker closed and clear its counters."""
        self._close()

    async def call(self, fn: Callable[[], Awaitable[_T]]) -> _T:
        async with self._lock:
            st = self._raw_state()
            if st == _OPEN:
                if self._recovery_elapsed():
                    st = _HALF_OPEN
                    self._store.set(self._k_state, _HALF_OPEN)
                else:
                    raise CircuitOpenError(self._name)
            entry_state = st

        try:
            result = await fn()
        except BaseException as exc:
            if isinstance(exc, self._expected):
                async with self._lock:
                    self._on_failure(entry_state)
            raise
        else:
            async with self._lock:
                self._on_success(entry_state)
            return result

    def _on_failure(self, entry_state: str) -> None:
        if entry_state == _HALF_OPEN:
            self._open()
            return
        n = self._store.incr(self._k_failures)
        if n >= self._threshold:
            self._open()

    def _on_success(self, entry_state: str) -> None:
        if entry_state == _HALF_OPEN:
            self._close()
        else:
            self._store.delete(self._k_failures)
