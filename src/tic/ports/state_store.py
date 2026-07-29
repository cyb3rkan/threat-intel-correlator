# src/tic/ports/state_store.py
"""StateStore port: shared mutable counters/flags for durability state.

Rate-limit counters and circuit-breaker state are process-local by default,
which is correct for the single-replica, local-first deployment but blocks
horizontal scaling (each replica would keep its own counters). This port puts
that state behind an interface: the default in-memory adapter keeps everything
in-process (identical to the original behavior), while an optional Redis-backed
adapter (flagged off) lets state be shared across replicas.

Implementations MUST be safe under concurrent access. Values are strings (or
integers via :meth:`incr`); callers serialize richer values themselves.
"""

from __future__ import annotations

from typing import Protocol


class StateStore(Protocol):
    """Contract for a small shared counter/flag store."""

    def incr(self, key: str, *, ttl_seconds: float | None = None) -> int:
        """Atomically increment the integer counter at ``key`` and return it.

        Creates the key at 1 if absent. ``ttl_seconds`` sets an expiry when the
        counter is first created (fixed-window semantics for rate limiting);
        it is not refreshed on subsequent increments within the window.
        """
        ...

    def get(self, key: str) -> str | None:
        """Return the value at ``key``, or None if absent/expired."""
        ...

    def set(self, key: str, value: str, *, ttl_seconds: float | None = None) -> None:
        """Set ``key`` to ``value`` with an optional expiry (seconds)."""
        ...

    def delete(self, key: str) -> None:
        """Delete ``key`` (no error if absent)."""
        ...
