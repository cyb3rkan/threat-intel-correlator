# src/tic/adapters/state/memory_store.py
"""In-process StateStore -- the default backend.

Keeps all counters/flags in this process, so a single replica behaves exactly
as the original process-local code did. It does NOT share state across replicas;
use the Redis backend for that. Thread-safe so it is correct whether driven from
the event loop or worker threads.
"""

from __future__ import annotations

import threading
import time

from tic.ports.state_store import StateStore


class InMemoryStateStore(StateStore):
    """Thread-safe in-process key/value + counter store with TTL."""

    def __init__(self) -> None:
        self._values: dict[str, str] = {}
        self._expiry: dict[str, float] = {}
        self._lock = threading.Lock()

    def _purge_if_expired(self, key: str, now: float) -> None:
        exp = self._expiry.get(key)
        if exp is not None and exp <= now:
            self._values.pop(key, None)
            self._expiry.pop(key, None)

    def incr(self, key: str, *, ttl_seconds: float | None = None) -> int:
        now = time.monotonic()
        with self._lock:
            self._purge_if_expired(key, now)
            cur = int(self._values.get(key, "0")) + 1
            self._values[key] = str(cur)
            if cur == 1 and ttl_seconds is not None:
                self._expiry[key] = now + ttl_seconds
            return cur

    def get(self, key: str) -> str | None:
        now = time.monotonic()
        with self._lock:
            self._purge_if_expired(key, now)
            return self._values.get(key)

    def set(self, key: str, value: str, *, ttl_seconds: float | None = None) -> None:
        now = time.monotonic()
        with self._lock:
            self._values[key] = value
            if ttl_seconds is not None:
                self._expiry[key] = now + ttl_seconds
            else:
                self._expiry.pop(key, None)

    def delete(self, key: str) -> None:
        with self._lock:
            self._values.pop(key, None)
            self._expiry.pop(key, None)
