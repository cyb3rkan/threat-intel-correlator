# src/tic/adapters/state/redis_store.py
"""Optional Redis-backed StateStore for multi-replica deployments.

Disabled by default; selected via configuration (``state.backend = "redis"`` /
``TIC_STATE__BACKEND=redis``). Lets rate-limit counters and circuit-breaker
state be shared across replicas. Requires the optional ``redis`` package and a
reachable Redis instance; fails closed (ConfigError) if the package is absent.

NOTE: this backend is not exercised by the in-sandbox test suite (no Redis
available there); the in-memory backend is the tested default.
"""

from __future__ import annotations

from tic.domain.errors import ConfigError
from tic.ports.state_store import StateStore


class RedisStateStore(StateStore):
    """StateStore implemented over Redis string counters with TTL."""

    def __init__(self, url: str, *, key_prefix: str = "tic:state:") -> None:
        try:
            import redis
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ConfigError(
                "redis state backend selected but the 'redis' package is not installed",
                user_message="Install the 'redis' extra to use the redis state backend.",
            ) from exc
        self._client = redis.Redis.from_url(url, decode_responses=True)
        self._prefix = key_prefix

    def _k(self, key: str) -> str:
        return f"{self._prefix}{key}"

    def incr(self, key: str, *, ttl_seconds: float | None = None) -> int:
        k = self._k(key)
        val = int(self._client.incr(k))
        if val == 1 and ttl_seconds is not None:
            self._client.expire(k, max(1, int(ttl_seconds)))
        return val

    def get(self, key: str) -> str | None:
        val: str | None = self._client.get(self._k(key))
        return val

    def set(self, key: str, value: str, *, ttl_seconds: float | None = None) -> None:
        if ttl_seconds is not None:
            self._client.set(self._k(key), value, ex=max(1, int(ttl_seconds)))
        else:
            self._client.set(self._k(key), value)

    def delete(self, key: str) -> None:
        self._client.delete(self._k(key))
