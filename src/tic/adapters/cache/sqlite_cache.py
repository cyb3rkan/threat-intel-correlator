# src/tic/adapters/cache/sqlite_cache.py
"""SQLite-backed TTL cache. Parameterized queries only. File perms 0600."""
from __future__ import annotations

import os
import sqlite3
import threading
import time
from pathlib import Path

from tic.infra.logging import get_logger
from tic.ports.cache import Cache
from tic.security.path_guard import safe_resolve_within

_log = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    namespace TEXT NOT NULL,
    key TEXT NOT NULL,
    value BLOB NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (namespace, key)
);
CREATE INDEX IF NOT EXISTS idx_expires ON entries (expires_at);
"""


class SqliteCache(Cache):
    def __init__(self, db_path: Path, *, allowed_root: Path) -> None:
        resolved = safe_resolve_within(db_path, allowed_root=allowed_root)
        resolved.parent.mkdir(parents=True, exist_ok=True)
        self._path = resolved
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(resolved), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.executescript(_SCHEMA)
        try:
            os.chmod(resolved, 0o600)
        except OSError as e:
            _log.warning("cache_chmod_failed", error=str(e))

    def get(self, namespace: str, key: str) -> bytes | None:
        now = int(time.time())
        with self._lock:
            cur = self._conn.execute(
                "SELECT value, expires_at FROM entries WHERE namespace=? AND key=?",
                (namespace, key),
            )
            row = cur.fetchone()
        if row is None:
            return None
        value, expires_at = row
        if expires_at <= now:
            with self._lock:
                self._conn.execute(
                    "DELETE FROM entries WHERE namespace=? AND key=?", (namespace, key)
                )
                self._conn.commit()
            return None
        return bytes(value)

    def set(self, namespace: str, key: str, value: bytes, ttl_seconds: int) -> None:
        if ttl_seconds < 1:
            raise ValueError("ttl_seconds must be positive")
        expires_at = int(time.time()) + ttl_seconds
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO entries (namespace,key,value,expires_at) VALUES (?,?,?,?)",
                (namespace, key, value, expires_at),
            )
            self._conn.commit()

    def purge_expired(self) -> int:
        now = int(time.time())
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM entries WHERE expires_at <= ?", (now,)
            )
            self._conn.commit()
            return cur.rowcount or 0

    def close(self) -> None:
        with self._lock:
            self._conn.close()