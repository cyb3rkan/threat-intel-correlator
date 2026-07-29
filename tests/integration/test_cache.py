# tests/integration/test_cache.py
from __future__ import annotations

import time
from pathlib import Path

from tic.adapters.cache.sqlite_cache import SqliteCache


def test_set_get_roundtrip(tmp_path: Path) -> None:
    c = SqliteCache(tmp_path / "cache.db", allowed_root=tmp_path)
    c.set("ns", "k", b"value", ttl_seconds=60)
    assert c.get("ns", "k") == b"value"


def test_ttl_expiry(tmp_path: Path) -> None:
    c = SqliteCache(tmp_path / "cache.db", allowed_root=tmp_path)
    c.set("ns", "k", b"v", ttl_seconds=1)
    time.sleep(1.2)
    assert c.get("ns", "k") is None


def test_purge_expired(tmp_path: Path) -> None:
    c = SqliteCache(tmp_path / "cache.db", allowed_root=tmp_path)
    c.set("ns", "k1", b"v", ttl_seconds=1)
    c.set("ns", "k2", b"v", ttl_seconds=1000)
    time.sleep(1.2)
    removed = c.purge_expired()
    assert removed == 1
