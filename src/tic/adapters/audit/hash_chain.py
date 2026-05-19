# src/tic/adapters/audit/hash_chain.py
"""Append-only, hash-chained audit log. Tamper-evident."""
from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tic.infra.logging import get_logger
from tic.ports.audit_logger import AuditLogger

_log = get_logger(__name__)


class HashChainAuditLogger(AuditLogger):
    """Each line: {"ts","type","payload","prev_hash","this_hash"} as JSON."""

    GENESIS = "0" * 64

    def __init__(self, log_path: Path) -> None:
        self._path = log_path
        self._lock = threading.Lock()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        if not log_path.exists():
            log_path.touch(mode=0o600)
        else:
            try:
                os.chmod(log_path, 0o600)
            except OSError:
                pass

    def _last_hash(self) -> str:
        if not self._path.exists() or self._path.stat().st_size == 0:
            return self.GENESIS
        with self._path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            read = min(size, 8192)
            f.seek(-read, os.SEEK_END)
            tail = f.read().splitlines()
        for line in reversed(tail):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                return str(obj["this_hash"])
            except (json.JSONDecodeError, KeyError):
                continue
        return self.GENESIS

    def append(self, event_type: str, payload: dict[str, Any]) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": event_type[:64],
            "payload": payload,
        }
        serialized = json.dumps(record, sort_keys=True, separators=(",", ":"))
        with self._lock:
            prev = self._last_hash()
            this_hash = hashlib.sha256((prev + serialized).encode("utf-8")).hexdigest()
            record["prev_hash"] = prev
            record["this_hash"] = this_hash
            line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
            with self._path.open("ab") as f:
                f.write(line.encode("utf-8"))

    def verify_chain(self) -> bool:
        prev = self.GENESIS
        with self._path.open("rb") as f:
            for raw in f:
                if not raw.strip():
                    continue
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    return False
                claimed_prev = obj.get("prev_hash")
                claimed_this = obj.get("this_hash")
                if claimed_prev != prev:
                    return False
                # Recompute on the record without the two hash fields.
                core = {k: v for k, v in obj.items() if k not in ("prev_hash", "this_hash")}
                serialized = json.dumps(core, sort_keys=True, separators=(",", ":"))
                expect = hashlib.sha256((prev + serialized).encode("utf-8")).hexdigest()
                if expect != claimed_this:
                    return False
                prev = claimed_this
        return True