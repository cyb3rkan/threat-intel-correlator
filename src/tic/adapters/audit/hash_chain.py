# src/tic/adapters/audit/hash_chain.py
"""Append-only, hash-chained audit log. Tamper-evident, optionally signed.

Two integrity layers:

* SHA-256 *link* chain (always on): each record stores
  ``this_hash = sha256(prev_hash + serialized_core)``. Reordering or in-place
  edits become detectable, but a writer who can append to the file can also
  recompute the link chain, so on its own it does not stop a privileged forger.

* HMAC *signature* chain (opt-in: ``audit.sign: true`` + a keyring key): each
  record stores ``hmac = HMAC-SHA256(key, this_hash || prev_hmac)``. The key
  never lives in the log, so a writer without it cannot forge signatures. The
  HMAC is itself chained (folds in the previous record's hmac), so a signed
  record cannot be moved, edited, or dropped from the middle undetected.

Backward compatibility: records written before signing was enabled carry no
``hmac`` field; ``verify_chain`` accepts that leading *prefix* with link-only
checks. Once the first signed record appears, every later record MUST carry a
valid hmac -- an unsigned record after that point fails verification, which
blocks a downgrade where a forger simply strips signatures.

Residual (documented for operators): a forger with write access can still
*truncate* trailing signed records -- the shortened chain stays internally
valid. Defeating truncation needs an out-of-band anchor (e.g. shipping the
head hmac to a separate trust domain), which is out of scope here.
"""

from __future__ import annotations

import hashlib
import hmac as hmaclib
import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tic.infra.logging import get_logger
from tic.ports.audit_logger import AuditLogger

_log = get_logger(__name__)


def _hmac_sign(key: bytes, this_hash: str, prev_hmac: str) -> str:
    """Chained HMAC-SHA256 of the link hash folded with the previous hmac."""
    msg = (this_hash + prev_hmac).encode("utf-8")
    return hmaclib.new(key, msg, hashlib.sha256).hexdigest()


class HashChainAuditLogger(AuditLogger):
    """Each line: {"ts","type","payload","prev_hash","this_hash"[,"hmac"]} JSON.

    Pass ``signing_key`` (raw bytes from the keyring) to enable the HMAC
    signature chain. Omit it (or ``None``) for the link-only chain -- the
    historical behaviour, which stays verifiable by a signed-aware verifier.
    """

    GENESIS = "0" * 64
    HMAC_GENESIS = "0" * 64

    def __init__(
        self,
        log_path: Path,
        *,
        signing_key: bytes | None = None,
        max_bytes: int | None = None,
        max_rotations: int = 5,
    ) -> None:
        self._path = log_path
        self._lock = threading.Lock()
        self._signing_key = signing_key
        self._max_bytes = max_bytes
        self._max_rotations = max_rotations
        log_path.parent.mkdir(parents=True, exist_ok=True)
        if not log_path.exists():
            log_path.touch(mode=0o600)
        else:
            try:
                os.chmod(log_path, 0o600)
            except OSError:
                pass

    def _last_record(self) -> dict[str, Any] | None:
        if not self._path.exists() or self._path.stat().st_size == 0:
            return None
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
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                return obj
        return None

    def append(self, event_type: str, payload: dict[str, Any]) -> None:
        record: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "type": event_type[:64],
            "payload": payload,
        }
        serialized = json.dumps(record, sort_keys=True, separators=(",", ":"))
        key = self._signing_key
        with self._lock:
            self._maybe_rotate()
            last = self._last_record()
            prev = self.GENESIS
            prev_hmac = self.HMAC_GENESIS
            if last is not None:
                if "this_hash" in last:
                    prev = str(last["this_hash"])
                if "hmac" in last:
                    prev_hmac = str(last["hmac"])
            this_hash = hashlib.sha256((prev + serialized).encode("utf-8")).hexdigest()
            record["prev_hash"] = prev
            record["this_hash"] = this_hash
            if key is not None:
                record["hmac"] = _hmac_sign(key, this_hash, prev_hmac)
            line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
            with self._path.open("ab") as f:
                f.write(line.encode("utf-8"))

    def _rotated_path(self, n: int) -> Path:
        return self._path.with_name(f"{self._path.name}.{n}")

    def _maybe_rotate(self) -> None:
        """Roll the log at ``max_bytes``, keeping <= ``max_rotations`` segments.

        Each rotated file is a sealed, independently verifiable hash chain; the
        new current file restarts from genesis. The oldest segment beyond the
        retention window is deleted. No-op when ``max_bytes`` is None.
        """
        if self._max_bytes is None or not self._path.exists():
            return
        if self._path.stat().st_size < self._max_bytes:
            return
        oldest = self._rotated_path(self._max_rotations)
        if oldest.exists():
            oldest.unlink()
        for i in range(self._max_rotations - 1, 0, -1):
            src = self._rotated_path(i)
            if src.exists():
                src.replace(self._rotated_path(i + 1))
        self._path.replace(self._rotated_path(1))

    def verify_chain(self) -> bool:
        """Verify the link chain and, where present, the HMAC signature chain.

        Returns False on any link mismatch, any bad/forged HMAC, an unsigned
        record appearing after signing has begun, or a signed record when no
        verification key is available (fail-closed: an unverifiable signature
        is treated as a failure).
        """
        key = self._signing_key
        prev = self.GENESIS
        prev_hmac = self.HMAC_GENESIS
        signing_seen = False
        with self._path.open("rb") as f:
            for raw in f:
                if not raw.strip():
                    continue
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    return False
                if not isinstance(obj, dict):
                    return False
                claimed_prev = obj.get("prev_hash")
                claimed_this = obj.get("this_hash")
                if claimed_prev != prev:
                    return False
                core = {
                    k: v
                    for k, v in obj.items()
                    if k not in ("prev_hash", "this_hash", "hmac")
                }
                serialized = json.dumps(core, sort_keys=True, separators=(",", ":"))
                expect = hashlib.sha256((prev + serialized).encode("utf-8")).hexdigest()
                if expect != claimed_this:
                    return False

                claimed_hmac = obj.get("hmac")
                if claimed_hmac is not None:
                    if key is None:
                        return False
                    expect_hmac = _hmac_sign(key, str(claimed_this), prev_hmac)
                    if not hmaclib.compare_digest(expect_hmac, str(claimed_hmac)):
                        return False
                    signing_seen = True
                    prev_hmac = str(claimed_hmac)
                elif signing_seen:
                    return False
                prev = str(claimed_this)
        return True
