# tests/unit/test_audit_retention.py
"""Audit-log rotation / retention (Part 5, Finding 3)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tic.adapters.audit.hash_chain import HashChainAuditLogger

if TYPE_CHECKING:
    from pathlib import Path


def test_rotation_seals_segments_and_enforces_retention(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    logger = HashChainAuditLogger(log, max_bytes=4096, max_rotations=2)
    for i in range(400):
        logger.append("e", {"i": i, "pad": "x" * 64})

    # Current segment exists and is itself a valid (genesis-rooted) chain.
    assert log.exists()
    assert logger.verify_chain() is True

    # At most max_rotations sealed segments are retained.
    assert log.with_name("audit.log.1").exists()
    assert log.with_name("audit.log.2").exists()
    assert not log.with_name("audit.log.3").exists()


def test_no_rotation_when_max_bytes_none(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    logger = HashChainAuditLogger(log)  # default: never rolls
    for i in range(50):
        logger.append("e", {"i": i})

    assert log.exists()
    assert not log.with_name("audit.log.1").exists()
    assert logger.verify_chain() is True
