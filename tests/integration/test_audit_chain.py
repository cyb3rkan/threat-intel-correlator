# tests/integration/test_audit_chain.py
from __future__ import annotations

from pathlib import Path

from tic.adapters.audit.hash_chain import HashChainAuditLogger


def test_chain_verifies(tmp_path: Path) -> None:
    log = HashChainAuditLogger(tmp_path / "audit.log")
    for i in range(5):
        log.append("evt", {"i": i})
    assert log.verify_chain() is True


def test_chain_detects_tamper(tmp_path: Path) -> None:
    path = tmp_path / "audit.log"
    log = HashChainAuditLogger(path)
    log.append("evt", {"i": 1})
    log.append("evt", {"i": 2})
    # Tamper: modify the middle record's payload
    lines = path.read_text().splitlines()
    lines[0] = lines[0].replace('"i":1', '"i":999')
    path.write_text("\n".join(lines) + "\n")
    assert log.verify_chain() is False