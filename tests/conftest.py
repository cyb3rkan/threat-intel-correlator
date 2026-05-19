# tests/conftest.py
"""Shared fixtures."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tic.adapters.audit.hash_chain import HashChainAuditLogger
from tic.adapters.cache.sqlite_cache import SqliteCache
from tic.application.scoring import ScoringProfile
from tic.domain.finding import Finding, Severity
from tic.domain.ioc import IOC, IOCType
from tic.infra.config import PathsConfig, Settings


@pytest.fixture()
def tmp_settings(tmp_path: Path) -> Settings:
    return Settings(
        paths=PathsConfig(
            working_dir=tmp_path,
            cache_dir=tmp_path,
            audit_log_path=tmp_path / "audit.log",
        )
    )  # type: ignore[call-arg]


@pytest.fixture()
def cache(tmp_path: Path) -> SqliteCache:
    return SqliteCache(tmp_path / "tic-test.db", allowed_root=tmp_path)


@pytest.fixture()
def audit(tmp_path: Path) -> HashChainAuditLogger:
    return HashChainAuditLogger(tmp_path / "audit.log")


@pytest.fixture()
def default_profile() -> ScoringProfile:
    return ScoringProfile(version="1.0.0")


@pytest.fixture()
def make_ioc():
    def _f(value="1.2.3.4", ioc_type=IOCType.IP, source="test", confidence=80):
        return IOC(value=value, ioc_type=ioc_type, source=source, confidence=confidence)

    return _f


@pytest.fixture()
def make_finding(default_profile):
    def _f(value="evil.example.com", ioc_type=IOCType.DOMAIN, score=60, severity=Severity.MEDIUM):
        ioc = IOC(value=value, ioc_type=ioc_type, source="test")
        return Finding(
            finding_id="00000000-0000-4000-8000-000000000001",
            ioc=ioc,
            matches=[],
            enrichments=[],
            score=score,
            severity=severity,
            profile_hash=default_profile.profile_hash(),
            correlation_id="test-cid",
            created_at=datetime(2025, 1, 1, tzinfo=UTC),
        )

    return _f


@pytest.fixture()
def csv_feed_factory(tmp_path: Path):
    def _f(iocs: list[str], filename="feed.csv") -> Path:
        p = tmp_path / filename
        p.write_text("value,confidence\n" + "\n".join(f"{v},75" for v in iocs), encoding="utf-8")
        return p

    return _f


@pytest.fixture()
def ndjson_log_factory(tmp_path: Path):
    def _f(events: list[dict], filename="logs.ndjson") -> Path:
        p = tmp_path / filename
        p.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
        return p

    return _f


@pytest.fixture()
def log_with_ip(ndjson_log_factory):
    return ndjson_log_factory(
        [{"@timestamp": "2025-01-01T00:00:00Z", "src_ip": "1.2.3.4", "msg": "conn"}]
    )
