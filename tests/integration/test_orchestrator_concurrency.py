# tests/integration/test_orchestrator_concurrency.py
"""Part 3: concurrent enrichment, sweep deadline, deterministic output, and
audit-chain + cache safety under concurrency."""
from __future__ import annotations

import asyncio
import io
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

from tic.adapters.audit.hash_chain import HashChainAuditLogger
from tic.adapters.cache.sqlite_cache import SqliteCache
from tic.application.correlation import LogLine
from tic.application.normalization import make_ioc
from tic.application.orchestrator import SweepOrchestrator
from tic.application.scoring import ScoringProfile
from tic.domain.finding import EnrichmentResult, Finding

KEY = b"audit-key-audit-key-audit-key-32"


def _profile() -> ScoringProfile:
    return ScoringProfile(version="1.0.0")


def _ts() -> datetime:
    return datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)


def _enrichment(provider: str) -> EnrichmentResult:
    return EnrichmentResult(
        provider=provider,
        reputation_score=80,
        tags=frozenset({"malware"}),
        fetched_at=_ts(),
        ttl_seconds=3600,
    )


class _NullAudit:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def append(self, event_type: str, payload: dict) -> None:
        self.events.append((event_type, dict(payload)))


class _Provider:
    """Enrichment provider with a configurable (optionally per-IOC) delay."""

    def __init__(self, name: str, *, delay: float = 0.0, delay_fn=None) -> None:
        self.name = name
        self._delay = delay
        self._delay_fn = delay_fn

    async def enrich(self, ioc):
        d = self._delay_fn(ioc) if self._delay_fn is not None else self._delay
        if d:
            await asyncio.sleep(d)
        return _enrichment(self.name)


class _AuditingNarrator:
    """Narrator that appends an audit event per narration (sequential phase)."""

    def __init__(self, audit) -> None:
        self._audit = audit

    async def narrate(self, finding: Finding) -> Finding:
        self._audit.append("ai_invoke", {"finding_id": finding.finding_id})
        return finding


class _Out(io.StringIO):
    collected: list[Finding] = []


def _render(findings, out) -> int:
    out.collected = list(findings)
    return len(findings)


def _last_octet(ioc) -> int:
    return int(ioc.value.split(".")[-1])


def _iocs_logs(n: int):
    iocs = [make_ioc(f"1.2.3.{i}", source="test", confidence=50 + (i % 40)) for i in range(n)]
    logs = [LogLine(source="fw", timestamp=_ts(), text=f"blocked 1.2.3.{i}") for i in range(n)]
    return iocs, logs


def _run(orch: SweepOrchestrator, iocs, logs):
    out = _Out()
    code = asyncio.run(orch.run(iocs=iocs, log_lines=logs, out=out, render_fn=_render))
    return out.collected, code


def _projection(findings):
    return [
        (
            f.ioc.ioc_type.value,
            f.ioc.value,
            f.score,
            f.severity.value,
            tuple(sorted(e.provider for e in f.enrichments)),
        )
        for f in findings
    ]


# ---------------------------------------------------------------------------
# (a) determinism: output independent of completion order
# ---------------------------------------------------------------------------


def test_output_is_deterministic_regardless_of_completion_order() -> None:
    iocs, logs = _iocs_logs(12)
    # Forward vs reverse per-IOC delays produce opposite completion orders.
    fwd = _Provider("p", delay_fn=lambda ioc: _last_octet(ioc) * 0.005)
    rev = _Provider("p", delay_fn=lambda ioc: (12 - _last_octet(ioc)) * 0.005)

    o1 = SweepOrchestrator(
        providers=[fwd], profile=_profile(), audit=_NullAudit(), provider_concurrency=12
    )
    o2 = SweepOrchestrator(
        providers=[rev], profile=_profile(), audit=_NullAudit(), provider_concurrency=12
    )
    f1, _ = _run(o1, iocs, logs)
    f2, _ = _run(o2, iocs, logs)

    assert _projection(f1) == _projection(f2)
    assert len(f1) == 12


def test_sequential_concurrency_one_still_deterministic() -> None:
    # provider_concurrency=1 forces serial provider calls; output must match
    # the highly-concurrent run byte-for-byte (modulo finding_id/created_at).
    iocs, logs = _iocs_logs(8)
    serial = SweepOrchestrator(
        providers=[_Provider("p")], profile=_profile(), audit=_NullAudit(),
        provider_concurrency=1,
    )
    parallel = SweepOrchestrator(
        providers=[_Provider("p")], profile=_profile(), audit=_NullAudit(),
        provider_concurrency=16,
    )
    f1, _ = _run(serial, iocs, logs)
    f2, _ = _run(parallel, iocs, logs)
    assert _projection(f1) == _projection(f2)


# ---------------------------------------------------------------------------
# (b) concurrency proof: wall-clock far below the sequential bound
# ---------------------------------------------------------------------------


def test_concurrent_enrichment_beats_sequential_wallclock() -> None:
    iocs, logs = _iocs_logs(10)
    prov = _Provider("p", delay=0.05)  # each enrich sleeps 50ms
    orch = SweepOrchestrator(
        providers=[prov], profile=_profile(), audit=_NullAudit(), provider_concurrency=20
    )
    t0 = time.perf_counter()
    findings, _ = _run(orch, iocs, logs)
    elapsed = time.perf_counter() - t0
    assert len(findings) == 10
    # Sequential lower bound is 10 * 0.05 = 0.50s; concurrent is ~0.05s.
    assert elapsed < 0.30


# ---------------------------------------------------------------------------
# (c) deadline: partial-but-valid result
# ---------------------------------------------------------------------------


def test_deadline_exceeded_yields_partial_but_valid_result() -> None:
    iocs, logs = _iocs_logs(6)
    slow = _Provider("p", delay=5.0)  # far beyond the deadline
    audit = _NullAudit()
    orch = SweepOrchestrator(
        providers=[slow], profile=_profile(), audit=audit,
        provider_concurrency=6, sweep_deadline_seconds=0.1,
    )
    t0 = time.perf_counter()
    findings, code = _run(orch, iocs, logs)
    elapsed = time.perf_counter() - t0

    assert elapsed < 1.5  # the deadline cut enrichment short, not 5s
    assert len(findings) == 6  # findings still produced
    assert all(f.enrichments == [] for f in findings)  # un-enriched but valid
    end = next(p for (e, p) in audit.events if e == "sweep_end")
    assert end["enrichment_deadline_exceeded"] is True
    assert end["unenriched_due_to_deadline"] == 6


def test_no_deadline_enriches_everything() -> None:
    iocs, logs = _iocs_logs(5)
    audit = _NullAudit()
    orch = SweepOrchestrator(
        providers=[_Provider("p")], profile=_profile(), audit=audit, provider_concurrency=8
    )
    findings, _ = _run(orch, iocs, logs)
    assert all(len(f.enrichments) == 1 for f in findings)
    end = next(p for (e, p) in audit.events if e == "sweep_end")
    assert end["enrichment_deadline_exceeded"] is False
    assert end["unenriched_due_to_deadline"] == 0


# ---------------------------------------------------------------------------
# (d) audit chain safety under concurrency (Part-2 interaction)
# ---------------------------------------------------------------------------


def test_audit_chain_survives_many_concurrent_appends(tmp_path: Path) -> None:
    log = tmp_path / "a.log"
    logger = HashChainAuditLogger(log, signing_key=KEY)
    orch = SweepOrchestrator(providers=[], profile=_profile(), audit=logger)

    async def _hammer() -> None:
        await asyncio.gather(*[orch._audit_append("evt", {"i": i}) for i in range(50)])  # noqa: SLF001

    asyncio.run(_hammer())
    assert HashChainAuditLogger(log, signing_key=KEY).verify_chain() is True


def test_audit_chain_valid_after_concurrent_signed_sweep(tmp_path: Path) -> None:
    log = tmp_path / "a.log"
    logger = HashChainAuditLogger(log, signing_key=KEY)
    iocs, logs = _iocs_logs(8)
    orch = SweepOrchestrator(
        providers=[_Provider("p", delay=0.02)],
        narrator=_AuditingNarrator(logger),
        profile=_profile(),
        audit=logger,
        provider_concurrency=8,
    )
    findings, _ = _run(orch, iocs, logs)
    assert len(findings) == 8
    assert HashChainAuditLogger(log, signing_key=KEY).verify_chain() is True


# ---------------------------------------------------------------------------
# cache concurrency safety (SQLite) — regression guard
# ---------------------------------------------------------------------------


def test_sqlite_cache_safe_under_concurrent_threads(tmp_path: Path) -> None:
    cache = SqliteCache(tmp_path / "c.db", allowed_root=tmp_path)

    def work(i: int) -> bytes | None:
        cache.set("ns", f"k{i}", str(i).encode(), 3600)
        return cache.get("ns", f"k{i}")

    with ThreadPoolExecutor(max_workers=16) as ex:
        results = list(ex.map(work, range(200)))
    assert all(results[i] == str(i).encode() for i in range(200))
    cache.close()
