"""Sweep orchestrator.

Fixes:
- concurrent enrichment ACROSS IOCs via asyncio.gather, bounded by one global
  asyncio.Semaphore(provider_concurrency) shared by every provider call (#5)
- optional overall sweep deadline: when it elapses, IOCs still being enriched
  are returned without enrichment (partial-but-valid) and the sweep is flagged
- deterministic output: gather preserves input order (not completion order),
  and findings are sorted by the existing deterministic key, so the rendered
  result is identical regardless of which provider/IOC finishes first
- audit appends are serialised with an asyncio.Lock so Part-2's chained-HMAC
  audit chain cannot race under concurrent enrichment
- matches_by_ioc bounded per IOC (max_matches_per_ioc)

Phase B: `sweep_end` audit payload carries a metadata-only count of findings
annotated by AI (`ai_narratives_generated`).

Phase C: AI invocation is bounded by `ai_max_findings_per_sweep`. We select the
top-N findings deterministically (severity desc, score desc, provider count
desc, match count desc, finding_id asc) and only invoke the narrator on those.
The remaining findings still appear with `ai_narrative=null`. Selection happens
BEFORE narration so score/severity/enrichments/exit_code/above_threshold are
unchanged regardless of the cap.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any, TextIO

from tic.application.correlation import Correlator, LogLine
from tic.application.scoring import ScoringInputs, ScoringProfile, compute_score
from tic.domain.finding import Finding, Match, Severity
from tic.domain.ioc import IOC
from tic.infra.exit_codes import ExitCode
from tic.infra.logging import get_logger, new_correlation_id
from tic.ports.audit_logger import AuditLogger
from tic.ports.enrichment_provider import EnrichmentProvider

_log = get_logger(__name__)
_DEFAULT_MAX_MATCHES = 500
_DEFAULT_CONCURRENCY = 4
_DEFAULT_AI_CAP = 25


def _ai_selection_key(f: Finding) -> tuple[int | str, ...]:
    """Deterministic ranking key for top-N AI selection.

    Sort order (descending priority first):
      severity rank down, score down, provider count down, match count down,
      finding_id up (stable tie-break).

    `sorted(..., key=...)` is ascending by default, so we negate the "down"
    terms and use the bare `finding_id` for the "up" tail.
    """
    return (
        -f.severity.rank,
        -f.score,
        -len(f.enrichments),
        -len(f.matches),
        f.finding_id,
    )


class SweepOrchestrator:
    def __init__(
        self,
        *,
        providers: list[EnrichmentProvider],
        narrator: object | None = None,
        profile: ScoringProfile,
        audit: AuditLogger,
        min_severity_exit: Severity = Severity.HIGH,
        max_matches_per_ioc: int = _DEFAULT_MAX_MATCHES,
        provider_concurrency: int = _DEFAULT_CONCURRENCY,
        ai_max_findings_per_sweep: int = _DEFAULT_AI_CAP,
        sweep_deadline_seconds: float | None = None,
    ) -> None:
        self._providers = providers
        self._narrator = narrator
        self._profile = profile
        self._audit = audit
        self._min_sev = min_severity_exit
        self._max_matches = max_matches_per_ioc
        # One global semaphore bounds ALL in-flight provider calls (across every
        # IOC and provider), not just the calls for a single IOC.
        self._sem = asyncio.Semaphore(max(1, provider_concurrency))
        # Phase C: AI invocation cap. Clamped to [1, 100] at AIConfig level;
        # re-clamped here for defensive callers that bypass AIConfig.
        self._ai_cap = max(1, min(100, int(ai_max_findings_per_sweep)))
        # Optional overall budget (seconds). None -> no deadline (still
        # concurrent). The budget is measured from the start of run().
        self._deadline = sweep_deadline_seconds
        # Serialises audit appends. append() is itself synchronous (atomic
        # within the single-threaded event loop), but this lock makes the
        # ordering guarantee for Part-2's chained HMAC explicit and keeps it
        # correct even if an append ever moves into the concurrent path.
        self._audit_lock = asyncio.Lock()

    async def _audit_append(self, event_type: str, payload: dict[str, Any]) -> None:
        async with self._audit_lock:
            self._audit.append(event_type, payload)

    async def _enrich_one(self, provider: EnrichmentProvider, ioc: IOC) -> Any:
        async with self._sem:
            try:
                return await provider.enrich(ioc)
            except Exception as e:  # noqa: BLE001
                _log.warning("provider_error", provider=provider.name, error=type(e).__name__)
                return None

    async def _enrich_ioc(self, ioc: IOC) -> list[Any]:
        results = await asyncio.gather(*[self._enrich_one(p, ioc) for p in self._providers])
        return [r for r in results if r is not None]

    async def _gather_enrichments(
        self, matched_iocs: list[IOC], deadline_at: float | None
    ) -> tuple[list[list[Any]], int]:
        """Enrich all matched IOCs concurrently; return (enrichments, unenriched).

        Results are returned in `matched_iocs` order regardless of completion
        order (asyncio.gather/asyncio.wait do not reorder the task list we
        iterate), so the findings stay deterministic. When `deadline_at` is set
        and reached, tasks that have not finished are cancelled and their IOCs
        come back with an empty enrichment list (partial-but-valid).
        """
        if not matched_iocs:
            return [], 0
        tasks = [asyncio.ensure_future(self._enrich_ioc(ioc)) for ioc in matched_iocs]

        if deadline_at is None:
            results = await asyncio.gather(*tasks)
            return list(results), 0

        remaining = max(0.0, deadline_at - asyncio.get_running_loop().time())
        done, pending = await asyncio.wait(tasks, timeout=remaining)
        for t in pending:
            t.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

        enrichments: list[list[Any]] = []
        for t in tasks:  # preserves matched_iocs order
            if t in done and not t.cancelled():
                enrichments.append(t.result())
            else:
                enrichments.append([])
        return enrichments, len(pending)

    async def run(
        self,
        *,
        iocs: Iterable[IOC],
        log_lines: Iterable[LogLine],
        out: TextIO,
        render_fn: Callable[[list[Finding], TextIO], int],
    ) -> ExitCode:
        loop = asyncio.get_running_loop()
        deadline_at = loop.time() + self._deadline if self._deadline is not None else None

        cid = new_correlation_id()
        await self._audit_append(
            "sweep_start", {"correlation_id": cid, "profile_hash": self._profile.profile_hash()}
        )

        # Materialise once; max_iocs_per_feed enforced by parsers upstream.
        ioc_list = list(iocs)
        _log.info("sweep_inputs_loaded", ioc_count=len(ioc_list))

        correlator = Correlator(ioc_list)
        matches_by_ioc: dict[tuple[str, str], list[Match]] = {}
        overflow: dict[tuple[str, str], int] = {}

        for ioc, match in correlator.iter_matches(log_lines):
            key = (ioc.ioc_type.value, ioc.value)
            bucket = matches_by_ioc.setdefault(key, [])
            if len(bucket) >= self._max_matches:
                overflow[key] = overflow.get(key, 0) + 1
            else:
                bucket.append(match)

        if overflow:
            _log.warning("match_overflow", ioc_count=len(overflow), cap=self._max_matches)

        # IOCs that produced at least one match, in input order (deterministic).
        matched_iocs = [
            ioc for ioc in ioc_list if matches_by_ioc.get((ioc.ioc_type.value, ioc.value))
        ]

        # Concurrent enrichment across IOCs, bounded by the global semaphore,
        # under the optional overall deadline.
        enrichments_per_ioc, unenriched = await self._gather_enrichments(
            matched_iocs, deadline_at
        )
        if unenriched:
            _log.warning(
                "sweep_deadline_exceeded",
                unenriched_iocs=unenriched,
                deadline_seconds=self._deadline,
            )

        # Phase C: produce all Finding objects WITHOUT AI first. This keeps
        # severity/score/enrichments/exit_code deterministic regardless of
        # whether AI runs.
        findings: list[Finding] = []
        above_threshold = False

        for ioc, enrichments in zip(matched_iocs, enrichments_per_ioc, strict=True):
            matches = matches_by_ioc[(ioc.ioc_type.value, ioc.value)]
            score = compute_score(
                ScoringInputs(
                    ioc_confidence=ioc.confidence,
                    matches=tuple(matches),
                    enrichments=tuple(enrichments),
                ),
                self._profile,
            )
            severity = self._profile.severity_for_score(score)

            finding = Finding(
                finding_id=str(uuid.uuid4()),
                ioc=ioc,
                matches=matches[:1000],
                enrichments=enrichments[:16],
                score=score,
                severity=severity,
                profile_hash=self._profile.profile_hash(),
                correlation_id=cid,
                created_at=datetime.now(UTC),
            )

            findings.append(finding)
            if finding.severity.rank >= self._min_sev.rank:
                above_threshold = True

        # Phase C: deterministic AI selection over the Finding objects above.
        ai_skipped_due_to_cap = 0
        if self._narrator is not None and findings:
            ranked = sorted(findings, key=_ai_selection_key)
            top = ranked[: self._ai_cap]
            top_ids = {f.finding_id for f in top}
            ai_skipped_due_to_cap = max(0, len(findings) - len(top))

            updated: list[Finding] = []
            for f in findings:
                narrated = f
                if f.finding_id in top_ids:
                    try:
                        narrated = await self._narrator.narrate(f)  # type: ignore[attr-defined]
                    except Exception as e:  # noqa: BLE001
                        _log.warning("narrator_error", error=type(e).__name__)
                updated.append(narrated)
            findings = updated

        findings.sort(key=lambda f: (-f.severity.rank, -f.score, f.ioc.value))
        count = render_fn(findings, out)

        # Phase B: metadata-only count of AI narratives attached to this sweep.
        ai_count = sum(1 for f in findings if f.ai_narrative is not None)

        await self._audit_append(
            "sweep_end",
            {
                "correlation_id": cid,
                "findings": count,
                "above_threshold": above_threshold,
                "ai_narratives_generated": ai_count,
                # Phase C: metadata-only count of findings eligible for AI but
                # skipped due to the per-sweep cap.
                "ai_narration_skipped_due_to_cap": int(ai_skipped_due_to_cap),
                # Performance phase: partial-but-valid marker. True when the
                # overall sweep deadline elapsed and some IOCs were returned
                # without enrichment.
                "enrichment_deadline_exceeded": unenriched > 0,
                "unenriched_due_to_deadline": int(unenriched),
            },
        )
        return ExitCode.FINDINGS_ABOVE_THRESHOLD if above_threshold else ExitCode.SUCCESS
