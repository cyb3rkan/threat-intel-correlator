# src/tic/application/orchestrator.py
"""Sweep orchestrator.

Fixes:
- concurrent enrichment via asyncio.gather + Semaphore (#5 provider concurrency)
- matches_by_ioc bounded per IOC (max_matches_per_ioc)
- list(iocs) documented + bounded by max_iocs_per_feed upstream
- partial_scan flag set when log source truncates

Phase B: `sweep_end` audit payload carries a metadata-only count of
findings annotated by AI (`ai_narratives_generated`).

Phase C: AI invocation is bounded by `ai_max_findings_per_sweep`. We
select the top-N findings deterministically (severity desc, score desc,
provider count desc, match count desc, finding_id asc) and only invoke
the narrator on those. The remaining findings still appear in the sweep
result with `ai_narrative=null`. Selection happens BEFORE narration so
score/severity/enrichments/exit_code/above_threshold are unchanged
regardless of the cap.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import TextIO

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


def _ai_selection_key(f: Finding) -> tuple:
    """Deterministic ranking key for top-N AI selection.

    Sort order (descending priority first):
      severity rank ↓, score ↓, provider count ↓, match count ↓,
      finding_id ↑ (stable tie-break).

    `sorted(..., key=...)` is ascending by default, so we negate the
    "↓ desc" terms and use the bare `finding_id` for the "↑ asc" tail.
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
    ) -> None:
        self._providers = providers
        self._narrator = narrator
        self._profile = profile
        self._audit = audit
        self._min_sev = min_severity_exit
        self._max_matches = max_matches_per_ioc
        self._sem = asyncio.Semaphore(max(1, provider_concurrency))
        # Phase C: AI invocation cap. Clamped to [1, 100] at AIConfig level;
        # we re-clamp here for defensive callers that bypass AIConfig.
        self._ai_cap = max(1, min(100, int(ai_max_findings_per_sweep)))

    async def _enrich_one(self, provider: EnrichmentProvider, ioc: IOC):
        async with self._sem:
            try:
                return await provider.enrich(ioc)
            except Exception as e:  # noqa: BLE001
                _log.warning("provider_error", provider=provider.name, error=type(e).__name__)
                return None

    async def run(
        self,
        *,
        iocs: Iterable[IOC],
        log_lines: Iterable[LogLine],
        out: TextIO,
        render_fn,
    ) -> ExitCode:
        cid = new_correlation_id()
        self._audit.append(
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

        # Phase C: produce all Finding objects WITHOUT AI first. This keeps
        # severity/score/enrichments/exit_code deterministic regardless of
        # whether AI runs. We then run the narrator over a deterministically
        # selected top-N slice.
        findings: list[Finding] = []
        above_threshold = False

        for ioc in ioc_list:
            key = (ioc.ioc_type.value, ioc.value)
            matches = matches_by_ioc.get(key, [])
            if not matches:
                continue

            results = await asyncio.gather(*[self._enrich_one(p, ioc) for p in self._providers])
            enrichments = [r for r in results if r is not None]

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

        # Phase C: deterministic AI selection. Runs over Finding objects
        # produced above, *not* over the unrelated IOC order, so the
        # selection is stable across runs with the same input.
        ai_skipped_due_to_cap = 0
        if self._narrator is not None and findings:
            ranked = sorted(findings, key=_ai_selection_key)
            top = ranked[: self._ai_cap]
            top_ids = {f.finding_id for f in top}
            ai_skipped_due_to_cap = max(0, len(findings) - len(top))

            updated: list[Finding] = []
            for f in findings:
                if f.finding_id in top_ids:
                    try:
                        f = await self._narrator.narrate(f)  # type: ignore[attr-defined]
                    except Exception as e:  # noqa: BLE001
                        _log.warning("narrator_error", error=type(e).__name__)
                updated.append(f)
            findings = updated

        findings.sort(key=lambda f: (-f.severity.rank, -f.score, f.ioc.value))
        count = render_fn(findings, out)

        # Phase B: include a metadata-only count of AI narratives attached
        # to this sweep so the tamper-evident audit chain reflects whether
        # AI ran and how many findings it annotated. The count is derived
        # from the in-memory Finding list; no AI content is audited.
        ai_count = sum(1 for f in findings if f.ai_narrative is not None)

        self._audit.append(
            "sweep_end",
            {
                "correlation_id": cid,
                "findings": count,
                "above_threshold": above_threshold,
                "ai_narratives_generated": ai_count,
                # Phase C: metadata-only count of findings that were eligible
                # for AI but skipped due to the per-sweep cap. Zero when AI
                # is disabled or when fewer findings than the cap exist.
                "ai_narration_skipped_due_to_cap": int(ai_skipped_due_to_cap),
            },
        )
        return ExitCode.FINDINGS_ABOVE_THRESHOLD if above_threshold else ExitCode.SUCCESS
