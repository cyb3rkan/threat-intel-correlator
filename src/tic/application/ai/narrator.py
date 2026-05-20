"""Narrator: redaction -> truncation -> AI provider -> validated narrative.

Phase B introduced optional, metadata-only audit hooks. Phase C adds:
  - input truncation between redaction and AI invocation, with a metadata-
    only `ai_input_truncated` audit event when truncation fires.
  - opt-in invocation-latency observability (`latency_ms`) recorded on the
    `ai_invoke` audit event. Still no prompt, completion, header, or key.

The Narrator never audits:
- prompt body
- completion / response body
- API key or Authorization header
- raw IOC values (it only sees the RedactedFinding)
- raw provider response

Allowed audit event types (closed set):
  - `ai_invoke`              payload: {finding_id, latency_ms?}
  - `ai_input_truncated`     payload: {finding_id, original_chars,
                                       final_chars, dropped_matches_count,
                                       dropped_enrichments_count}
  - `ai_response_rejected`   payload: {finding_id, reason} where reason ∈
                                       {schema, timeout, non_2xx, filtered,
                                        invalid_json, provider_error,
                                        redaction_failed, input_too_large}
  - `ai_narrative_attached`  payload: {finding_id}

Audit-write failures are isolated — the sweep continues.
"""

from __future__ import annotations

import time
from typing import Any, Literal

from tic.application.ai.prompt_builder import _truncate_redacted
from tic.application.redaction import RedactedFinding, Redactor
from tic.domain.finding import Finding
from tic.infra.logging import get_logger
from tic.ports.ai_provider import AIProvider
from tic.ports.audit_logger import AuditLogger

_log = get_logger(__name__)

# Closed set of audit reason strings. Defined here so a typo at a call site
# is caught by mypy / runtime and so the documented contract has a single
# authoritative source.
AIRejectionReason = Literal[
    "schema",
    "timeout",
    "non_2xx",
    "filtered",
    "invalid_json",
    "provider_error",
    "redaction_failed",
    "input_too_large",
]


class Narrator:
    """Handles redaction, truncation, and failure isolation around AIProvider.

    `audit` is optional and backward-compatible. `max_input_chars` is the
    truncation deadline applied to the redacted payload BEFORE handing it
    to the provider. Pre-Phase-C callers that don't pass it keep working;
    the default mirrors the AIConfig.max_input_chars default.
    """

    def __init__(
        self,
        ai: AIProvider,
        redactor: Redactor,
        *,
        audit: AuditLogger | None = None,
        max_input_chars: int = 8000,
    ) -> None:
        self._ai = ai
        self._redactor = redactor
        self._audit = audit
        self._max_input_chars = int(max_input_chars)

    # ------------------------------------------------------------------
    # Audit helpers — all metadata-only and isolated from sweep failure.
    # ------------------------------------------------------------------

    def _safe_audit(self, event_type: str, payload: dict[str, Any]) -> None:
        """Append an audit event; never raise. A failing audit sink must
        not break the sweep — we drop to a structlog warning and move on.

        Note: structlog reserves the `event` keyword for the log message
        name, so we surface the audit event name as `audit_event` to
        avoid a kwargs collision.
        """
        if self._audit is None:
            return
        try:
            self._audit.append(event_type, payload)
        except Exception as e:  # noqa: BLE001 — audit must never raise upstream
            _log.warning(
                "ai_audit_append_failed",
                audit_event=event_type,
                error=type(e).__name__,
            )

    def _audit_invoke(self, finding_id: str, *, latency_ms: int | None = None) -> None:
        payload: dict[str, Any] = {"finding_id": finding_id}
        if latency_ms is not None:
            payload["latency_ms"] = int(latency_ms)
        self._safe_audit("ai_invoke", payload)

    def _audit_rejected(self, finding_id: str, reason: AIRejectionReason) -> None:
        self._safe_audit(
            "ai_response_rejected",
            {"finding_id": finding_id, "reason": reason},
        )

    def _audit_attached(self, finding_id: str) -> None:
        self._safe_audit("ai_narrative_attached", {"finding_id": finding_id})

    def _audit_truncated(self, finding_id: str, meta: dict[str, int]) -> None:
        # Defensive copy + injected finding_id; the meta dict from the
        # prompt_builder only carries counts, never raw content.
        payload: dict[str, Any] = {"finding_id": finding_id}
        payload.update({k: int(v) for k, v in meta.items()})
        self._safe_audit("ai_input_truncated", payload)

    # ------------------------------------------------------------------
    # Truncation
    # ------------------------------------------------------------------

    def _prepare_payload(
        self, redacted: RedactedFinding, finding_id: str
    ) -> RedactedFinding | None:
        """Truncate `matches` then `enrichments` if the JSON would exceed
        `max_input_chars`. Returns the (possibly shorter) RedactedFinding,
        or None if the payload is still too large after truncation."""
        new, meta = _truncate_redacted(redacted, max_chars=self._max_input_chars)
        if meta["dropped_matches_count"] or meta["dropped_enrichments_count"]:
            self._audit_truncated(finding_id, meta)
        if meta["final_chars"] > self._max_input_chars:
            # Even after dropping everything droppable, the required-fields
            # core is too large. This is a degenerate input — fail closed.
            return None
        return new

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def narrate(self, finding: Finding) -> Finding:
        """Return Finding with AINarrative, or original on failure. Never raises."""
        # Redaction must not fail in normal operation, but if it does the
        # sweep continues and we audit the reason. We do not log the
        # exception message — type only — because the input is partly
        # attacker-controlled.
        try:
            redacted = self._redactor.redact(finding)
        except Exception as e:  # noqa: BLE001
            _log.warning(
                "narrator_redaction_failed",
                finding_id=finding.finding_id,
                error=type(e).__name__,
            )
            self._audit_rejected(finding.finding_id, "redaction_failed")
            return finding

        prepared = self._prepare_payload(redacted, finding.finding_id)
        if prepared is None:
            _log.warning(
                "ai_input_too_large_after_truncation",
                finding_id=finding.finding_id,
            )
            self._audit_rejected(finding.finding_id, "input_too_large")
            return finding

        # Latency observability (metadata-only). We measure wall-clock
        # around the provider call only — redaction and truncation are
        # excluded so the recorded number reflects the AI round-trip,
        # which is the actionable signal for cost/SLA dashboards.
        start_ns = time.monotonic_ns()
        try:
            narrative = await self._ai.narrate(prepared)  # type: ignore[arg-type]
        except TimeoutError as e:
            elapsed_ms = (time.monotonic_ns() - start_ns) // 1_000_000
            _log.warning(
                "narrator_ai_call_failed",
                finding_id=finding.finding_id,
                error=type(e).__name__,
                latency_ms=int(elapsed_ms),
            )
            self._audit_invoke(finding.finding_id, latency_ms=int(elapsed_ms))
            self._audit_rejected(finding.finding_id, "timeout")
            return finding
        except Exception as e:  # noqa: BLE001
            elapsed_ms = (time.monotonic_ns() - start_ns) // 1_000_000
            _log.warning(
                "narrator_ai_call_failed",
                finding_id=finding.finding_id,
                error=type(e).__name__,
                latency_ms=int(elapsed_ms),
            )
            self._audit_invoke(finding.finding_id, latency_ms=int(elapsed_ms))
            self._audit_rejected(finding.finding_id, "provider_error")
            return finding

        elapsed_ms = (time.monotonic_ns() - start_ns) // 1_000_000
        self._audit_invoke(finding.finding_id, latency_ms=int(elapsed_ms))

        if narrative is None:
            # The provider returned None — could be schema violation, non-2xx,
            # invalid JSON, or a filtered response. The provider has already
            # logged the precise reason at structlog level; we record a
            # coarse audit reason here so the tamper-evident chain reflects
            # that an invocation did not produce a narrative.
            self._audit_rejected(finding.finding_id, "schema")
            return finding

        self._audit_attached(finding.finding_id)
        return finding.model_copy(update={"ai_narrative": narrative})