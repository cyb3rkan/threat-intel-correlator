# src/tic/domain/finding.py
"""Finding entity + privacy-safe DTOs for external output.

OutputMode controls IOC value exposure:
  ANALYST (default): full value — analysts need it for triage.
  SUMMARY: first 8 chars + "…" — safe for wider distribution.
  HASH:    HMAC-SHA256 pseudonym — compliance/public reports.
"""
from __future__ import annotations

import hmac
import hashlib
from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from tic.domain.ioc import IOC


# ---------------------------------------------------------------------------
# Output mode
# ---------------------------------------------------------------------------

class OutputMode(str):
    """IOC value exposure level in PublicFinding output."""
    ANALYST: "OutputMode"
    SUMMARY: "OutputMode"
    HASH:    "OutputMode"

OutputMode.ANALYST = OutputMode("analyst")
OutputMode.SUMMARY = OutputMode("summary")
OutputMode.HASH    = OutputMode("hash")


def _mask_ioc_value(value: str, mode: OutputMode, hmac_key: bytes | None = None) -> str:
    if mode == OutputMode.SUMMARY:
        return value[:8] + "…" if len(value) > 8 else value[:4] + "…"
    if mode == OutputMode.HASH:
        # Hash mode requires a real keyring-backed HMAC key. A silent zero-key
        # fallback would let attackers correlate IOCs across deployments, so
        # we fail closed instead. Callers must load the key from
        # `redaction_hmac_keyring_service/_user` and pass it in.
        if hmac_key is None or len(hmac_key) == 0:
            from tic.domain.errors import ConfigError
            raise ConfigError(
                "hash output_mode requires a redaction HMAC key; none provided",
                user_message=(
                    "Hash output mode requires a redaction HMAC key in the OS keyring. "
                    "Run `tic config set-key redaction-hmac` to store one (32+ random bytes), "
                    "or pick output_mode=analyst / summary."
                ),
            )
        return "hmac:" + hmac.new(hmac_key, value.encode(), hashlib.sha256).hexdigest()[:16]
    return value  # ANALYST


# ---------------------------------------------------------------------------
# Core domain types
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Match(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    log_source:    Annotated[str, StringConstraints(max_length=256)]
    field:         Annotated[str, StringConstraints(max_length=64)]
    timestamp:     datetime
    raw_line_hash: Annotated[str, StringConstraints(min_length=64, max_length=64)]


class EnrichmentResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    provider:         Annotated[str, StringConstraints(max_length=64)]
    reputation_score: int | None = Field(default=None, ge=0, le=100)
    tags:             frozenset[str] = Field(default_factory=frozenset)
    fetched_at:       datetime
    ttl_seconds:      int = Field(ge=1, le=30 * 24 * 3600)
    # truncated_raw: debug-only; never serialised to public output or cache by default.
    # Enable via TIC_DEBUG_CACHE_RAW=true for local troubleshooting only.
    truncated_raw:    Annotated[str, StringConstraints(max_length=4096)] = ""


class AINarrative(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    summary:                   Annotated[str, StringConstraints(max_length=1000)]
    false_positive_likelihood: Literal["low", "medium", "high"]
    suggested_actions:         list[Annotated[str, StringConstraints(max_length=200)]] = Field(
        default_factory=list, max_length=5
    )
    confidence:    Literal["low", "medium", "high"]
    model:         Annotated[str, StringConstraints(max_length=128)]
    generated_at:  datetime
    ai_origin:     Literal[True] = True


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    finding_id:    Annotated[str, StringConstraints(min_length=36, max_length=36)]
    ioc:           IOC
    matches:       list[Match]           = Field(default_factory=list, max_length=1000)
    enrichments:   list[EnrichmentResult] = Field(default_factory=list, max_length=16)
    score:         int   = Field(ge=0, le=100)
    severity:      Severity
    profile_hash:  Annotated[str, StringConstraints(min_length=64, max_length=64)]
    correlation_id: Annotated[str, StringConstraints(max_length=64)]
    created_at:    datetime
    ai_narrative:  AINarrative | None = None

    def to_public(
        self,
        mode: OutputMode = OutputMode.ANALYST,
        hmac_key: bytes | None = None,
    ) -> "PublicFinding":
        """Return the privacy-safe DTO. `hmac_key` is required for HASH mode."""
        return PublicFinding(
            finding_id=self.finding_id,
            ioc_type=self.ioc.ioc_type.value,
            ioc_value=_mask_ioc_value(self.ioc.value, mode, hmac_key),
            ioc_source=self.ioc.source,
            ioc_confidence=self.ioc.confidence,
            ioc_tags=sorted(self.ioc.tags),
            match_count=len(self.matches),
            enrichments=[
                PublicEnrichment(
                    provider=e.provider,
                    reputation_score=e.reputation_score,
                    tags=sorted(e.tags),
                )
                for e in self.enrichments
            ],
            score=self.score,
            severity=self.severity.value,
            profile_hash=self.profile_hash,
            correlation_id=self.correlation_id,
            created_at=self.created_at,
            ai_narrative=self.ai_narrative,
            output_mode=str(mode),
        )


# ---------------------------------------------------------------------------
# Public-safe DTOs
# ---------------------------------------------------------------------------

class PublicEnrichment(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    provider:         str
    reputation_score: int | None
    tags:             list[str]


class PublicFinding(BaseModel):
    """Privacy-safe Finding projection for all rendered output.

    Omitted vs Finding:
    - matches[*].log_source   → replaced by match_count
    - matches[*].raw_line_hash → omitted
    - enrichments[*].truncated_raw → omitted
    """
    model_config = ConfigDict(frozen=True, extra="forbid")
    finding_id:    str
    ioc_type:      str
    ioc_value:     str
    ioc_source:    str
    ioc_confidence: int
    ioc_tags:      list[str]
    match_count:   int
    enrichments:   list[PublicEnrichment]
    score:         int
    severity:      str
    profile_hash:  str
    correlation_id: str
    created_at:    datetime
    ai_narrative:  AINarrative | None = None
    output_mode:   str = "analyst"
