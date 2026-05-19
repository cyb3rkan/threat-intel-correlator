# src/tic/application/redaction.py
"""Redaction layer for AI inputs.

Philosophy: allowlist over blocklist. We emit only the fields AI needs and
pseudonymize identifiers via HMAC so narratives can reference consistent tokens
without leaking real values.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from tic.domain.finding import Finding
from tic.security.crypto import hmac_pseudonymize


class RedactedMatch(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    log_source_pseudo: str
    field_generic: Literal["network", "host", "user", "hash", "url", "other"]
    timestamp_iso: str


class RedactedEnrichment(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    provider: str
    reputation_score: int | None
    tag_count: int


class RedactedFinding(BaseModel):
    """Safe-to-send-to-AI view of a Finding. No raw values, no PII."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    finding_id: str
    ioc_type: str
    ioc_pseudo: str  # HMAC token of canonical value
    confidence: int
    tag_count: int
    match_count: int
    enrichments: list[RedactedEnrichment] = Field(default_factory=list, max_length=16)
    matches: list[RedactedMatch] = Field(default_factory=list, max_length=25)
    score: int
    severity: str


def _field_generic(field: str) -> Literal["network", "host", "user", "hash", "url", "other"]:
    low = field.lower()
    if any(k in low for k in ("ip", "addr", "port", "net")):
        return "network"
    if "host" in low or "dns" in low:
        return "host"
    if "user" in low or "account" in low or "email" in low:
        return "user"
    if "hash" in low or "md5" in low or "sha" in low:
        return "hash"
    if "url" in low or "uri" in low:
        return "url"
    return "other"


class Redactor:
    """Stateless redactor parameterized by an HMAC key (from keyring)."""

    def __init__(self, hmac_key: bytes) -> None:
        if len(hmac_key) < 32:
            raise ValueError("HMAC key must be at least 32 bytes")
        self._key = hmac_key

    def redact(self, f: Finding) -> RedactedFinding:
        return RedactedFinding(
            finding_id=f.finding_id,
            ioc_type=f.ioc.ioc_type.value,
            ioc_pseudo=hmac_pseudonymize(f.ioc.value, key=self._key, length=16),
            confidence=f.ioc.confidence,
            tag_count=len(f.ioc.tags),
            match_count=len(f.matches),
            enrichments=[
                RedactedEnrichment(
                    provider=e.provider,
                    reputation_score=e.reputation_score,
                    tag_count=len(e.tags),
                )
                for e in f.enrichments
            ],
            matches=[
                RedactedMatch(
                    log_source_pseudo=hmac_pseudonymize(m.log_source, key=self._key, length=12),
                    field_generic=_field_generic(m.field),
                    timestamp_iso=m.timestamp.isoformat(),
                )
                for m in f.matches[:25]
            ],
            score=f.score,
            severity=f.severity.value,
        )
