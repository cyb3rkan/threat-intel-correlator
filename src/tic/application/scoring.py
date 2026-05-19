# src/tic/application/scoring.py
"""Deterministic scoring engine. Pure function, no I/O, no side effects.

Determinism guarantee: for given (finding inputs, scoring_profile), the output
(score, severity) is identical across all runs, processes, and machines.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from pydantic import BaseModel, Field

from tic.domain.finding import EnrichmentResult, Match, Severity


class ScoringWeights(BaseModel):
    provider_reliability: float = Field(default=0.25, ge=0.0, le=1.0)
    ioc_confidence: float = Field(default=0.25, ge=0.0, le=1.0)
    match_count: float = Field(default=0.20, ge=0.0, le=1.0)
    recency: float = Field(default=0.15, ge=0.0, le=1.0)
    reputation_vote: float = Field(default=0.15, ge=0.0, le=1.0)


class ScoringProfile(BaseModel):
    """Immutable scoring profile, version-tracked."""

    version: str
    weights: ScoringWeights = ScoringWeights()
    severity_thresholds: dict[str, int] = Field(
        default_factory=lambda: {
            "info": 0,
            "low": 20,
            "medium": 40,
            "high": 70,
            "critical": 90,
        }
    )

    def canonical_json(self) -> str:
        """Deterministic JSON serialization for hashing."""
        return json.dumps(self.model_dump(), sort_keys=True, separators=(",", ":"))

    def profile_hash(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    def severity_for_score(self, score: int) -> Severity:
        # Deterministic: pick highest threshold ≤ score.
        chosen = Severity.INFO
        for name in ("info", "low", "medium", "high", "critical"):
            threshold = self.severity_thresholds.get(name, 0)
            if score >= threshold:
                chosen = Severity(name)
        return chosen


@dataclass(frozen=True)
class ScoringInputs:
    ioc_confidence: int  # 0..100
    matches: tuple[Match, ...]
    enrichments: tuple[EnrichmentResult, ...]


def compute_score(inputs: ScoringInputs, profile: ScoringProfile) -> int:
    """Compute a 0..100 integer score. Pure and deterministic."""
    w = profile.weights

    # Provider reliability: treat presence of enrichment as +reliability per provider.
    provider_factor = min(1.0, len(inputs.enrichments) / 3.0)  # 3+ providers = full
    confidence_factor = inputs.ioc_confidence / 100.0
    match_factor = min(1.0, len(inputs.matches) / 10.0)  # 10+ matches = full

    # Recency: use the most recent match timestamp relative to enrichment times.
    # Stable, integer-based factor (no wall clock).
    if inputs.matches and inputs.enrichments:
        most_recent_match = max(m.timestamp for m in inputs.matches).timestamp()
        earliest_enrich = min(e.fetched_at for e in inputs.enrichments).timestamp()
        delta_days = abs(most_recent_match - earliest_enrich) / 86400.0
        # within 7 days -> 1.0; decays to 0 at 90 days
        recency_factor = max(0.0, 1.0 - max(0.0, (delta_days - 7.0)) / 83.0)
    else:
        recency_factor = 0.5

    # Reputation vote: average enrichment reputation_score / 100.
    rep_scores = [e.reputation_score for e in inputs.enrichments if e.reputation_score is not None]
    reputation_factor = (sum(rep_scores) / len(rep_scores) / 100.0) if rep_scores else 0.0

    weighted = (
        w.provider_reliability * provider_factor
        + w.ioc_confidence * confidence_factor
        + w.match_count * match_factor
        + w.recency * recency_factor
        + w.reputation_vote * reputation_factor
    )

    # Weights may not sum exactly to 1; normalize against actual sum for stability.
    weight_sum = (
        w.provider_reliability
        + w.ioc_confidence
        + w.match_count
        + w.recency
        + w.reputation_vote
    )
    normalized = (weighted / weight_sum) if weight_sum > 0 else 0.0

    # Round half-to-even for determinism (banker's rounding; Python default).
    return max(0, min(100, int(round(normalized * 100.0))))