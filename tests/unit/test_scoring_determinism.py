# tests/unit/test_scoring_determinism.py
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from tic.application.scoring import ScoringInputs, ScoringProfile, compute_score
from tic.domain.finding import EnrichmentResult, Match


def _inputs() -> ScoringInputs:
    return ScoringInputs(
        ioc_confidence=80,
        matches=(
            Match(
                log_source="file.ndjson",
                field="text",
                timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
                raw_line_hash="a" * 64,
            ),
        ),
        enrichments=(
            EnrichmentResult(
                provider="abuseipdb",
                reputation_score=85,
                tags=frozenset({"TR"}),
                fetched_at=datetime(2025, 1, 2, tzinfo=timezone.utc),
                ttl_seconds=3600,
            ),
        ),
    )


def test_scoring_is_deterministic() -> None:
    profile = ScoringProfile(version="1.0.0")
    inp = _inputs()
    scores = {compute_score(inp, profile) for _ in range(1000)}
    assert len(scores) == 1


def test_profile_hash_stable() -> None:
    p1 = ScoringProfile(version="1.0.0")
    p2 = ScoringProfile(version="1.0.0")
    assert p1.profile_hash() == p2.profile_hash()


def test_profile_hash_changes_on_weight_change() -> None:
    p1 = ScoringProfile(version="1.0.0")
    p2 = p1.model_copy(update={"weights": p1.weights.model_copy(update={"recency": 0.5})})
    assert p1.profile_hash() != p2.profile_hash()