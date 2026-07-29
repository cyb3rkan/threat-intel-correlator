# src/tic/domain/scoring_profile.py
"""Scoring profile domain model.

Re-exported from application layer for backward compatibility. The canonical
definition currently lives in `tic.application.scoring` to avoid churn in
existing imports and tests. New code may import from either location; this
module is the preferred path for domain consumers.

Design note: `ScoringProfile` is a pure value object (frozen semantics via
pydantic defaults + explicit hashing). It must remain free of I/O and of any
dependency on infrastructure.
"""

from __future__ import annotations

from tic.application.scoring import ScoringProfile, ScoringWeights

__all__ = ["ScoringProfile", "ScoringWeights"]
