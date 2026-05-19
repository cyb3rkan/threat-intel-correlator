# tests/unit/test_scoring_profile_reexport.py
"""Ensure domain re-export of ScoringProfile stays identical to canonical."""
from __future__ import annotations

from tic.application.scoring import ScoringProfile as AppProfile
from tic.application.scoring import ScoringWeights as AppWeights
from tic.domain.scoring_profile import ScoringProfile as DomainProfile
from tic.domain.scoring_profile import ScoringWeights as DomainWeights


def test_re_export_identity() -> None:
    assert DomainProfile is AppProfile
    assert DomainWeights is AppWeights
