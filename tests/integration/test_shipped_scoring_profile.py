# tests/integration/test_shipped_scoring_profile.py
"""The shipped scoring profile YAML must load into the real ScoringProfile.

Regression guard for a defect where configs/scoring_profile.v1.yaml did not
match the ScoringProfile schema: `version` was an int (model wants str) and it
carried keys (type_weights/time_decay/source_trust/confidence_thresholds) the
model neither declared nor consumed. With extra="forbid" those stray keys now
fail loud instead of being silently dropped.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from tic.application.scoring import ScoringProfile

_REPO = Path(__file__).resolve().parents[2]
_SHIPPED_PROFILE = _REPO / "configs" / "scoring_profile.v1.yaml"


def _load(path: Path) -> ScoringProfile:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return ScoringProfile.model_validate(data)


def test_shipped_profile_exists() -> None:
    assert _SHIPPED_PROFILE.is_file(), f"missing {_SHIPPED_PROFILE}"


def test_shipped_profile_loads_into_model() -> None:
    profile = _load(_SHIPPED_PROFILE)
    assert profile.version == "1"
    # The three consumed sections are present and well-formed.
    assert 0.0 <= profile.weights.provider_reliability <= 1.0
    assert profile.severity_thresholds["critical"] >= profile.severity_thresholds["high"]


def test_shipped_profile_has_no_unknown_keys() -> None:
    """Every top-level key in the YAML is one the model actually declares."""
    data = yaml.safe_load(_SHIPPED_PROFILE.read_text(encoding="utf-8"))
    allowed = set(ScoringProfile.model_fields)
    stray = set(data) - allowed
    assert not stray, f"shipped profile carries keys the model ignores: {stray}"


def test_unknown_key_is_rejected() -> None:
    """extra='forbid' must reject a profile with an unknown field."""
    bad = {
        "version": "1",
        "type_weights": {"ip": 1.0},  # legacy key the model does not consume
    }
    with pytest.raises(ValidationError):
        ScoringProfile.model_validate(bad)


def test_int_version_is_rejected() -> None:
    """The original defect: version as int must not silently coerce."""
    with pytest.raises(ValidationError):
        ScoringProfile.model_validate({"version": 1})
