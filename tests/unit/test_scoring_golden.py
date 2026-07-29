# tests/unit/test_scoring_golden.py
"""Golden regression lock for the deterministic scoring engine.

`compute_score` + `severity_for_score` must be identical across runs, processes
and machines for a fixed (inputs, profile). This test builds a fixed set of
ScoringInputs scenarios, scores them with the SHIPPED profile, and asserts the
results match tests/fixtures/scoring/golden_scores.json byte-for-value.

To regenerate the golden file after an intentional scoring change, run:
    python tests/unit/test_scoring_golden.py --write
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import yaml

from tic.application.scoring import (
    ScoringInputs,
    ScoringProfile,
    compute_score,
)
from tic.domain.finding import EnrichmentResult, Match

_REPO = Path(__file__).resolve().parents[2]
_GOLDEN = _REPO / "tests" / "fixtures" / "scoring" / "golden_scores.json"
_SHIPPED_PROFILE = _REPO / "configs" / "scoring_profile.v1.yaml"

# A syntactically valid 64-char sha256-shaped hash for Match.raw_line_hash.
_HASH = "a" * 64
# Fixed clocks so recency is deterministic (no wall-clock reads).
_T_MATCH = datetime(2024, 1, 8, 12, 0, 0, tzinfo=UTC)  # 1 day after enrich
_T_ENRICH = datetime(2024, 1, 7, 12, 0, 0, tzinfo=UTC)


def _match() -> Match:
    return Match(
        log_source="auth.log",
        field="src_ip",
        timestamp=_T_MATCH,
        raw_line_hash=_HASH,
    )


def _enrich(reputation: int | None) -> EnrichmentResult:
    return EnrichmentResult(
        provider="test",
        reputation_score=reputation,
        fetched_at=_T_ENRICH,
        ttl_seconds=3600,
    )


def _scenarios() -> dict[str, ScoringInputs]:
    """Named, fixed scoring scenarios. Keys are stable golden identifiers."""
    return {
        "empty": ScoringInputs(ioc_confidence=0, matches=(), enrichments=()),
        "low_confidence_no_enrich": ScoringInputs(
            ioc_confidence=20, matches=(_match(),), enrichments=()
        ),
        "one_provider_mid": ScoringInputs(
            ioc_confidence=50,
            matches=(_match(),),
            enrichments=(_enrich(50),),
        ),
        "three_providers_high_rep": ScoringInputs(
            ioc_confidence=80,
            matches=tuple(_match() for _ in range(3)),
            enrichments=(_enrich(90), _enrich(85), _enrich(95)),
        ),
        "max_everything": ScoringInputs(
            ioc_confidence=100,
            matches=tuple(_match() for _ in range(10)),
            enrichments=(_enrich(100), _enrich(100), _enrich(100)),
        ),
        "no_reputation": ScoringInputs(
            ioc_confidence=60,
            matches=(_match(), _match()),
            enrichments=(_enrich(None), _enrich(None)),
        ),
    }


def _shipped_profile() -> ScoringProfile:
    data = yaml.safe_load(_SHIPPED_PROFILE.read_text(encoding="utf-8"))
    return ScoringProfile.model_validate(data)


def _compute_all() -> dict[str, dict[str, object]]:
    profile = _shipped_profile()
    out: dict[str, dict[str, object]] = {}
    for name, inputs in sorted(_scenarios().items()):
        score = compute_score(inputs, profile)
        out[name] = {
            "score": score,
            "severity": profile.severity_for_score(score).value,
        }
    return out


def test_scores_match_golden() -> None:
    computed = _compute_all()
    golden = json.loads(_GOLDEN.read_text(encoding="utf-8"))
    assert computed == golden, (
        "Scoring output drifted from golden. If intentional, regenerate with "
        "`python tests/unit/test_scoring_golden.py --write`."
    )


def test_golden_is_non_empty() -> None:
    golden = json.loads(_GOLDEN.read_text(encoding="utf-8"))
    assert golden, "golden_scores.json must not be empty"
    assert set(golden) == set(_scenarios()), "scenario/golden key mismatch"


def _write_golden() -> None:
    _GOLDEN.parent.mkdir(parents=True, exist_ok=True)
    _GOLDEN.write_text(
        json.dumps(_compute_all(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {_GOLDEN}")


if __name__ == "__main__":
    import sys

    if "--write" in sys.argv:
        _write_golden()
    else:
        print(json.dumps(_compute_all(), indent=2, sort_keys=True))
