# tests/unit/test_ai_config_phase_c.py
"""Phase C: freeze the new AIConfig defaults and validation bounds."""
from __future__ import annotations

import pytest

from pydantic import ValidationError

from tic.infra.config import AIConfig


def test_defaults_match_phase_c_policy() -> None:
    cfg = AIConfig()
    assert cfg.language == "tr"
    assert cfg.narration_level == "concise"
    assert cfg.max_findings_per_sweep == 25
    # AI must remain disabled by default — Phase C does not flip this.
    assert cfg.enabled is False
    assert cfg.endpoint_allowlist == []


def test_language_must_be_in_closed_set() -> None:
    with pytest.raises(ValidationError):
        AIConfig(language="de")  # not in the closed Literal


def test_narration_level_must_be_in_closed_set() -> None:
    with pytest.raises(ValidationError):
        AIConfig(narration_level="verbose")  # not in the closed Literal


def test_max_findings_per_sweep_bounds_enforced() -> None:
    # Lower bound: 1
    with pytest.raises(ValidationError):
        AIConfig(max_findings_per_sweep=0)
    # Upper bound: 100
    with pytest.raises(ValidationError):
        AIConfig(max_findings_per_sweep=101)
    # Bounds inclusive.
    assert AIConfig(max_findings_per_sweep=1).max_findings_per_sweep == 1
    assert AIConfig(max_findings_per_sweep=100).max_findings_per_sweep == 100


def test_existing_fields_unchanged() -> None:
    """Defensive: pre-Phase-C fields keep their defaults and types."""
    cfg = AIConfig()
    assert cfg.model == ""
    assert cfg.max_output_tokens == 512
    assert cfg.max_input_chars == 8000
    assert cfg.request_timeout_seconds == 20.0
    assert cfg.keyring_service == "tic-ai"
    assert cfg.keyring_user == "default"
