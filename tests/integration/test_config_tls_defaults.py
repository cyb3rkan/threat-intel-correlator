# tests/integration/test_config_tls_defaults.py
"""Finding #3: default config is TLS-verify-secure; the lab exception lives in local.yaml."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tic.infra.config import load_settings

_REPO = Path(__file__).resolve().parents[2]
_DEFAULT = _REPO / "configs" / "default.yaml"
_LOCAL = _REPO / "configs" / "local.yaml"


def _load_default(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    # default.yaml intentionally has no `paths:`; supply them via env.
    monkeypatch.setenv("TIC_PATHS__WORKING_DIR", str(tmp_path))
    monkeypatch.setenv("TIC_PATHS__CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("TIC_PATHS__AUDIT_LOG_PATH", str(tmp_path / "audit.log"))
    return load_settings(_DEFAULT)


def test_default_yaml_loads_cleanly(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    s = _load_default(monkeypatch, tmp_path)
    assert "misp" in s.providers


def test_default_yaml_misp_tls_verify_is_true(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    s = _load_default(monkeypatch, tmp_path)
    assert s.providers["misp"].verify_tls is True


def test_default_yaml_misp_has_loopback_cidrs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    s = _load_default(monkeypatch, tmp_path)
    assert s.providers["misp"].allowed_host_cidrs == ["127.0.0.0/8", "::1/128"]


def test_default_yaml_audit_signing_defaults(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    s = _load_default(monkeypatch, tmp_path)
    assert s.audit.sign is False
    assert s.audit.keyring_service == "tic-audit-hmac"


@pytest.mark.skipif(
    not _LOCAL.exists(),
    reason=(
        "configs/local.yaml is a git-ignored, machine-specific lab override "
        "(holds real local paths + the TLS-verify-off exception) and is absent "
        "in CI/clean checkouts. When present, assert the lab exception lives here."
    ),
)
def test_local_yaml_is_where_the_tls_exception_lives() -> None:
    # The insecure lab value must NOT be in default.yaml; it is documented in
    # local.yaml (the labelled lab override).
    doc = yaml.safe_load(_LOCAL.read_text(encoding="utf-8"))
    misp = doc["providers"]["misp"]
    assert misp["verify_tls"] is False
    assert misp["allowed_host_cidrs"] == ["127.0.0.0/8", "::1/128"]
