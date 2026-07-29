# tests/integration/test_container_env_wiring.py
"""Finding B-1: the container/k8s audit env var name must match PathsConfig.

The Dockerfile and the k8s/Helm manifests inject the audit-chain path via an
environment variable. If that variable is named ``TIC_PATHS__AUDIT_CHAIN`` (the
old, wrong name) instead of ``TIC_PATHS__AUDIT_LOG_PATH`` (the real
``PathsConfig`` field), a clean container has no XDG fallback and
``load_settings`` fails closed with ``paths.audit_log_path required`` — the pod
never becomes Ready.

These tests pin two things so the regression cannot silently return:
  1. The manifests use the correct env name and never the wrong one.
  2. Loading settings with *exactly* the manifest env set (and nothing else,
     as in a clean container) succeeds.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from tic.infra.config import load_settings

_REPO = Path(__file__).resolve().parents[2]
_DOCKERFILE = _REPO / "Dockerfile"
_K8S_DEPLOY = _REPO / "deploy" / "k8s" / "deployment.yaml"
_HELM_DEPLOY = _REPO / "deploy" / "helm" / "tic" / "templates" / "deployment.yaml"

_WRONG = "TIC_PATHS__AUDIT_CHAIN"
_RIGHT = "TIC_PATHS__AUDIT_LOG_PATH"

_MANIFESTS = [
    pytest.param(_DOCKERFILE, id="dockerfile"),
    pytest.param(_K8S_DEPLOY, id="k8s-deployment"),
    pytest.param(_HELM_DEPLOY, id="helm-deployment"),
]


@pytest.mark.parametrize("manifest", _MANIFESTS)
def test_manifest_uses_correct_audit_env_name(manifest: Path) -> None:
    text = manifest.read_text(encoding="utf-8")
    assert _RIGHT in text, f"{manifest.name} must set {_RIGHT}"


@pytest.mark.parametrize("manifest", _MANIFESTS)
def test_manifest_never_uses_wrong_audit_env_name(manifest: Path) -> None:
    text = manifest.read_text(encoding="utf-8")
    # Use a word boundary so AUDIT_LOG_PATH is not a false positive for the
    # AUDIT_CHAIN substring check.
    assert not re.search(rf"\b{_WRONG}\b", text), (
        f"{manifest.name} still references the wrong env var {_WRONG}; "
        f"it must use {_RIGHT} (see PathsConfig.audit_log_path)."
    )


def test_clean_container_env_loads_settings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Reproduce a clean container: only the manifest env, no XDG home, no YAML.

    This is the exact scenario B-1 broke. With the correct env names the load
    must succeed and resolve audit_log_path from the env value.
    """
    # Strip every TIC_* and XDG_* var so nothing else can rescue the load.
    for key in list(os.environ):
        if key.startswith(("TIC_", "XDG_")):
            monkeypatch.delenv(key, raising=False)

    data = tmp_path / "data"
    monkeypatch.setenv("TIC_PATHS__WORKING_DIR", str(data))
    monkeypatch.setenv("TIC_PATHS__CACHE_DIR", str(data / "cache"))
    monkeypatch.setenv(_RIGHT, str(data / "audit_chain.jsonl"))

    # No config file: emulate the container image, which ships no configs/.
    settings = load_settings(config_file=Path(tmp_path / "does-not-exist.yaml"))

    assert settings.paths.audit_log_path == data / "audit_chain.jsonl"
    assert settings.paths.working_dir == data
