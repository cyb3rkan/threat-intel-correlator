# tests/integration/test_helm_render.py
"""Semantic checks on the rendered Helm chart.

`helm lint` validates syntax and schema. It cannot see that a Service's labels
fail to satisfy a ServiceMonitor's selector, or that a NetworkPolicy drops the
traffic an enabled Ingress depends on -- both render as valid YAML and fail
silently at runtime. Those are exactly the defects these tests cover.

Skipped when the `helm` binary is absent so a plain `pytest` still runs
locally; CI installs Helm, so the checks are enforced there.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

CHART = Path(__file__).resolve().parents[2] / "deploy" / "helm" / "tic"

pytestmark = pytest.mark.skipif(
    shutil.which("helm") is None, reason="helm binary not installed"
)


def _render(**sets: str) -> list[dict[str, Any]]:
    """Render the chart, returning parsed docs. Raises on render failure."""
    cmd = ["helm", "template", "tic", str(CHART)]
    for key, value in sets.items():
        cmd += ["--set", f"{key.replace('__', '.')}={value}"]
    # S603: the argv is built here from literals and test-local values; no
    # shell, no external input.
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)  # noqa: S603
    if proc.returncode != 0:
        raise AssertionError(f"helm template failed:\n{proc.stderr}")
    return [d for d in yaml.safe_load_all(proc.stdout) if d]


def _render_error(**sets: str) -> str:
    """Render expecting failure; return stderr. Fails the test if it succeeds."""
    cmd = ["helm", "template", "tic", str(CHART)]
    for key, value in sets.items():
        cmd += ["--set", f"{key.replace('__', '.')}={value}"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)  # noqa: S603
    assert proc.returncode != 0, "expected helm template to fail, but it succeeded"
    return proc.stderr


def _one(docs: list[dict[str, Any]], kind: str) -> dict[str, Any]:
    found = [d for d in docs if d.get("kind") == kind]
    assert len(found) == 1, f"expected exactly one {kind}, got {len(found)}"
    return found[0]


# --------------------------------------------------------------------------
# Label/selector wiring
# --------------------------------------------------------------------------


def test_service_labels_satisfy_servicemonitor_selector() -> None:
    """Regression: tic.labels once omitted component=api, which the
    ServiceMonitor selector requires -- so it matched no Service and Prometheus
    silently scraped nothing."""
    docs = _render(
        serviceMonitor__enabled="true",
        networkPolicy__ingressFromPrometheus__enabled="true",
    )
    labels = _one(docs, "Service")["metadata"]["labels"]
    selector = _one(docs, "ServiceMonitor")["spec"]["selector"]["matchLabels"]

    missing = {k: v for k, v in selector.items() if labels.get(k) != v}
    assert not missing, f"ServiceMonitor selects labels the Service lacks: {missing}"


def test_service_selector_matches_pod_labels() -> None:
    """A Service whose selector misses the pod template has no endpoints."""
    docs = _render()
    selector = _one(docs, "Service")["spec"]["selector"]
    pod_labels = _one(docs, "Deployment")["spec"]["template"]["metadata"]["labels"]

    missing = {k: v for k, v in selector.items() if pod_labels.get(k) != v}
    assert not missing, f"Service selector unmatched by pod labels: {missing}"


def test_networkpolicy_podselector_matches_pod_labels() -> None:
    docs = _render()
    selector = _one(docs, "NetworkPolicy")["spec"]["podSelector"]["matchLabels"]
    pod_labels = _one(docs, "Deployment")["spec"]["template"]["metadata"]["labels"]

    missing = {k: v for k, v in selector.items() if pod_labels.get(k) != v}
    assert not missing, f"NetworkPolicy selects labels the pod lacks: {missing}"


def test_service_targetport_matches_container_port_name() -> None:
    docs = _render()
    target = _one(docs, "Service")["spec"]["ports"][0]["targetPort"]
    names = {
        p["name"]
        for p in _one(docs, "Deployment")["spec"]["template"]["spec"]["containers"][0]["ports"]
    }
    assert target in names, f"targetPort {target!r} not among container ports {names}"


def test_deployment_claimname_matches_rendered_pvc() -> None:
    docs = _render()
    volumes = _one(docs, "Deployment")["spec"]["template"]["spec"]["volumes"]
    claims = {
        v["persistentVolumeClaim"]["claimName"] for v in volumes if "persistentVolumeClaim" in v
    }
    pvcs = {d["metadata"]["name"] for d in docs if d.get("kind") == "PersistentVolumeClaim"}
    assert claims <= pvcs, f"claimName(s) {claims - pvcs} have no PVC"


# --------------------------------------------------------------------------
# NetworkPolicy reachability
# --------------------------------------------------------------------------


def test_prometheus_rule_is_cross_namespace() -> None:
    """Prometheus usually runs in another namespace; a podSelector-only rule
    would match same-namespace pods only and drop every scrape."""
    docs = _render(
        serviceMonitor__enabled="true",
        networkPolicy__ingressFromPrometheus__enabled="true",
    )
    rules = _one(docs, "NetworkPolicy")["spec"]["ingress"]
    assert any(
        "namespaceSelector" in src and "podSelector" in src
        for rule in rules
        for src in rule.get("from", [])
    ), "no ingress rule pairs namespaceSelector with podSelector for Prometheus"


def test_ingress_controller_rule_is_cross_namespace() -> None:
    docs = _render(
        ingress__enabled="true",
        security__acknowledgeNoAuth="true",
        networkPolicy__ingressFromIngressController__enabled="true",
    )
    rules = _one(docs, "NetworkPolicy")["spec"]["ingress"]
    namespaces = {
        src["namespaceSelector"]["matchLabels"].get("kubernetes.io/metadata.name")
        for rule in rules
        for src in rule.get("from", [])
        if "namespaceSelector" in src
    }
    assert "ingress-nginx" in namespaces, f"ingress controller namespace missing: {namespaces}"


# --------------------------------------------------------------------------
# Guards -- each must abort the render rather than ship a broken deployment
# --------------------------------------------------------------------------


def test_servicemonitor_without_networkpolicy_rule_fails() -> None:
    err = _render_error(serviceMonitor__enabled="true")
    assert "ingressFromPrometheus" in err


def test_ingress_without_auth_acknowledgement_fails() -> None:
    err = _render_error(ingress__enabled="true")
    assert "NO API authentication" in err


def test_ingress_without_networkpolicy_rule_fails() -> None:
    err = _render_error(ingress__enabled="true", security__acknowledgeNoAuth="true")
    assert "ingressFromIngressController" in err


def test_fully_enabled_configuration_renders() -> None:
    """The documented "everything on" combination must be reachable."""
    docs = _render(
        serviceMonitor__enabled="true",
        networkPolicy__ingressFromPrometheus__enabled="true",
        ingress__enabled="true",
        security__acknowledgeNoAuth="true",
        networkPolicy__ingressFromIngressController__enabled="true",
    )
    kinds = {d["kind"] for d in docs}
    assert {"Deployment", "Service", "Ingress", "ServiceMonitor", "NetworkPolicy"} <= kinds


def test_default_render_has_no_ingress_or_servicemonitor() -> None:
    """Defaults stay closed: local-first, reached via port-forward."""
    kinds = {d["kind"] for d in _render()}
    assert "Ingress" not in kinds
    assert "ServiceMonitor" not in kinds


# --------------------------------------------------------------------------
# Upload staging
# --------------------------------------------------------------------------


def test_upload_dir_points_outside_the_persistent_volume() -> None:
    """Uploads must not stage on the PVC: cleanup cannot run after a SIGKILL."""
    docs = _render()
    spec = _one(docs, "Deployment")["spec"]["template"]["spec"]
    env = {e["name"]: e.get("value") for e in spec["containers"][0]["env"]}
    upload_dir = env.get("TIC_PATHS__UPLOAD_DIR")
    assert upload_dir, "TIC_PATHS__UPLOAD_DIR not set"

    mounts = {m["mountPath"]: m["name"] for m in spec["containers"][0]["volumeMounts"]}
    volumes = {v["name"]: v for v in spec["volumes"]}

    owner = max(
        (m for m in mounts if upload_dir.startswith(m)), key=len, default=None
    )
    assert owner, f"{upload_dir} is under no volumeMount: {sorted(mounts)}"
    assert "emptyDir" in volumes[mounts[owner]], (
        f"{upload_dir} resolves to volume {mounts[owner]!r}, which is not ephemeral"
    )
