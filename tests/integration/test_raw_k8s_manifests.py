# tests/integration/test_raw_k8s_manifests.py
"""Consistency checks for the raw manifests under deploy/k8s/.

README points operators at this directory as a Helm-free path, so
`kubectl apply -f deploy/k8s/` must produce a working deployment on its own.
It previously did not: the Deployment mounted a PVC that no manifest defined
(pod stuck Pending) and no Service existed (no stable endpoint).

Pure YAML parsing -- no helm, no cluster -- so these run everywhere.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

K8S_DIR = Path(__file__).resolve().parents[2] / "deploy" / "k8s"


@pytest.fixture(scope="module")
def docs() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for path in sorted(K8S_DIR.glob("*.yaml")):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if doc:
                doc["__source__"] = path.name
                out.append(doc)
    assert out, f"no manifests found under {K8S_DIR}"
    return out


def _one(docs: list[dict[str, Any]], kind: str) -> dict[str, Any]:
    found = [d for d in docs if d.get("kind") == kind]
    assert len(found) == 1, f"expected exactly one {kind}, got {len(found)}"
    return found[0]


def _pod_labels(docs: list[dict[str, Any]]) -> dict[str, str]:
    return _one(docs, "Deployment")["spec"]["template"]["metadata"]["labels"]


def test_required_kinds_are_present(docs: list[dict[str, Any]]) -> None:
    """Regression: Service and PersistentVolumeClaim were both missing."""
    kinds = {d["kind"] for d in docs}
    required = {"Deployment", "Service", "PersistentVolumeClaim", "ServiceAccount", "NetworkPolicy"}
    assert required <= kinds, f"missing manifests: {sorted(required - kinds)}"


def test_every_referenced_claim_is_defined(docs: list[dict[str, Any]]) -> None:
    """Regression: deployment.yaml referenced tic-data-pvc with no PVC manifest,
    leaving the pod Pending forever."""
    volumes = _one(docs, "Deployment")["spec"]["template"]["spec"]["volumes"]
    claims = {
        v["persistentVolumeClaim"]["claimName"] for v in volumes if "persistentVolumeClaim" in v
    }
    defined = {d["metadata"]["name"] for d in docs if d["kind"] == "PersistentVolumeClaim"}
    assert claims <= defined, f"claimName(s) with no PVC manifest: {sorted(claims - defined)}"


def test_service_selector_matches_pod_labels(docs: list[dict[str, Any]]) -> None:
    selector = _one(docs, "Service")["spec"]["selector"]
    pod_labels = _pod_labels(docs)
    missing = {k: v for k, v in selector.items() if pod_labels.get(k) != v}
    assert not missing, f"Service selector unmatched by pod labels: {missing}"


def test_service_labels_carry_selector_labels(docs: list[dict[str, Any]]) -> None:
    """Keeps the raw Service discoverable by the same label selectors the Helm
    chart guarantees (e.g. a hand-written ServiceMonitor)."""
    labels = _one(docs, "Service")["metadata"]["labels"]
    for key in ("app.kubernetes.io/name", "app.kubernetes.io/component"):
        assert key in labels, f"Service metadata.labels missing {key}"


def test_service_targetport_matches_container_port_name(docs: list[dict[str, Any]]) -> None:
    target = _one(docs, "Service")["spec"]["ports"][0]["targetPort"]
    names = {
        p["name"]
        for p in _one(docs, "Deployment")["spec"]["template"]["spec"]["containers"][0]["ports"]
    }
    assert target in names, f"targetPort {target!r} not among container ports {names}"


def test_networkpolicy_podselector_matches_pod_labels(docs: list[dict[str, Any]]) -> None:
    selector = _one(docs, "NetworkPolicy")["spec"]["podSelector"]["matchLabels"]
    pod_labels = _pod_labels(docs)
    missing = {k: v for k, v in selector.items() if pod_labels.get(k) != v}
    assert not missing, f"NetworkPolicy selects labels the pod lacks: {missing}"


def test_prometheus_ingress_rule_is_cross_namespace(docs: list[dict[str, Any]]) -> None:
    """Prometheus runs in another namespace, so its rule needs a
    namespaceSelector -- a podSelector alone would drop every scrape."""
    rules = _one(docs, "NetworkPolicy")["spec"]["ingress"]
    assert any(
        "namespaceSelector" in src and "podSelector" in src
        for rule in rules
        for src in rule.get("from", [])
    ), "no cross-namespace ingress rule for the Prometheus scraper"


def test_serviceaccount_reference_resolves(docs: list[dict[str, Any]]) -> None:
    wanted = _one(docs, "Deployment")["spec"]["template"]["spec"]["serviceAccountName"]
    defined = {d["metadata"]["name"] for d in docs if d["kind"] == "ServiceAccount"}
    assert wanted in defined, f"serviceAccountName {wanted!r} has no manifest"


def test_all_manifests_share_one_namespace(docs: list[dict[str, Any]]) -> None:
    namespaces = {d["metadata"].get("namespace") for d in docs}
    assert namespaces == {"tic"}, f"inconsistent namespaces: {namespaces}"


def test_uploads_are_staged_off_the_persistent_volume(docs: list[dict[str, Any]]) -> None:
    """Uploaded feeds/logs carry IPs, hostnames and usernames; a SIGKILL'd pod
    never runs cleanup, so staging must not land on the PVC."""
    spec = _one(docs, "Deployment")["spec"]["template"]["spec"]
    env = {e["name"]: e.get("value") for e in spec["containers"][0]["env"]}
    upload_dir = env.get("TIC_PATHS__UPLOAD_DIR")
    assert upload_dir, "TIC_PATHS__UPLOAD_DIR not set"

    mounts = {m["mountPath"]: m["name"] for m in spec["containers"][0]["volumeMounts"]}
    volumes = {v["name"]: v for v in spec["volumes"]}

    owner = max((m for m in mounts if upload_dir.startswith(m)), key=len, default=None)
    assert owner, f"{upload_dir} is under no volumeMount: {sorted(mounts)}"
    assert "emptyDir" in volumes[mounts[owner]], (
        f"{upload_dir} resolves to volume {mounts[owner]!r}, which is not ephemeral"
    )
