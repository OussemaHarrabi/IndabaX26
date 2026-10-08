"""Validate and policy-check the Kubernetes manifests under ``deploy/k8s``.

Two independent gates run over the *rendered* manifests (``kustomize`` output,
not the raw files, so the image rewrite and namespace are exercised too):

1. **Schema validation.** ``kubernetes-validate`` (offline, schema shipped with
   the package) is preferred; if it is not installed the script falls back to the
   ``kubeconform`` binary when one is on ``PATH``. If neither is available the
   script fails loudly rather than reporting a green result it did not earn.
2. **Hardening assertions.** The security properties the milestone claims —
   non-root, read-only root filesystem, no privilege escalation, all
   capabilities dropped, RuntimeDefault seccomp, probes, resource requests and
   limits, a default-deny NetworkPolicy, a PodDisruptionBudget, and no literal
   Secret values — are asserted over the rendered objects, so a regression fails
   CI instead of silently degrading the deployment.

A real cluster smoke test (``kubectl apply``, pod readiness, NetworkPolicy
enforcement) is **not** performed here: no cluster is available in this
environment. See ``deploy/k8s/README.md``.

Usage:
    python scripts/validate_k8s_manifests.py
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
KUSTOMIZE_DIR = REPO_ROOT / "deploy" / "k8s"
KUBERNETES_VERSION = "1.31.0"

_FAILURES: list[str] = []


def _record(ok: bool, message: str) -> None:
    print(f"[{'PASS' if ok else 'FAIL'}] {message}")
    if not ok:
        _FAILURES.append(message)


def render_manifests() -> list[dict[str, Any]]:
    """Render ``deploy/k8s`` with kustomize and return the parsed documents."""
    candidates = (
        ["kubectl", "kustomize", str(KUSTOMIZE_DIR)],
        ["kustomize", "build", str(KUSTOMIZE_DIR)],
    )
    for command in candidates:
        if shutil.which(command[0]) is None:
            continue
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        if completed.returncode != 0:
            print(f"`{' '.join(command)}` failed: {completed.stderr.strip()}", file=sys.stderr)
            continue
        documents = [doc for doc in yaml.safe_load_all(completed.stdout) if doc]
        print(f"rendered {len(documents)} objects via `{' '.join(command)}`")
        return documents
    raise SystemExit("neither `kubectl kustomize` nor `kustomize build` is available")


def _validate_with_python_package(documents: list[dict[str, Any]]) -> int:
    """Schema-validate every document with the offline ``kubernetes-validate``."""

    import kubernetes_validate

    checked = 0
    for document in documents:
        kind = document.get("kind", "?")
        name = document.get("metadata", {}).get("name", "?")
        try:
            kubernetes_validate.validate(document, KUBERNETES_VERSION, strict=True)
        except Exception as error:  # report every schema failure verbatim
            _record(False, f"schema[kubernetes-validate] {kind}/{name}: {error}")
        else:
            _record(True, f"schema[kubernetes-validate] {kind}/{name}")
        checked += 1
    return checked


def _validate_with_kubeconform(documents: list[dict[str, Any]], binary: str) -> int:
    """Schema-validate the rendered set with the ``kubeconform`` binary."""

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as handle:
        yaml.safe_dump_all(documents, handle)
        rendered_path = handle.name
    try:
        completed = subprocess.run(
            [
                binary,
                "-strict",
                "-summary",
                "-kubernetes-version",
                KUBERNETES_VERSION,
                rendered_path,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        _record(completed.returncode == 0, f"schema[kubeconform]: {completed.stdout.strip()}")
    finally:
        os.unlink(rendered_path)
    return len(documents)


def schema_validate(
    documents: list[dict[str, Any]], validator: str, kubeconform_path: str | None
) -> None:
    """Run the requested schema validators over the rendered documents.

    ``auto`` prefers the offline ``kubernetes-validate`` package and falls back to
    ``kubeconform``. ``both`` runs both so the two independent implementations
    cross-check each other. Either way, if neither is available the run fails
    loudly instead of reporting a green result it did not earn.
    """

    try:
        import kubernetes_validate  # noqa: F401
    except ImportError:
        has_python_validator = False
    else:
        has_python_validator = True

    kubeconform = kubeconform_path or shutil.which("kubeconform")
    if (
        kubeconform_path
        and shutil.which(kubeconform_path) is None
        and not Path(kubeconform_path).exists()
    ):
        raise SystemExit(f"--kubeconform {kubeconform_path!r} does not exist")

    if validator in {"kubernetes-validate", "both"} and not has_python_validator:
        raise SystemExit(
            "kubernetes-validate is not installed; "
            "`python -m pip install kubernetes-validate pyyaml`"
        )
    if validator in {"kubeconform", "both"} and kubeconform is None:
        raise SystemExit(
            "kubeconform is not available; install it with `python scripts/install_kubeconform.py`"
        )

    if validator == "kubernetes-validate":
        _validate_with_python_package(documents)
        return
    if validator == "kubeconform":
        _validate_with_kubeconform(documents, kubeconform or "kubeconform")
        return
    if validator == "both":
        _validate_with_python_package(documents)
        _validate_with_kubeconform(documents, kubeconform or "kubeconform")
        return

    # auto
    if has_python_validator:
        _validate_with_python_package(documents)
        if kubeconform is not None:
            _validate_with_kubeconform(documents, kubeconform)
        else:
            print(
                "[NOTE] kubeconform not found; only kubernetes-validate ran "
                "(install it with `python scripts/install_kubeconform.py`)"
            )
        return
    if kubeconform is not None:
        _validate_with_kubeconform(documents, kubeconform)
        return
    raise SystemExit(
        "no schema validator available: install `kubernetes-validate` (pip) or run "
        "`python scripts/install_kubeconform.py`"
    )


def _by_kind(documents: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [document for document in documents if document.get("kind") == kind]


def _find_deployment(documents: list[dict[str, Any]]) -> dict[str, Any]:
    matches = [
        d for d in _by_kind(documents, "Deployment") if d["metadata"]["name"] == "aegisgraph-api"
    ]
    if not matches:
        raise SystemExit("Deployment/aegisgraph-api not found in the rendered manifests")
    return matches[0]


def policy_checks(documents: list[dict[str, Any]]) -> None:
    deployment = _find_deployment(documents)
    pod_spec = deployment["spec"]["template"]["spec"]
    pod_security = pod_spec.get("securityContext", {})
    containers = pod_spec["containers"]
    container_security = containers[0].get("securityContext", {})

    _record(pod_security.get("runAsNonRoot") is True, "pod runAsNonRoot=true")
    _record(
        pod_security.get("seccompProfile", {}).get("type") == "RuntimeDefault",
        "pod seccompProfile=RuntimeDefault",
    )
    _record(
        container_security.get("allowPrivilegeEscalation") is False,
        "container allowPrivilegeEscalation=false",
    )
    _record(
        container_security.get("readOnlyRootFilesystem") is True,
        "container readOnlyRootFilesystem=true",
    )
    _record(
        container_security.get("capabilities", {}).get("drop") == ["ALL"],
        "container drops ALL capabilities",
    )
    _record(
        pod_spec.get("automountServiceAccountToken") is False,
        "automountServiceAccountToken=false",
    )

    for container in containers:
        name = container["name"]
        resources = container.get("resources", {})
        _record(
            bool(resources.get("requests", {}).get("cpu"))
            and bool(resources.get("requests", {}).get("memory")),
            f"{name}: cpu+memory requests set",
        )
        _record(
            bool(resources.get("limits", {}).get("cpu"))
            and bool(resources.get("limits", {}).get("memory")),
            f"{name}: cpu+memory limits set",
        )
        for probe in ("readinessProbe", "livenessProbe"):
            http_get = container.get(probe, {}).get("httpGet", {})
            _record(
                http_get.get("path") == "/healthz",
                f"{name}: {probe} on /healthz",
            )

    _record(bool(_by_kind(documents, "Service")), "Service present")

    config_maps = _by_kind(documents, "ConfigMap")
    _record(bool(config_maps), "ConfigMap present")

    secrets = _by_kind(documents, "Secret")
    leaks = [s["metadata"]["name"] for s in secrets if s.get("data") or s.get("stringData")]
    _record(not leaks, f"no Secret resource carries literal values (offenders: {leaks})")

    policies = _by_kind(documents, "NetworkPolicy")
    default_deny = [p for p in policies if p["metadata"]["name"] == "default-deny-all"]
    _record(bool(default_deny), "default-deny NetworkPolicy present")
    if default_deny:
        _record(
            set(default_deny[0]["spec"].get("policyTypes", [])) == {"Ingress", "Egress"},
            "default-deny covers Ingress and Egress",
        )

    api_policy = [p for p in policies if p["metadata"]["name"] == "aegisgraph-api"]
    _record(bool(api_policy), "api NetworkPolicy present")
    if api_policy:
        spec = api_policy[0]["spec"]
        ingress_ports = {
            port.get("port") for rule in spec.get("ingress", []) for port in rule.get("ports", [])
        }
        egress_ports = {
            port.get("port") for rule in spec.get("egress", []) for port in rule.get("ports", [])
        }
        _record(
            ingress_ports <= {8080},
            f"api ingress limited to 8080 (got {sorted(ingress_ports)})",
        )
        _record(
            egress_ports <= {53, 5432, 4317, 4318},
            f"api egress limited to DNS/DB/OTLP (got {sorted(egress_ports)})",
        )

    pdbs = _by_kind(documents, "PodDisruptionBudget")
    _record(bool(pdbs), "PodDisruptionBudget present")
    if pdbs:
        spec = pdbs[0]["spec"]
        _record(
            "minAvailable" in spec or "maxUnavailable" in spec,
            "PodDisruptionBudget bounds voluntary disruption",
        )

    image = containers[0]["image"]
    _record(not image.endswith(":latest"), f"image is not a floating :latest tag ({image})")
    digest_pinned = "@sha256:" in image
    explicit_tag = ":" in image.rsplit("/", 1)[-1] and not image.endswith(":latest")
    _record(
        digest_pinned or explicit_tag,
        f"image carries a digest or an explicit non-latest tag ({image})",
    )
    if not digest_pinned:
        print(
            "[NOTE] image is tag-pinned, not digest-pinned; production must use the "
            "digest recorded by CI (docs/ops/deployment.md)"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--validator",
        choices=["auto", "kubernetes-validate", "kubeconform", "both"],
        default="auto",
        help=(
            "which schema validator(s) to run; 'auto' prefers kubernetes-validate "
            "and also runs kubeconform when it is available (default: auto)"
        ),
    )
    parser.add_argument(
        "--kubeconform",
        default=None,
        help="path to the kubeconform binary (default: search PATH)",
    )
    arguments = parser.parse_args()

    documents = render_manifests()
    schema_validate(documents, arguments.validator, arguments.kubeconform)
    policy_checks(documents)
    if _FAILURES:
        print(f"\n{len(_FAILURES)} check(s) failed:", file=sys.stderr)
        for failure in _FAILURES:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("\nall manifest checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
