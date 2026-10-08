"""Publish and verify the policy sets a benchmark run pins.

The gateway resolves a policy *identity* server-side: a request may name a policy
set only if that version is stored for its tenant. The benchmark derives one
policy set per distinct policy document in the dataset (id ``bench-<digest>``,
version ``1``) and publishes it through the administration surface, so a run
measures stored, versioned, auditable policy facts rather than caller-asserted
ones — and needs no ``policy:context_override`` scope to be honest.

This module holds the logic; ``scripts/bench_policies.py`` is the CLI and the
runner tests use the same code, so the published documents and the pinned
documents cannot drift apart.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from benchmark.dataset import load_dataset
from benchmark.runner import HttpClient, RunError
from benchmark.wire import policy_document, policy_set_for

POLICIES_PATH = "/api/v1/policies"

#: Publication outcomes, ordered from best to worst.
PUBLISHED = "published"
PRESENT = "present"
PRESENT_INACTIVE = "present-inactive"
MISSING = "missing"


@dataclass(frozen=True)
class PolicyPlan:
    """The distinct policy sets a selection needs, and their identity hash."""

    documents: dict[str, dict[str, Any]]
    blob_sha256: str
    source: str = "benchmark/data/scenarios/**/policy_context"

    @property
    def keys(self) -> list[str]:
        return sorted(self.documents)


def collect_policy_sets(dataset_root: Path | str, splits: tuple[str, ...]) -> PolicyPlan:
    """The ``"<id>:<version>" -> document`` map for every scenario in ``splits``."""

    dataset = load_dataset(dataset_root)
    documents: dict[str, dict[str, Any]] = {}
    for entry in dataset.entries:
        scenario = entry.scenario
        if scenario.split.value not in splits:
            continue
        identity = policy_set_for(scenario)
        documents[f"{identity['id']}:{identity['version']}"] = policy_document(scenario)
    return PolicyPlan(documents=documents, blob_sha256=policy_blob_sha256(documents))


def policy_blob_sha256(documents: dict[str, dict[str, Any]]) -> str:
    """The H5.2 gate value: one hash over the whole policy-set map."""

    blob = json.dumps(
        {key: documents[key] for key in sorted(documents)}, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def publish_one(
    client: HttpClient, key: str, document: dict[str, Any], *, check_only: bool = False
) -> str:
    """Publish (or verify) one policy set. Raises :class:`RunError` on any refusal."""

    policy_id, _, version = key.rpartition(":")
    if check_only:
        response = client.get(POLICIES_PATH)
        if response.status != 200 or response.payload is None:
            raise RunError(f"could not list policies: HTTP {response.status} [{response.error}]")
        for item in response.payload.get("items", []):
            if item.get("id") == policy_id and item.get("version") == version:
                return PRESENT if item.get("active") else PRESENT_INACTIVE
        return MISSING

    body = {"id": policy_id, "version": version, "document": document, "activate": True}
    response = client.post(POLICIES_PATH, body)
    if response.status not in (200, 201) or response.payload is None:
        raise RunError(
            f"publishing {key} failed: HTTP {response.status} [{response.error}]. "
            "The credential needs policy:read and policy:write."
        )
    if response.payload.get("document") != document:
        raise RunError(
            f"the gateway stored a different document for {key}; refusing to continue "
            "(the derived id is not injective)"
        )
    if not response.payload.get("active"):
        raise RunError(f"policy set {key} was stored but is not active")
    return PUBLISHED


def publish_plan(
    client: HttpClient, plan: PolicyPlan, *, check_only: bool = False
) -> dict[str, str]:
    """Publish every policy set in the plan, in a stable order."""

    if not plan.documents:
        raise RunError("no policy sets to publish for this selection")
    return {
        key: publish_one(client, key, plan.documents[key], check_only=check_only)
        for key in plan.keys
    }


def ensure_published(client: HttpClient, plan: PolicyPlan) -> dict[str, str]:
    """Publish and verify in one call; fails if anything is not active afterwards."""

    publish_plan(client, plan)
    results = {
        key: publish_one(client, key, plan.documents[key], check_only=True) for key in plan.keys
    }
    inactive = [key for key, value in results.items() if value != PRESENT]
    if inactive:
        raise RunError(f"policy sets not active after publication: {inactive}")
    return results


__all__ = [
    "MISSING",
    "POLICIES_PATH",
    "PRESENT",
    "PRESENT_INACTIVE",
    "PUBLISHED",
    "PolicyPlan",
    "collect_policy_sets",
    "ensure_published",
    "policy_blob_sha256",
    "publish_one",
    "publish_plan",
]
