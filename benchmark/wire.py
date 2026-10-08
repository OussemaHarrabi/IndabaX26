"""Translate a native scenario into SENTINEL decision requests.

This module is the *only* coupling between the native benchmark and the gateway's
wire contract. It is deliberately a pure function library: no HTTP, no policy
logic, no defence imports. The runner posts what this module builds, and the
validator proves that what this module builds leaks no benchmark label.

Label hygiene
-------------
The request carries: ``user_goal``, the evidence (observations and their
provenance), the proposed action, the policy context, the history digest and any
declared confirmation grants. It never carries the scenario id, the pair id, the
attack family, the split, the expected property, the utility criterion or the
scoring method. The ``run_id`` is a positional identifier assigned by the runner
(``r000``, ``r001``, ...), so not even a hash of a benchmark label reaches the
wire.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from benchmark.schema import Observation, Scenario, SourceType

API_VERSION = "aegisgraph/v1"

#: Role vocabulary accepted by the SENTINEL conversation item.
_ROLE_BY_SOURCE: dict[SourceType, str] = {
    SourceType.USER_MESSAGE: "user",
    SourceType.AGENT_MESSAGE: "agent",
    SourceType.MEMORY: "memory",
    SourceType.POLICY: "safety",
}


def run_id_for(index: int) -> str:
    """Return the deterministic, label-free run identifier for dataset position ``index``."""

    return f"r{index:03d}"


def _role_for(observation: Observation, scenario: Scenario) -> str:
    node = next(node for node in scenario.provenance if node.id == observation.provenance_id)
    return _ROLE_BY_SOURCE.get(node.source_type, "tool")


def _action_payload(scenario: Scenario, step_id: int) -> dict[str, Any]:
    proposed = next(item for item in scenario.proposed_actions if item.step_id == step_id)
    return proposed.action.model_dump(mode="json")


def _provenance_payload(scenario: Scenario) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for node in scenario.provenance:
        records.append(
            {
                "id": node.id,
                "provenance": {
                    "source_type": node.source_type.value,
                    "source_id": node.source_id,
                    "trust_level": node.trust_level.value,
                    "origin_actor": node.origin_actor,
                    "retrieved_via": node.retrieved_via,
                    "sensitivity": node.sensitivity.value,
                    "timestamp": node.observed_at.isoformat(),
                    "parent_event_ids": list(node.parents),
                    "tags": list(node.labels),
                },
            }
        )
    return records


def _evidence_payload(scenario: Scenario) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Split observations into the wire's single ``observation`` plus conversation items."""

    primary, *rest = scenario.observations
    observation = {
        "kind": primary.kind,
        "content": primary.content,
        "provenance_ids": [primary.provenance_id],
    }
    conversation = [
        {
            "role": _role_for(item, scenario),
            "kind": item.kind,
            "content": item.content,
            "provenance_ids": [item.provenance_id],
        }
        for item in rest
    ]
    return observation, conversation


def build_request(
    scenario: Scenario,
    *,
    run_id: str,
    step_id: int,
    action: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the exact JSON body posted to ``POST /api/v1/decisions``.

    ``action`` overrides the scenario's authored action for ``step_id``; the
    scripted adapter passes the scenario's own action, and a model adapter passes
    whatever the model proposed.
    """

    observation, conversation = _evidence_payload(scenario)
    policy = scenario.policy_context
    history = scenario.history
    return {
        "api_version": API_VERSION,
        "run_id": run_id,
        "step_id": step_id,
        "user_goal": scenario.user_goal,
        "conversation": conversation,
        "observation": observation,
        "candidate_action": action if action is not None else _action_payload(scenario, step_id),
        "policy_context": {
            "policy_id": policy.policy_id,
            "policy_version": policy.policy_version,
            "allowed_tools": list(policy.allowed_tools),
            "consequential_tools": list(policy.consequential_tools),
            "confirmation_required_tools": list(policy.confirmation_required_tools),
            "internal_email_domains": list(policy.internal_email_domains),
        },
        "provenance": _provenance_payload(scenario),
        "history_digest": {
            "steps_taken": history.steps_taken,
            "turn_index": 0,
            "tool_calls": [
                {
                    "step_id": call.step_id,
                    "tool": call.tool,
                    "decision": call.decision,
                    "succeeded": call.succeeded,
                }
                for call in history.tool_calls
            ],
            "confirmations_granted": [grant.value for grant in scenario.confirmations],
            "blocked_count": history.blocked_count,
            "escalated_count": history.escalated_count,
        },
    }


def build_episode(scenario: Scenario, *, run_id: str) -> list[dict[str, Any]]:
    """Build one request per proposed action, in declared step order."""

    return [
        build_request(scenario, run_id=run_id, step_id=proposed.step_id)
        for proposed in scenario.proposed_actions
    ]


def build_plan_episode(
    scenario: Scenario,
    *,
    run_id: str,
    plan: tuple[tuple[int, dict[str, Any]], ...],
) -> list[dict[str, Any]]:
    """Build one request per ``(step_id, action)`` pair produced by a model adapter."""

    return [
        build_request(scenario, run_id=run_id, step_id=step_id, action=action)
        for step_id, action in plan
    ]


def request_bytes(request: dict[str, Any]) -> bytes:
    """The exact bytes the runner sends (compact JSON, UTF-8)."""

    return json.dumps(request, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def request_hash(request: dict[str, Any]) -> str:
    return hashlib.sha256(request_bytes(request)).hexdigest()


def episode_hash(scenario: Scenario, *, run_id: str) -> str:
    """A stable hash of the full request set for one scenario."""

    digest = hashlib.sha256()
    for request in build_episode(scenario, run_id=run_id):
        digest.update(request_bytes(request))
        digest.update(b"\n")
    return digest.hexdigest()
