"""Seeded property tests over the decision contract (stdlib only).

These loops are deliberately generative rather than illustrative: they exercise
serialization round-trips, argument tampering, bound enforcement and determinism
over many randomly generated, seeded inputs.
"""

from __future__ import annotations

import json
import random
from collections.abc import Mapping
from typing import Any

import pytest
from aegisgraph.adapter import canonical_action
from aegisgraph.api_v1 import DEFAULT_POLICY_SET
from aegisgraph.app import MAX_BODY_BYTES_ENV, app
from aegisgraph.contracts import CandidateAction, PolicyIdentity
from aegisgraph.enforcement import RefusalReason, enforce
from aegisgraph.sentinel import SentinelRequest
from fastapi.testclient import TestClient


def _expected_policy(receipt: Mapping[str, Any]) -> PolicyIdentity:
    """Return the policy identity the receipt itself carries.

    The generic surface resolves that identity server-side (H2-02, H3-04), so a
    caller cannot assert it; these tests enforce a receipt against the identity the
    server recorded for it, while the mismatch cases still pass a different one.
    """

    return PolicyIdentity.model_validate(receipt["policy_set"])



client = TestClient(app)

SEED = 20261008
ITERATIONS = 40
TOOLS = ["document_search", "email_draft", "ticket_read", "account_summary"]
WORDS = ["alpha", "beta", "gamma", "status", "report", "invoice", "queue", "asset"]


def _rng() -> random.Random:
    return random.Random(SEED)


def _random_arguments(rng: random.Random) -> dict[str, Any]:
    arguments: dict[str, Any] = {}
    for _ in range(rng.randint(0, 3)):
        key = rng.choice(["query", "limit", "body", "note", "ticket_id"])
        kind = rng.choice(["str", "int", "float", "bool"])
        if kind == "str":
            arguments[key] = " ".join(rng.choice(WORDS) for _ in range(rng.randint(1, 4)))
        elif kind == "int":
            arguments[key] = rng.randint(0, 999)
        elif kind == "float":
            arguments[key] = rng.choice([0.5, 1.25, 2.0, 17.75])
        else:
            arguments[key] = rng.choice([True, False])
    return arguments


def _random_request(rng: random.Random, *, api_version: bool = True) -> dict[str, Any]:
    action: dict[str, Any] = {
        "type": "tool_call",
        "tool": rng.choice(TOOLS),
        "arguments": _random_arguments(rng),
    }
    payload: dict[str, Any] = {
        "run_id": f"property-{rng.randint(0, 10_000)}",
        "step_id": rng.randint(0, 50),
        "user_goal": " ".join(rng.choice(WORDS) for _ in range(rng.randint(1, 5))),
        "conversation": [],
        "candidate_action": action,
        "policy_context": {
            "allowed_tools": TOOLS,
            "confirmation_required_tools": [],
            "consequential_tools": [],
        },
        "history_digest": {"confirmations_granted": []},
    }
    if api_version:
        payload["api_version"] = "aegisgraph/v1"
    return payload


def test_response_round_trips_through_json_for_random_requests() -> None:
    rng = _rng()
    for _ in range(ITERATIONS):
        payload = _random_request(rng)
        response = client.post("/api/v1/decisions", json=payload)

        assert response.status_code == 200
        body = response.json()
        assert json.loads(json.dumps(body)) == body
        assert body["api_version"] == "aegisgraph/v1"
        assert body["request_id"]
        assert len(body["receipt_id"]) == 32
        assert len(body["action_digest"]) == 24
        assert len(body["execution_digest"]) == 24


def test_decisions_are_deterministic_for_identical_inputs() -> None:
    rng = _rng()
    for _ in range(ITERATIONS):
        payload = _random_request(rng)
        payload["request_id"] = f"determinism-{rng.randint(0, 1_000_000)}"

        first = client.post("/api/v1/decisions", json=payload).json()
        second = client.post("/api/v1/decisions", json=payload).json()

        for volatile in ("receipt_id", "decided_at", "valid_until"):
            first.pop(volatile)
            second.pop(volatile)
        assert first == second


def test_every_argument_tamper_changes_the_execution_digest() -> None:
    rng = _rng()
    for _ in range(ITERATIONS):
        action = CandidateAction(
            type="tool_call", tool="document_search", arguments=_random_arguments(rng)
        )
        key = rng.choice(["query", "limit", "note"])
        value = action.arguments.get(key)
        if isinstance(value, bool):
            tampered_value: Any = not value
        elif isinstance(value, int | float):
            tampered_value = value + 1
        elif isinstance(value, str):
            tampered_value = f"{value} x"
        else:
            tampered_value = "injected"
        tampered = CandidateAction(
            type="tool_call",
            tool="document_search",
            arguments={**action.arguments, key: tampered_value},
        )

        assert tampered.execution_digest() != action.execution_digest()
        receipt = {
            "receipt_id": "a" * 32,
            "decision": "allow",
            "policy_set": DEFAULT_POLICY_SET.model_dump(mode="json"),
            "action_digest": action.digest(),
            "execution_digest": action.execution_digest(),
            "valid_until": "2999-01-01T00:00:00+00:00",
        }
        outcome = enforce(receipt, tampered, expected_policy=_expected_policy(receipt))
        assert outcome.reason in {RefusalReason.DIGEST_MISMATCH, RefusalReason.MALFORMED_RECEIPT}
        assert outcome.allowed is False


def test_body_bound_is_enforced_for_random_payload_sizes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rng = _rng()
    for _ in range(ITERATIONS):
        payload = _random_request(rng)
        payload["user_goal"] = "x" * rng.randint(0, 600)
        body = json.dumps(payload).encode("utf-8")
        limit = rng.choice([len(body) - 1, len(body), len(body) + 1])
        monkeypatch.setenv(MAX_BODY_BYTES_ENV, str(max(limit, 1)))

        response = client.post(
            "/v1/decision", content=body, headers={"content-type": "application/json"}
        )

        expected = 413 if len(body) > max(limit, 1) else 200
        assert response.status_code == expected, (len(body), limit)


def test_strict_and_legacy_modes_agree_when_no_confirmation_is_involved() -> None:
    rng = _rng()
    for _ in range(ITERATIONS):
        payload = _random_request(rng, api_version=False)
        request = SentinelRequest.model_validate(payload)

        legacy = client.post("/v1/decision", json=payload).json()
        strict = client.post(
            "/api/v1/decisions", json={**payload, "api_version": "aegisgraph/v1"}
        ).json()

        assert legacy["decision"] == strict["decision"]
        assert legacy["reason_codes"] == strict["reason_codes"]
        canonical = canonical_action(request.candidate_action)
        assert strict["action_digest"] == canonical.digest()
        assert strict["execution_digest"] == canonical.execution_digest()
