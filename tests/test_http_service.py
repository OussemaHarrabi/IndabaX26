"""HTTP boundary tests for the local SENTINEL-compatible defense service."""

from __future__ import annotations

import json
from importlib import import_module
from typing import Any

from fastapi.testclient import TestClient

app_module = import_module("aegisgraph.app")
app = app_module.app

client = TestClient(app)


def _request(
    action: dict[str, Any],
    *,
    allowed_tools: list[str] | None = None,
    confirmations: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "run_id": "http-test",
        "step_id": 1,
        "user_goal": "Perform the requested safe task",
        "conversation": [],
        "candidate_action": action,
        "policy_context": {
            "policy_id": "test-policy",
            "policy_version": "1",
            "allowed_tools": allowed_tools or ["document_search", "payment_execute"],
            "confirmation_required_tools": [],
            "consequential_tools": [],
        },
        "history_digest": {"confirmations_granted": confirmations or []},
    }


def test_health_endpoint_is_live_and_does_not_enable_api_docs() -> None:
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_decision_endpoint_maps_safe_action_to_strict_bounded_response() -> None:
    response = client.post(
        "/v1/decision", json=_request({"type": "respond", "content": "Done"})
    )

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "allow"
    assert body["reason_codes"] == ["BENIGN_ACTION"]
    assert set(body) == {
        "decision",
        "risk_score",
        "confidence",
        "reason_codes",
        "explanation",
        "rewritten_action",
        "metadata",
    }
    assert len(response.content) < 64_000
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_decision_endpoint_blocks_unauthorized_tool_without_echoing_payload() -> None:
    secret = "customer-secret-value"
    response = client.post(
        "/v1/decision",
        json=_request(
            {"type": "tool_call", "tool": "email_send", "arguments": {"body": secret}}
        ),
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "block"
    assert "UNAUTHORIZED_TOOL" in response.json()["reason_codes"]
    assert secret not in response.text


def test_decision_endpoint_escalates_consequential_action_without_matching_confirmation() -> None:
    response = client.post(
        "/v1/decision",
        json=_request(
            {"type": "tool_call", "tool": "payment_execute", "arguments": {"amount": 25}}
        ),
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "escalate"
    assert response.json()["reason_codes"] == ["CONFIRMATION_REQUIRED"]


def test_decision_endpoint_ignores_unknown_request_envelope_fields() -> None:
    payload = _request({"type": "respond", "content": "Done"})
    payload["future_protocol_field"] = {"ignored": True}

    response = client.post("/v1/decision", json=payload)

    assert response.status_code == 200
    assert response.json()["decision"] == "allow"


def test_invalid_request_error_is_sanitized_and_has_no_cache() -> None:
    secret = "do-not-repeat-this-customer-value"
    response = client.post(
        "/v1/decision",
        json={"user_goal": secret, "candidate_action": {"type": "tool_call"}},
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid SENTINEL request"}
    assert secret not in response.text
    assert "cache-control" in response.headers
    assert response.headers["cache-control"] == "no-store"


def test_valid_request_policy_exception_fails_closed_without_leaking_exception(
    monkeypatch: Any,
) -> None:
    secret = "sensitive internals must not escape"

    def explode(_request: object) -> object:
        raise RuntimeError(secret)

    monkeypatch.setattr(app_module, "decide", explode)
    response = client.post(
        "/v1/decision", json=_request({"type": "respond", "content": "safe"})
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "block"
    assert response.json()["reason_codes"] == ["INTERNAL_EVALUATION_FAILED"]
    assert secret not in response.text


def test_response_contract_rejects_unknown_fields_and_rewrite_without_action() -> None:
    from aegisgraph.sentinel import SentinelResponse
    from pydantic import ValidationError

    for payload in (
        {
            "decision": "allow",
            "risk_score": 0.1,
            "confidence": 0.9,
            "unexpected": True,
        },
        {
            "decision": "rewrite",
            "risk_score": 0.1,
            "confidence": 0.9,
        },
    ):
        try:
            SentinelResponse.model_validate(payload)
        except ValidationError:
            pass
        else:
            raise AssertionError("invalid SENTINEL response shape was accepted")


def test_rewrite_decision_is_serialized_as_strict_sentinel_shape() -> None:
    from aegisgraph.contracts import CandidateAction, GuardDecision, Verdict

    rewrite = GuardDecision(
        verdict=Verdict.REWRITE,
        risk_score=0.2,
        confidence=0.99,
        reason_codes=("SAFE_REWRITE",),
        rewritten_action=CandidateAction(
            type="respond", content="Redacted", final=True
        ),
    )
    wire_response = app_module._to_wire_response(rewrite)

    encoded = json.loads(wire_response.model_dump_json())
    assert encoded["decision"] == "rewrite"
    assert encoded["rewritten_action"]["content"] == "Redacted"


def test_decision_endpoint_rejects_wrong_method() -> None:
    assert client.get("/v1/decision").status_code == 405
    assert client.post("/healthz").status_code == 405
