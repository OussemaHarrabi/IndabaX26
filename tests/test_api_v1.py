"""Contract tests for the generic ``aegisgraph/v1`` decision surface."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from importlib import import_module
from pathlib import Path
from typing import Any

import pytest
from aegisgraph.contracts import CandidateAction
from aegisgraph.sentinel import SentinelResponse
from fastapi.testclient import TestClient
from pydantic import ValidationError

app_module = import_module("aegisgraph.app")
api_v1 = import_module("aegisgraph.api_v1")

client = TestClient(app_module.app)

LEGACY_FIELDS = {
    "decision",
    "risk_score",
    "confidence",
    "reason_codes",
    "explanation",
    "rewritten_action",
    "metadata",
}
GENERIC_FIELDS = LEGACY_FIELDS | {
    "api_version",
    "request_id",
    "receipt_id",
    "policy_set",
    "action_digest",
    "execution_digest",
    "decided_at",
    "valid_until",
}


def _request(action: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "api_version": "aegisgraph/v1",
        "run_id": "api-v1-run",
        "step_id": 2,
        "user_goal": "Perform the requested safe task",
        "conversation": [],
        "candidate_action": action,
        "policy_context": {
            "policy_id": "test-policy",
            "policy_version": "1",
            "allowed_tools": ["document_search", "payment_execute"],
            "confirmation_required_tools": [],
            "consequential_tools": [],
        },
        "history_digest": {"confirmations_granted": []},
    }
    payload.update(overrides)
    return payload


def test_generic_endpoint_returns_identity_alongside_the_legacy_fields() -> None:
    response = client.post("/api/v1/decisions", json=_request({"type": "respond", "content": "Ok"}))

    assert response.status_code == 200
    body = response.json()
    assert set(body) == GENERIC_FIELDS
    assert body["api_version"] == "aegisgraph/v1"
    assert body["decision"] == "allow"
    assert body["reason_codes"] == ["BENIGN_ACTION"]
    assert len(response.content) < 64_000


def test_generic_endpoint_requires_the_declared_api_version() -> None:
    payload = _request({"type": "respond", "content": "Ok"})
    payload.pop("api_version")

    missing = client.post("/api/v1/decisions", json=payload)
    wrong = client.post(
        "/api/v1/decisions",
        json={**_request({"type": "respond", "content": "Ok"}), "api_version": "v2"},
    )

    assert missing.status_code == 422
    assert missing.json() == {"detail": "Invalid SENTINEL request"}
    assert wrong.status_code == 422


def test_generic_endpoint_echoes_or_generates_the_request_id() -> None:
    echoed = client.post(
        "/api/v1/decisions",
        json=_request({"type": "respond", "content": "Ok"}, request_id="caller-supplied-7"),
    )
    generated = client.post(
        "/api/v1/decisions", json=_request({"type": "respond", "content": "Ok"})
    )

    assert echoed.json()["request_id"] == "caller-supplied-7"
    generated_id = generated.json()["request_id"]
    assert generated_id and generated_id != echoed.json()["request_id"]


def test_receipt_carries_a_bounded_validity_window() -> None:
    response = client.post("/api/v1/decisions", json=_request({"type": "respond", "content": "Ok"}))
    body = response.json()

    receipt_id = body["receipt_id"]
    assert len(receipt_id) == 32 and int(receipt_id, 16) >= 0
    decided_at = datetime.fromisoformat(body["decided_at"])
    valid_until = datetime.fromisoformat(body["valid_until"])
    assert valid_until - decided_at == timedelta(seconds=60)
    assert decided_at.utcoffset() == timedelta(0)


def test_receipt_ttl_is_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(api_v1.RECEIPT_TTL_ENV, "5")

    body = client.post(
        "/api/v1/decisions", json=_request({"type": "respond", "content": "Ok"})
    ).json()

    decided_at = datetime.fromisoformat(body["decided_at"])
    valid_until = datetime.fromisoformat(body["valid_until"])
    assert valid_until - decided_at == timedelta(seconds=5)


def test_receipt_ttl_falls_back_to_the_default_for_invalid_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(api_v1.RECEIPT_TTL_ENV, "not-a-number")
    assert api_v1.receipt_ttl_seconds() == api_v1.DEFAULT_RECEIPT_TTL_SECONDS
    monkeypatch.setenv(api_v1.RECEIPT_TTL_ENV, "-4")
    assert api_v1.receipt_ttl_seconds() == api_v1.DEFAULT_RECEIPT_TTL_SECONDS


def test_response_digests_describe_the_exact_candidate_action() -> None:
    action = CandidateAction(
        type="tool_call", tool="document_search", arguments={"query": "status report"}
    )
    body = client.post(
        "/api/v1/decisions", json=_request(action.model_dump(mode="json"))
    ).json()

    assert body["action_digest"] == action.digest()
    assert body["execution_digest"] == action.execution_digest()


def test_request_policy_set_is_echoed_and_defaults_to_the_server_policy_set() -> None:
    pinned = client.post(
        "/api/v1/decisions",
        json=_request(
            {"type": "respond", "content": "Ok"},
            policy_set={"id": "tenant-policy", "version": "7"},
        ),
    ).json()
    default = client.post(
        "/api/v1/decisions", json=_request({"type": "respond", "content": "Ok"})
    ).json()

    assert pinned["policy_set"] == {"id": "tenant-policy", "version": "7"}
    assert default["policy_set"] == api_v1.DEFAULT_POLICY_SET.model_dump(mode="json")


def test_version_endpoint_reports_api_policy_and_build_identity() -> None:
    response = client.get("/api/v1/version")

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"api_version", "policy_set", "build"}
    assert body["api_version"] == "aegisgraph/v1"
    assert body["policy_set"] == api_v1.DEFAULT_POLICY_SET.model_dump(mode="json")
    assert set(body["build"]) == {"service", "version", "commit"}
    assert body["build"]["service"] == "aegisgraph"


def test_legacy_endpoint_keeps_its_seven_field_response_and_rejects_extra_fields() -> None:
    payload = _request({"type": "respond", "content": "Ok"})
    payload.pop("api_version")
    response = client.post("/v1/decision", json=payload)

    assert response.status_code == 200
    assert set(response.json()) == LEGACY_FIELDS

    with pytest.raises(ValidationError):
        SentinelResponse.model_validate({**response.json(), "receipt_id": "not-legacy"})


def test_legacy_endpoint_does_not_expose_the_generic_surface() -> None:
    assert client.get("/v1/version").status_code == 404
    assert client.post("/v1/decisions", json={}).status_code == 404


def test_decision_record_is_one_structured_line_without_request_content(
    caplog: pytest.LogCaptureFixture,
) -> None:
    canary = "canary-value-must-not-be-logged"
    with caplog.at_level(logging.INFO, logger="aegisgraph.decision"):
        response = client.post(
            "/api/v1/decisions",
            json=_request({"type": "respond", "content": canary}),
        )

    records = [
        record
        for record in caplog.records
        if record.name == "aegisgraph.decision" and record.levelno == logging.INFO
    ]
    assert len(records) == 1
    line = records[0].getMessage()
    assert canary not in line
    event = json.loads(line)
    assert set(event) == {
        "event",
        "request_id",
        "receipt_id",
        "policy_set",
        "verdict",
        "reason_codes",
        "action_digest",
        "execution_digest",
        "latency_ms",
        "caller",
    }
    assert event["event"] == "decision"
    assert event["caller"] is None
    assert event["request_id"] == response.json()["request_id"]
    assert event["receipt_id"] == response.json()["receipt_id"]
    assert event["verdict"] == response.json()["decision"]
    assert event["reason_codes"] == response.json()["reason_codes"]
    assert event["latency_ms"] >= 0.0


def test_published_schema_matches_the_live_generic_contract() -> None:
    schema_path = Path(__file__).resolve().parents[1] / "docs" / "api" / "decision.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    body = client.post(
        "/api/v1/decisions", json=_request({"type": "respond", "content": "Ok"})
    ).json()

    assert set(schema["response"]["required"]) == set(body)
    assert schema["response"]["additionalProperties"] is False
    assert schema["request"]["properties"]["api_version"]["const"] == "aegisgraph/v1"
    assert schema["$defs"]["candidateAction"]["properties"]["type"]["enum"] == [
        "respond",
        "tool_call",
        "memory_write",
        "request_confirmation",
    ]


def test_generic_boundary_fails_closed_without_leaking_internals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "internal evaluator detail"

    def explode(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError(secret)

    monkeypatch.setattr(api_v1, "evaluate", explode)
    response = client.post("/api/v1/decisions", json=_request({"type": "respond", "content": "Ok"}))

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "block"
    assert body["reason_codes"] == ["INTERNAL_EVALUATION_FAILED"]
    assert secret not in response.text
    assert set(body) == GENERIC_FIELDS
