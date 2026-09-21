from importlib import import_module

import pytest
from pydantic import ValidationError


def _adapter():
    return import_module("aegisgraph.sentinel")


def _request_payload() -> dict[str, object]:
    return {
        "run_id": "run-1",
        "step_id": 3,
        "user_goal": "Review the message",
        "conversation": [
            {"role": "user", "kind": "message", "content": "Review", "future": True}
        ],
        "observation": {
            "kind": "email",
            "content": "Vendor message",
            "provenance_ids": ["prov-1"],
            "future": True,
        },
        "candidate_action": {"type": "respond", "content": "Reviewed", "final": True},
        "policy_context": {},
        "provenance": [
            {
                "id": "prov-1",
                "provenance": {
                    "source_type": "email",
                    "source_id": "vendor-1",
                    "trust_level": "untrusted_external",
                    "origin_actor": "vendor",
                    "retrieved_via": "mailbox",
                    "sensitivity": "internal",
                    "future": True,
                },
            }
        ],
        "history_digest": {"steps_taken": 2, "turn_index": 1, "future": True},
        "future_envelope_field": {"added": "later"},
    }


def test_request_envelope_and_views_ignore_unknown_fields() -> None:
    adapter = _adapter()

    request = adapter.SentinelRequest.model_validate(_request_payload())

    assert request.run_id == "run-1"
    assert "future_envelope_field" not in request.model_dump()
    assert "future" not in request.conversation[0].model_dump()


def test_request_rejects_oversized_policy_context() -> None:
    adapter = _adapter()
    payload = _request_payload()
    payload["policy_context"] = {"blob": "x" * 16_385}

    with pytest.raises(ValidationError, match="16384 bytes"):
        adapter.SentinelRequest.model_validate(payload)


def test_response_and_candidate_actions_forbid_unknown_fields() -> None:
    adapter = _adapter()

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        adapter.SentinelResponse(
            decision="allow",
            risk_score=0.1,
            confidence=0.9,
            future=True,
        )
    payload = _request_payload()
    payload["candidate_action"] = {
        "type": "respond",
        "content": "Reviewed",
        "future": True,
    }
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        adapter.SentinelRequest.model_validate(payload)


@pytest.mark.parametrize(
    "kind",
    ["respond", "tool_call", "memory_write", "request_confirmation"],
)
def test_adapter_accepts_all_v1_action_kinds(kind: str) -> None:
    adapter = _adapter()
    assert adapter.SentinelCandidateAction(type=kind).type == kind


def test_response_enforces_rewrite_and_score_consistency() -> None:
    adapter = _adapter()
    rewritten = adapter.SentinelCandidateAction(type="respond", content="Safe")

    adapter.SentinelResponse(
        decision="rewrite",
        risk_score=0.8,
        confidence=0.9,
        rewritten_action=rewritten,
    )
    with pytest.raises(ValidationError, match="required for, and only for"):
        adapter.SentinelResponse(decision="rewrite", risk_score=0.8, confidence=0.9)
    with pytest.raises(ValidationError, match="required for, and only for"):
        adapter.SentinelResponse(
            decision="allow",
            risk_score=0.1,
            confidence=0.9,
            rewritten_action=rewritten,
        )
    with pytest.raises(ValidationError):
        adapter.SentinelResponse(decision="block", risk_score=1.01, confidence=0.9)


def test_response_bounds_reason_codes_explanation_and_metadata() -> None:
    adapter = _adapter()
    base = {"decision": "block", "risk_score": 0.9, "confidence": 0.8}

    for invalid in ("lower_case", "HAS-DASH", "A", "_PREFIX"):
        with pytest.raises(ValidationError, match="UPPER_SNAKE_CASE"):
            adapter.SentinelResponse(**base, reason_codes=[invalid])
    with pytest.raises(ValidationError):
        adapter.SentinelResponse(**base, reason_codes=[f"CODE_{i}" for i in range(17)])
    with pytest.raises(ValidationError):
        adapter.SentinelResponse(**base, explanation="x" * 501)
    with pytest.raises(ValidationError, match="4096 bytes"):
        adapter.SentinelResponse(**base, metadata={"data": "x" * 4_097})
