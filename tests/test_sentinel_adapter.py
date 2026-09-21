import ast
import tomllib
from importlib import import_module
from pathlib import Path

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
                    "timestamp": "2026-09-21T10:30:00Z",
                    "parent_event_ids": ["event-parent"],
                    "tags": ["vendor", "email"],
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
    provenance = request.provenance[0].provenance
    assert provenance.timestamp.isoformat() == "2026-09-21T10:30:00+00:00"
    assert provenance.parent_event_ids == ("event-parent",)
    assert provenance.tags == ("vendor", "email")


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


def test_candidate_actions_enforce_official_per_kind_shapes() -> None:
    adapter = _adapter()
    target = adapter.SentinelCandidateAction(
        type="tool_call",
        tool="email_send",
        arguments={"recipient": "ops@example.com"},
    )

    assert adapter.SentinelCandidateAction(type="respond", content="Done", final=True)
    assert adapter.SentinelCandidateAction(type="memory_write", content="Approved")
    assert adapter.SentinelCandidateAction(
        type="request_confirmation", confirmation_for=target, content="Approve?"
    )

    invalid_actions = (
        {"type": "tool_call"},
        {"type": "tool_call", "tool": "BAD TOOL"},
        {"type": "tool_call", "tool": "email_send", "content": "not allowed"},
        {"type": "respond"},
        {"type": "respond", "content": "Done", "tool": "email_send"},
        {"type": "memory_write", "content": "note", "arguments": {"x": 1}},
        {"type": "request_confirmation"},
        {
            "type": "request_confirmation",
            "confirmation_for": {"type": "respond", "content": "wrong target"},
        },
        {"type": "memory_write", "content": "note", "final": True},
    )
    for payload in invalid_actions:
        with pytest.raises(ValidationError):
            adapter.SentinelCandidateAction.model_validate(payload)


def test_action_argument_boundaries_and_nested_contract_use() -> None:
    adapter = _adapter()
    valid_arguments = {f"arg_{index}": "x" * 8_000 for index in range(32)}
    action = adapter.SentinelCandidateAction(
        type="tool_call", tool="email_send", arguments=valid_arguments
    )
    assert len(action.arguments) == 32

    with pytest.raises(ValidationError, match="at most 32"):
        adapter.SentinelCandidateAction(
            type="tool_call",
            tool="email_send",
            arguments=valid_arguments | {"arg_32": "x"},
        )
    with pytest.raises(ValidationError, match="8000"):
        adapter.SentinelCandidateAction(
            type="tool_call", tool="email_send", arguments={"body": "x" * 8_001}
        )

    request_payload = _request_payload()
    request_payload["candidate_action"] = {
        "type": "tool_call",
        "tool": "email_send",
        "final": True,
    }
    with pytest.raises(ValidationError, match="only respond actions can be final"):
        adapter.SentinelRequest.model_validate(request_payload)
    with pytest.raises(ValidationError, match="tool_call actions require 'tool'"):
        adapter.SentinelResponse.model_validate(
            {
                "decision": "rewrite",
                "risk_score": 0.8,
                "confidence": 0.9,
                "rewritten_action": {"type": "tool_call"},
            }
        )


def test_conversation_provenance_and_history_use_official_types() -> None:
    adapter = _adapter()
    payload = _request_payload()
    payload["history_digest"] = {
        "steps_taken": 2,
        "turn_index": 1,
        "tool_calls": [
            {"step_id": 1, "tool": "email_send", "decision": "allow", "succeeded": True}
        ],
        "least_trusted_seen": "untrusted_external",
        "most_sensitive_seen": "confidential",
    }

    request = adapter.SentinelRequest.model_validate(payload)

    assert request.history_digest.tool_calls[0].tool == "email_send"
    assert request.history_digest.least_trusted_seen == "untrusted_external"
    assert request.history_digest.most_sensitive_seen == "confidential"
    payload["conversation"] = [{"role": "assistant", "kind": "message", "content": "bad"}]
    with pytest.raises(ValidationError):
        adapter.SentinelRequest.model_validate(payload)


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
    with pytest.raises(ValidationError):
        adapter.SentinelResponse(decision="block", risk_score=0.9, confidence=-0.01)


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


def test_benchmark_lock_matches_pinned_public_suite() -> None:
    root = Path(__file__).parents[1]
    with (root / "benchmark.lock").open("rb") as stream:
        lock = tomllib.load(stream)

    assert lock == {
        "url": "https://github.com/Skan22/Sentinel_Starter_Kit",
        "commit": "dd2e5fe0979d0781a4bfe6d0849cd80cf69ef4a2",
        "expected_scenarios": 40,
        "attacks": 31,
        "benign": 9,
        "hard_negatives": 3,
        "domains": {"enterprise": 15, "finance": 12, "soc": 13},
    }


def test_runtime_sources_exclude_evaluator_and_execution_capabilities() -> None:
    root = Path(__file__).parents[1]
    forbidden_fields = {
        "scenario_id",
        "expected_outcome",
        "chain_of_thought",
        "reasoning_trace",
        "internal_reasoning",
    }
    forbidden_imports = {"httpx", "requests", "socket", "subprocess", "urllib"}

    for path in (root / "backend" / "aegisgraph").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        declared_fields = {
            node.target.id
            for node in ast.walk(tree)
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
        }
        imported_roots: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", maxsplit=1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_roots.add(node.module.split(".", maxsplit=1)[0])
        assert declared_fields.isdisjoint(forbidden_fields), path
        assert imported_roots.isdisjoint(forbidden_imports), path
