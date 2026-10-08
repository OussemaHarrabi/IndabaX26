"""Caller-side enforcement boundary tests: a decision bound to an exact action."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from aegisgraph.api_v1 import DEFAULT_POLICY_SET
from aegisgraph.app import app
from aegisgraph.contracts import CandidateAction, PolicyIdentity
from aegisgraph.demo_tools import InertToolbox
from aegisgraph.enforcement import (
    EnforcementOutcome,
    RefusalReason,
    ToolResult,
    enforce,
    execute_guarded,
)
from fastapi.testclient import TestClient

client = TestClient(app)

ALLOWED_TOOLS = ["document_search", "payment_execute"]


def _candidate(action: dict[str, Any]) -> CandidateAction:
    return CandidateAction.model_validate(action)


def _receipt(action: dict[str, Any], *, confirmations: list[str] | None = None) -> dict[str, Any]:
    response = client.post(
        "/api/v1/decisions",
        json={
            "api_version": "aegisgraph/v1",
            "run_id": "enforcement-run",
            "step_id": 4,
            "user_goal": "Perform the requested operational task",
            "conversation": [],
            "candidate_action": action,
            "policy_context": {
                "allowed_tools": ALLOWED_TOOLS,
                "confirmation_required_tools": [],
                "consequential_tools": [],
            },
            "history_digest": {"confirmations_granted": confirmations or []},
        },
    )
    assert response.status_code == 200
    return response.json()


def test_allow_receipt_authorizes_exactly_the_action_it_was_issued_for() -> None:
    action = _candidate(
        {"type": "tool_call", "tool": "document_search", "arguments": {"query": "status"}}
    )
    receipt = _receipt(action.model_dump(mode="json"))

    outcome = enforce(receipt, action, expected_policy=DEFAULT_POLICY_SET)

    assert outcome == EnforcementOutcome(
        allowed=True, reason=None, detail="receipt authorizes this action"
    )


def test_tampered_action_is_refused_with_a_digest_mismatch() -> None:
    approved = _candidate(
        {"type": "tool_call", "tool": "document_search", "arguments": {"query": "status"}}
    )
    tampered = _candidate(
        {"type": "tool_call", "tool": "document_search", "arguments": {"query": "secrets"}}
    )
    receipt = _receipt(approved.model_dump(mode="json"))

    outcome = enforce(receipt, tampered, expected_policy=DEFAULT_POLICY_SET)

    assert outcome.allowed is False
    assert outcome.reason is RefusalReason.DIGEST_MISMATCH


def test_canonical_digest_collisions_are_refused_by_the_execution_digest() -> None:
    int_action = _candidate(
        {"type": "tool_call", "tool": "document_search", "arguments": {"limit": 12}}
    )
    float_variant = _candidate(
        {"type": "tool_call", "tool": "document_search", "arguments": {"limit": 12.0}}
    )
    text_action = _candidate(
        {"type": "tool_call", "tool": "document_search", "arguments": {"query": "12"}}
    )
    padded_variant = _candidate(
        {"type": "tool_call", "tool": "document_search", "arguments": {"query": " 12 "}}
    )

    # The canonical digest is lossy: each pair collides on it but not on the
    # exact execution digest that the receipt and the SDK bind to (F6).
    assert float_variant.digest() == int_action.digest()
    assert padded_variant.digest() == text_action.digest()
    assert float_variant.execution_digest() != int_action.execution_digest()
    assert padded_variant.execution_digest() != text_action.execution_digest()

    for approved, variant in ((int_action, float_variant), (text_action, padded_variant)):
        receipt = _receipt(approved.model_dump(mode="json"))
        outcome = enforce(receipt, variant, expected_policy=DEFAULT_POLICY_SET)
        assert outcome.reason is RefusalReason.DIGEST_MISMATCH


def test_expired_receipt_is_refused() -> None:
    action = _candidate({"type": "respond", "content": "Done"})
    receipt = _receipt(action.model_dump(mode="json"))

    outcome = enforce(
        receipt,
        action,
        expected_policy=DEFAULT_POLICY_SET,
        now=datetime.fromisoformat(receipt["valid_until"]) + timedelta(seconds=1),
    )

    assert outcome.reason is RefusalReason.EXPIRED_RECEIPT


def test_receipt_under_another_policy_is_refused() -> None:
    action = _candidate({"type": "respond", "content": "Done"})
    receipt = _receipt(action.model_dump(mode="json"))

    outcome = enforce(
        receipt, action, expected_policy=PolicyIdentity(id="other-policy", version="1")
    )

    assert outcome.reason is RefusalReason.POLICY_MISMATCH


def test_blocked_decision_is_refused() -> None:
    action = _candidate({"type": "tool_call", "tool": "email_send", "arguments": {"body": "x"}})
    receipt = _receipt(action.model_dump(mode="json"))

    assert receipt["decision"] == "block"
    outcome = enforce(receipt, action, expected_policy=DEFAULT_POLICY_SET)

    assert outcome.reason is RefusalReason.VERDICT_BLOCKED


def test_unresolved_escalation_is_refused() -> None:
    action = _candidate(
        {"type": "tool_call", "tool": "payment_execute", "arguments": {"amount": 25}}
    )
    receipt = _receipt(action.model_dump(mode="json"))

    assert receipt["decision"] == "escalate"
    outcome = enforce(receipt, action, expected_policy=DEFAULT_POLICY_SET)

    assert outcome.reason is RefusalReason.UNRESOLVED_ESCALATION


def test_rewrite_decision_is_refused_until_revalidated() -> None:
    action = _candidate({"type": "respond", "content": "Redacted"})
    receipt = {
        **_receipt({"type": "respond", "content": "Redacted"}),
        "decision": "rewrite",
    }

    outcome = enforce(receipt, action, expected_policy=DEFAULT_POLICY_SET)

    assert outcome.reason is RefusalReason.REWRITE_NOT_REVALIDATED


def test_missing_receipt_is_refused() -> None:
    action = _candidate({"type": "respond", "content": "Done"})

    for receipt in ({}, {"decision": "allow"}):
        outcome = enforce(receipt, action, expected_policy=DEFAULT_POLICY_SET)
        assert outcome.reason is RefusalReason.MISSING_RECEIPT
        assert outcome.detail


def test_malformed_receipt_is_refused() -> None:
    action = _candidate({"type": "respond", "content": "Done"})
    receipt = _receipt({"type": "respond", "content": "Done"})

    without_digests = {key: value for key, value in receipt.items() if key != "action_digest"}
    without_window = {key: value for key, value in receipt.items() if key != "valid_until"}
    unknown_verdict = {**receipt, "decision": "quarantine"}

    for broken in (without_digests, without_window, unknown_verdict):
        outcome = enforce(broken, action, expected_policy=DEFAULT_POLICY_SET)
        assert outcome.reason is RefusalReason.MALFORMED_RECEIPT


@pytest.mark.parametrize("reason", list(RefusalReason))
def test_every_refusal_reason_is_reachable(reason: RefusalReason) -> None:
    action = _candidate({"type": "respond", "content": "Done"})
    allow = _receipt({"type": "respond", "content": "Done"})
    expired = {**allow, "valid_until": (datetime.now(UTC) - timedelta(seconds=1)).isoformat()}
    witnesses: dict[RefusalReason, dict[str, Any]] = {
        RefusalReason.MISSING_RECEIPT: {},
        RefusalReason.MALFORMED_RECEIPT: {**allow, "execution_digest": "not-a-digest"},
        RefusalReason.EXPIRED_RECEIPT: expired,
        RefusalReason.DIGEST_MISMATCH: allow,
        RefusalReason.POLICY_MISMATCH: {**allow, "policy_set": {"id": "other", "version": "1"}},
        RefusalReason.VERDICT_BLOCKED: {**allow, "decision": "block"},
        RefusalReason.UNRESOLVED_ESCALATION: {**allow, "decision": "escalate"},
        RefusalReason.REWRITE_NOT_REVALIDATED: {**allow, "decision": "rewrite"},
    }
    candidate = action
    if reason is RefusalReason.DIGEST_MISMATCH:
        candidate = _candidate({"type": "respond", "content": "Something else"})

    outcome = enforce(witnesses[reason], candidate, expected_policy=DEFAULT_POLICY_SET)

    assert outcome.allowed is False
    assert outcome.reason is reason
    assert outcome.detail


def test_execute_guarded_never_calls_the_executor_on_refusal() -> None:
    tampered = _candidate({"type": "respond", "content": "Tampered"})
    receipt = _receipt({"type": "respond", "content": "Approved"})
    calls: list[CandidateAction] = []

    def executor(action: CandidateAction) -> ToolResult:
        calls.append(action)
        return ToolResult(tool="respond", status="simulated", detail="should not run")

    guarded = execute_guarded(
        executor, receipt, tampered, expected_policy=DEFAULT_POLICY_SET
    )

    assert guarded.executed is False
    assert guarded.result is None
    assert guarded.outcome.reason is RefusalReason.DIGEST_MISMATCH
    assert calls == []


def test_execute_guarded_runs_an_authorized_action_through_an_inert_tool() -> None:
    action = _candidate(
        {"type": "tool_call", "tool": "document_search", "arguments": {"query": "status"}}
    )
    receipt = _receipt(action.model_dump(mode="json"))
    toolbox = InertToolbox()

    guarded = execute_guarded(
        toolbox.executor, receipt, action, expected_policy=DEFAULT_POLICY_SET
    )

    assert guarded.executed is True
    assert guarded.result is not None
    assert guarded.result.status == "simulated"
    assert toolbox.audit() == [
        {"tool": "document_search", "digest": action.execution_digest()}
    ]


def test_enforcement_does_not_mutate_the_receipt() -> None:
    action = _candidate({"type": "respond", "content": "Done"})
    receipt = _receipt({"type": "respond", "content": "Done"})
    snapshot = json.loads(json.dumps(receipt))

    enforce(receipt, action, expected_policy=DEFAULT_POLICY_SET)

    assert receipt == snapshot
