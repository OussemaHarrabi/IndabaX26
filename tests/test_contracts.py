import aegisgraph.contracts as contracts
import pytest
from aegisgraph.contracts import Sensitivity, TrustLevel
from pydantic import ValidationError


def test_trust_and_sensitivity_have_security_ordering() -> None:
    assert TrustLevel.SYSTEM_POLICY < TrustLevel.AUTHENTICATED_USER
    assert TrustLevel.AUTHENTICATED_USER < TrustLevel.TRUSTED_INTERNAL
    assert TrustLevel.TRUSTED_INTERNAL < TrustLevel.UNTRUSTED_INTERNAL
    assert TrustLevel.UNTRUSTED_INTERNAL < TrustLevel.UNTRUSTED_EXTERNAL
    assert TrustLevel.UNTRUSTED_EXTERNAL < TrustLevel.ADVERSARY_CONTROLLED

    assert Sensitivity.PUBLIC < Sensitivity.INTERNAL
    assert Sensitivity.INTERNAL < Sensitivity.CONFIDENTIAL
    assert Sensitivity.CONFIDENTIAL < Sensitivity.RESTRICTED


def test_candidate_action_enforces_shape_and_is_frozen() -> None:
    action = contracts.CandidateAction(
        type="tool_call",
        tool="payment_confirm",
        arguments={"amount": 12},
    )

    with pytest.raises(ValidationError, match="require 'tool'"):
        contracts.CandidateAction(type="tool_call")
    with pytest.raises(ValidationError, match="only respond actions can be final"):
        contracts.CandidateAction(type="memory_write", content="note", final=True)
    with pytest.raises(ValidationError, match="frozen"):
        action.tool = "other"  # type: ignore[misc]


def test_action_digest_binds_exact_top_level_and_nested_action_semantics() -> None:
    first = contracts.CandidateAction(
        type="tool_call",
        tool="payment_confirm",
        arguments={"note": "a   b\n c", "amount": 12.0},
    )
    second = contracts.CandidateAction(
        type="tool_call",
        tool="payment_confirm",
        arguments={"amount": 12, "note": "a b c"},
    )
    first_confirmation = contracts.CandidateAction(
        type="request_confirmation", confirmation_for=first, content="Approve?"
    )
    second_confirmation = contracts.CandidateAction(
        type="request_confirmation", confirmation_for=second, content="Approve?"
    )
    non_final = contracts.CandidateAction(type="respond", content="Done", final=False)
    final = contracts.CandidateAction(type="respond", content="Done", final=True)

    assert first.digest() != second.digest()
    assert first_confirmation.digest() != second_confirmation.digest()
    assert non_final.digest() != final.digest()
    assert len(first.digest()) == 24


def test_action_digest_is_stable_across_argument_key_order_and_json_round_trip() -> None:
    first = contracts.CandidateAction(
        type="tool_call",
        tool="payment_confirm",
        arguments={"note": "exact spacing", "amount": 12.0},
    )
    second = contracts.CandidateAction.model_validate_json(first.model_dump_json())
    reordered = contracts.CandidateAction(
        type="tool_call",
        tool="payment_confirm",
        arguments={"amount": 12.0, "note": "exact spacing"},
    )

    assert first.digest() == second.digest() == reordered.digest()


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_candidate_action_rejects_non_finite_float_arguments(value: float) -> None:
    with pytest.raises(ValidationError, match="finite"):
        contracts.CandidateAction(
            type="tool_call", tool="payment_confirm", arguments={"amount": value}
        )


def test_canonical_nested_mappings_are_deeply_immutable_and_serializable() -> None:
    action = contracts.CandidateAction(
        type="tool_call", tool="email_send", arguments={"recipient": "ops@example.com"}
    )
    request = contracts.GuardRequest(
        request_id="req-immutable",
        user_goal="Send the approved notice",
        candidate_action=action,
        policy_context={"limits": {"recipients": ["ops@example.com"]}},
    )
    decision = contracts.GuardDecision(
        verdict="allow",
        risk_score=0.1,
        confidence=0.9,
        metadata={"evidence": {"checks": ["recipient_allowlist"]}},
    )
    original_digest = action.digest()

    with pytest.raises(TypeError):
        action.arguments["recipient"] = "attacker@example.com"  # type: ignore[index]
    with pytest.raises(TypeError):
        request.policy_context["limits"]["recipients"] = []  # type: ignore[index]
    with pytest.raises(AttributeError):
        decision.metadata["evidence"]["checks"].append("changed")  # type: ignore[union-attr]

    assert action.digest() == original_digest
    assert request.model_dump(mode="json")["policy_context"] == {
        "limits": {"recipients": ["ops@example.com"]}
    }
    assert decision.model_dump_json()


def test_guard_contracts_are_bounded_and_contain_no_evaluator_fields() -> None:
    observation = contracts.Observation(
        kind="message",
        content="Vendor email",
        source="mailbox/vendor",
        trust_level="untrusted_external",
        sensitivity="confidential",
    )
    action = contracts.CandidateAction(type="respond", content="Received", final=True)
    request = contracts.GuardRequest(
        request_id="req-1",
        user_goal="Review the vendor message",
        observations=(observation,),
        candidate_action=action,
    )
    decision = contracts.GuardDecision(
        verdict="allow",
        risk_score=0.1,
        confidence=0.9,
        reason_codes=("TRUSTED_RESULT",),
    )
    receipt = contracts.DecisionReceipt(
        request_id=request.request_id,
        action_digest=action.digest(),
        decision=decision,
    )

    assert receipt.decision.verdict == "allow"
    for model in (
        contracts.Observation,
        contracts.CandidateAction,
        contracts.GuardRequest,
        contracts.GuardDecision,
        contracts.DecisionReceipt,
    ):
        assert "scenario_id" not in model.model_fields
        assert "expected_outcome" not in model.model_fields
        assert "chain_of_thought" not in model.model_fields

    with pytest.raises(ValidationError):
        contracts.Observation(
            kind="message",
            content="x" * 16_001,
            source="mailbox/vendor",
            trust_level="untrusted_external",
        )
