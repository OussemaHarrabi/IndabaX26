"""Deterministic security decisions for proposed agent actions."""

import re
from dataclasses import replace

from aegisgraph.adapter import AdaptedRequest, adapt_request
from aegisgraph.contracts import (
    ActionKind,
    CandidateAction,
    GuardDecision,
    Sensitivity,
    TrustLevel,
    Verdict,
)
from aegisgraph.policy import (
    PolicyFacts,
    parse_policy_facts,
    recipient_is_external,
    requires_confirmation,
)
from aegisgraph.sentinel import SentinelRequest

_INSTRUCTION_MARKERS = re.compile(
    r"\b(ignore|disregard|override|bypass|must|immediately|always|never|execute|call|send|"
    r"transfer|close|remember|store|write)\b",
    re.IGNORECASE,
)
_UNTRUSTED_THRESHOLD = TrustLevel.UNTRUSTED_INTERNAL


def decide(request: SentinelRequest) -> GuardDecision:
    """Evaluate one SENTINEL request without side effects or external calls."""

    adapted = adapt_request(request)
    facts = parse_policy_facts(adapted.request.policy_context)
    return _evaluate(adapted, facts, skip_confirmation=False)


def validate_rewrite(request: SentinelRequest, rewritten_action: CandidateAction) -> GuardDecision:
    """Close the organizer rewrite trap by revalidating the exact replacement."""

    adapted = adapt_request(request)
    original = adapted.request.candidate_action
    if not original.final and rewritten_action.final:
        return _block("REWRITE_FINALITY_ESCALATION", 1.0, adapted)
    if (
        original.type is ActionKind.REQUEST_CONFIRMATION
        and rewritten_action.type is not ActionKind.REQUEST_CONFIRMATION
    ):
        return _block("REWRITE_CONFIRMATION_BYPASS", 1.0, adapted)

    rewritten_request = adapted.request.model_copy(update={"candidate_action": rewritten_action})
    rewritten = replace(adapted, request=rewritten_request)
    facts = parse_policy_facts(rewritten.request.policy_context)
    evaluated = _evaluate(rewritten, facts, skip_confirmation=False)
    if evaluated.verdict is not Verdict.ALLOW:
        return GuardDecision(
            verdict=Verdict.BLOCK,
            risk_score=max(0.95, evaluated.risk_score),
            confidence=evaluated.confidence,
            reason_codes=("UNSAFE_REWRITE", *evaluated.reason_codes)[:16],
            explanation="The proposed rewrite failed mandatory policy revalidation.",
            metadata=evaluated.metadata,
        )
    return GuardDecision(
        verdict=Verdict.REWRITE,
        risk_score=max(0.2, evaluated.risk_score),
        confidence=0.99,
        reason_codes=("SAFE_REWRITE",),
        explanation="The replacement action passed the same checks as a direct action.",
        rewritten_action=rewritten_action,
        metadata=evaluated.metadata,
    )


def _evaluate(
    adapted: AdaptedRequest, facts: PolicyFacts, *, skip_confirmation: bool
) -> GuardDecision:
    if not facts.valid:
        return _block("POLICY_CONTEXT_INVALID", 0.98, adapted)
    if not adapted.provenance_complete:
        return _block("PROVENANCE_INCOMPLETE", 0.97, adapted)

    action = adapted.request.candidate_action
    if action.type is ActionKind.REQUEST_CONFIRMATION:
        target = action.confirmation_for
        if target is None:
            return _block("INVALID_CONFIRMATION_TARGET", 1.0, adapted)
        targeted_request = adapted.request.model_copy(update={"candidate_action": target})
        target_adapted = replace(adapted, request=targeted_request)
        target_result = _evaluate(target_adapted, facts, skip_confirmation=True)
        if target_result.verdict is not Verdict.ALLOW:
            return target_result
        return _decision(
            Verdict.ALLOW,
            0.18,
            "CONFIRMATION_REQUEST_SAFE",
            adapted,
            "The confirmation target is allowed and policy-valid.",
        )

    if action.type is ActionKind.TOOL_CALL and action.tool not in facts.allowed_tools:
        return _block("UNAUTHORIZED_TOOL", 1.0, adapted)

    if action.type is ActionKind.MEMORY_WRITE and _has_untrusted_evidence(adapted):
        return _block("MEMORY_POISONING", 0.96, adapted)

    if action.type in {ActionKind.TOOL_CALL, ActionKind.MEMORY_WRITE} and _coupled_instruction(
        action, adapted
    ):
        return _block("UNTRUSTED_INSTRUCTION", 0.99, adapted)

    if _is_sensitive_external_flow(action, adapted, facts):
        return _block("SENSITIVE_DATA_EXFILTRATION", 1.0, adapted)

    if action.type is ActionKind.TOOL_CALL and requires_confirmation(action, facts):
        if not skip_confirmation and action.digest() not in adapted.confirmations_granted:
            return _decision(
                Verdict.ESCALATE,
                0.72,
                "CONFIRMATION_REQUIRED",
                adapted,
                "A matching confirmation digest is required before execution.",
            )
        reason = "CONFIRMATION_VERIFIED" if not skip_confirmation else "POLICY_CHECKS_PASSED"
        return _decision(
            Verdict.ALLOW,
            0.16,
            reason,
            adapted,
            "The consequential action is policy-valid and confirmation-bound.",
        )

    if action.type is ActionKind.RESPOND:
        return _decision(
            Verdict.ALLOW,
            0.05,
            "BENIGN_ACTION",
            adapted,
            "A response has no tool or memory side effect.",
        )
    return _decision(
        Verdict.ALLOW,
        0.08,
        "POLICY_CHECKS_PASSED",
        adapted,
        "The action passed deterministic policy and provenance checks.",
    )


def _is_sensitive_external_flow(
    action: CandidateAction, adapted: AdaptedRequest, facts: PolicyFacts
) -> bool:
    return (
        action.type is ActionKind.TOOL_CALL
        and list(Sensitivity).index(adapted.max_sensitivity)
        >= list(Sensitivity).index(Sensitivity.CONFIDENTIAL)
        and recipient_is_external(action, facts)
    )


def _has_untrusted_evidence(adapted: AdaptedRequest) -> bool:
    return any(
        list(TrustLevel).index(observation.trust_level)
        >= list(TrustLevel).index(_UNTRUSTED_THRESHOLD)
        for observation in adapted.request.observations
    )


def _coupled_instruction(action: CandidateAction, adapted: AdaptedRequest) -> bool:
    untrusted_text = "\n".join(
        observation.content
        for observation in adapted.request.observations
        if list(TrustLevel).index(observation.trust_level)
        >= list(TrustLevel).index(_UNTRUSTED_THRESHOLD)
    )
    if not untrusted_text or _INSTRUCTION_MARKERS.search(untrusted_text) is None:
        return False
    lowered = untrusted_text.lower()
    if action.type is ActionKind.MEMORY_WRITE:
        return True
    if action.tool is not None:
        tool_tokens = {action.tool.lower(), action.tool.lower().replace("_", " ")}
        if any(token in lowered for token in tool_tokens):
            return True
    argument_values = (
        value.strip().lower()
        for value in action.arguments.values()
        if isinstance(value, str) and len(value.strip()) >= 4
    )
    return any(value in lowered for value in argument_values)


def _block(code: str, risk: float, adapted: AdaptedRequest) -> GuardDecision:
    return _decision(
        Verdict.BLOCK,
        risk,
        code,
        adapted,
        "A mandatory security invariant rejected the proposed action.",
    )


def _decision(
    verdict: Verdict,
    risk: float,
    code: str,
    adapted: AdaptedRequest,
    explanation: str,
) -> GuardDecision:
    return GuardDecision(
        verdict=verdict,
        risk_score=risk,
        confidence=0.99,
        reason_codes=(code,),
        explanation=explanation,
        metadata={
            "least_trust": adapted.least_trust.value,
            "max_sensitivity": adapted.max_sensitivity.value,
        },
    )
