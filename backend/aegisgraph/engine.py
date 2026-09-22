"""Deterministic security decisions for proposed agent actions."""

import re
from dataclasses import replace
from enum import IntEnum
from typing import Final

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

_STRONG_INSTRUCTION_MARKERS = re.compile(
    r"\b(ignore|disregard|override|bypass)\b|"
    r"\b(?:you|the agent|the assistant|agent|assistant)\s+"
    r"(?:must|should|need(?:s)? to|has to|is required to)\b",
    re.IGNORECASE,
)
_IMPERATIVE_START = re.compile(
    r"(?:^|[.!?]\s+)[\"']?\s*(?:please\s+|kindly\s+)?"
    r"(?:send|email|message|mail|close|resolve|update|pay|transfer|confirm|execute|"
    r"remediate|isolate|block|remember|store|save|call|write)\b",
    re.IGNORECASE,
)
_ACTION_VERBS = (
    r"send|email|message|mail|close|resolve|update|pay|transfer|confirm|execute|"
    r"remediate|isolate|block|remember|store|save|call|write"
)
_NEGATED_IMPERATIVE = re.compile(
    rf"^(?:do\s+not|don't|never)\s+(?:please\s+|kindly\s+)?(?:{_ACTION_VERBS})\b",
    re.IGNORECASE,
)
_IGNORE_META_INSTRUCTION = re.compile(
    r"^ignore\s+(?:the\s+)?(?:instruction|request|command)\s+to\b",
    re.IGNORECASE,
)
_META_DISCUSSION = re.compile(
    r"\b(?:example|training|quoted?|malicious instruction|prompt[- ]injection|"
    r"do not follow)\b",
    re.IGNORECASE,
)
_QUOTED_SPAN = re.compile(r'"[^"\n]*"|\'[^\'\n]*\'')
_CLAUSE_SPLIT = re.compile(r"[.!?;\n]+")
_CONTRAST_SPLIT = re.compile(r"\b(?:but|instead|then|however)\b", re.IGNORECASE)
_UNTRUSTED_THRESHOLD = TrustLevel.UNTRUSTED_INTERNAL
_ACTION_ALIASES: Final[dict[str, frozenset[str]]] = {
    "email_send": frozenset({"send", "email", "message", "mail"}),
    "ticket_update": frozenset({"close", "resolve", "resolved", "ticket"}),
    "payment_confirm": frozenset({"pay", "payment", "transfer", "confirm"}),
    "payment_execute": frozenset({"pay", "payment", "transfer", "execute"}),
    "remediation_execute": frozenset({"remediate", "isolate", "block", "execute"}),
    "incident_update": frozenset({"close", "update", "incident"}),
    "memory_write": frozenset({"remember", "store", "save", "memory"}),
}
_SIDE_EFFECTING_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "email_draft",
        "email_send",
        "ticket_update",
        "case_note_create",
        "payment_prepare",
        "payment_confirm",
        "payment_execute",
        "incident_create",
        "incident_update",
        "remediation_prepare",
        "remediation_execute",
    }
)
_READ_ONLY_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "email_search",
        "email_read",
        "document_search",
        "document_read",
        "wiki_search",
        "ticket_read",
        "customer_lookup",
        "account_summary",
        "case_document_read",
        "policy_search",
        "alert_search",
        "alert_read",
        "asset_lookup",
        "intel_search",
    }
)
VERDICT_SEVERITY: Final[dict[str, int]] = {
    Verdict.ALLOW.value: 0,
    Verdict.REWRITE.value: 1,
    Verdict.ESCALATE.value: 2,
    Verdict.BLOCK.value: 3,
}


class ActionEffect(IntEnum):
    INERT = 0
    READ_OR_CONFIRM = 1
    WRITE = 2
    PERSISTENT_OR_CONSEQUENTIAL = 3


def decide(request: SentinelRequest) -> GuardDecision:
    """Evaluate one SENTINEL request without side effects or external calls."""

    try:
        adapted = adapt_request(request)
    except Exception:
        return _failure_decision(
            "ADAPTER_VALIDATION_FAILED",
            "The request could not be safely normalized for policy evaluation.",
        )
    try:
        facts = parse_policy_facts(adapted.request.policy_context)
    except Exception:
        return _failure_decision(
            "POLICY_VALIDATION_FAILED",
            "The policy context could not be safely validated.",
        )
    try:
        return _evaluate(adapted, facts, skip_confirmation=False)
    except Exception:
        return _failure_decision(
            "INTERNAL_EVALUATION_FAILED",
            "The request could not be safely evaluated.",
        )


def validate_rewrite(request: SentinelRequest, rewritten_action: CandidateAction) -> GuardDecision:
    """Close the organizer rewrite trap by revalidating the exact replacement."""

    try:
        adapted = adapt_request(request)
    except Exception:
        return _failure_decision(
            "ADAPTER_VALIDATION_FAILED",
            "The request could not be safely normalized for policy evaluation.",
        )
    try:
        facts = parse_policy_facts(adapted.request.policy_context)
    except Exception:
        return _failure_decision(
            "POLICY_VALIDATION_FAILED",
            "The policy context could not be safely validated.",
        )
    try:
        return _validate_rewrite(adapted, facts, rewritten_action)
    except Exception:
        return _failure_decision(
            "INTERNAL_EVALUATION_FAILED",
            "The rewrite could not be safely evaluated.",
        )


def _validate_rewrite(
    adapted: AdaptedRequest, facts: PolicyFacts, rewritten_action: CandidateAction
) -> GuardDecision:
    original = adapted.request.candidate_action
    if not original.final and rewritten_action.final:
        return _block("REWRITE_FINALITY_ESCALATION", 1.0, adapted)
    if (
        original.type is ActionKind.REQUEST_CONFIRMATION
        and rewritten_action.type is not ActionKind.REQUEST_CONFIRMATION
    ):
        return _block("REWRITE_CONFIRMATION_BYPASS", 1.0, adapted)
    if (
        original.type is ActionKind.RESPOND
        and original.final
        and (rewritten_action.type is not ActionKind.RESPOND)
    ):
        return _block("REWRITE_FINAL_ACTION_CHANGED", 1.0, adapted)

    original_decision = _evaluate(adapted, facts, skip_confirmation=False)
    if VERDICT_SEVERITY[original_decision.verdict.value] > VERDICT_SEVERITY[Verdict.ALLOW.value]:
        return GuardDecision(
            verdict=Verdict.BLOCK,
            risk_score=max(0.95, original_decision.risk_score),
            confidence=original_decision.confidence,
            reason_codes=(
                "REWRITE_ENFORCEMENT_DOWNGRADE",
                *original_decision.reason_codes,
            )[:16],
            explanation="A rewrite cannot reduce the original action's enforcement level.",
            metadata=original_decision.metadata,
        )

    rewritten_request = adapted.request.model_copy(update={"candidate_action": rewritten_action})
    rewritten = replace(adapted, request=rewritten_request)
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
    if original.type is ActionKind.RESPOND and rewritten_action.type is ActionKind.MEMORY_WRITE:
        return _block("REWRITE_EFFECT_ESCALATION", 1.0, adapted)
    original_effect = _action_effect(original, facts)
    rewritten_effect = _action_effect(rewritten_action, facts)
    if (
        rewritten_effect > original_effect
        and rewritten_effect >= ActionEffect.WRITE
        and rewritten_action.digest() not in adapted.confirmations_granted
    ):
        return _block("REWRITE_EFFECT_ESCALATION", 0.98, adapted)
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
    if adapted.evidence_truncated and action.type is not ActionKind.RESPOND:
        return _block("EVIDENCE_TRUNCATED", 0.96, adapted)
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
    return any(
        _observation_couples(action, observation.content)
        for observation in adapted.request.observations
        if list(TrustLevel).index(observation.trust_level)
        >= list(TrustLevel).index(_UNTRUSTED_THRESHOLD)
    )


def _observation_couples(action: CandidateAction, content: str) -> bool:
    if not content or not _looks_instructional(content):
        return False
    lowered = content.lower()
    if action.type is ActionKind.MEMORY_WRITE:
        return True
    if action.tool is not None:
        tool_tokens = {action.tool.lower(), action.tool.lower().replace("_", " ")}
        if any(token in lowered for token in tool_tokens):
            return True
        aliases = _ACTION_ALIASES.get(action.tool, frozenset())
        if any(re.search(rf"\b{re.escape(alias)}\b", lowered) for alias in aliases):
            return True
    argument_values = (
        value.strip().lower()
        for value in action.arguments.values()
        if isinstance(value, str) and len(value.strip()) >= 4
    )
    if any(value in lowered for value in argument_values):
        return True
    return action.tool in _SIDE_EFFECTING_TOOLS


def _looks_instructional(content: str) -> bool:
    normalized = content.strip()
    if _META_DISCUSSION.search(normalized) is not None:
        normalized = _QUOTED_SPAN.sub(" ", normalized)
    for clause in _CLAUSE_SPLIT.split(normalized):
        cleaned = clause.strip(" \t\r\n\"'")
        if not cleaned:
            continue
        contrast_parts = [part.strip() for part in _CONTRAST_SPLIT.split(cleaned)]
        first = contrast_parts[0]
        if (
            _NEGATED_IMPERATIVE.search(first) is not None
            or _IGNORE_META_INSTRUCTION.search(first) is not None
        ):
            if any(_clause_is_active(part) for part in contrast_parts[1:]):
                return True
            continue
        if _clause_is_active(cleaned):
            return True
    return False


def _clause_is_active(clause: str) -> bool:
    return (
        _STRONG_INSTRUCTION_MARKERS.search(clause) is not None
        or _IMPERATIVE_START.search(clause) is not None
    )


def _action_effect(action: CandidateAction, facts: PolicyFacts) -> ActionEffect:
    if action.type is ActionKind.RESPOND:
        return ActionEffect.INERT
    if action.type is ActionKind.REQUEST_CONFIRMATION:
        return ActionEffect.READ_OR_CONFIRM
    if action.type is ActionKind.MEMORY_WRITE:
        return ActionEffect.PERSISTENT_OR_CONSEQUENTIAL
    if requires_confirmation(action, facts):
        return ActionEffect.PERSISTENT_OR_CONSEQUENTIAL
    if action.tool in _READ_ONLY_TOOLS:
        return ActionEffect.READ_OR_CONFIRM
    return ActionEffect.WRITE


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


def _failure_decision(code: str, explanation: str) -> GuardDecision:
    return GuardDecision(
        verdict=Verdict.BLOCK,
        risk_score=1.0,
        confidence=1.0,
        reason_codes=(code,),
        explanation=explanation,
        metadata={},
    )
