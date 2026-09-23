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
    Observation,
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

_ACTION_VERBS = (
    r"send|email|message|mail|draft|compose|search|find|lookup|look\s+up|read|open|"
    r"review|summarize|close|resolve|update|create|add|prepare|plan|initiate|approve|"
    r"pay|transfer|confirm|execute|remediate|isolate|block|remember|store|save|call|"
    r"use|write"
)
_SUBJECT_MODAL = re.compile(
    rf"^(?:(?:the\s+)?(?:agent|assistant)|you)\s+"
    r"(?:must|should|need(?:s)?\s+to|has\s+to|is\s+required\s+to)\s+"
    rf"(?P<negation>not\s+|never\s+)?(?:{_ACTION_VERBS})\b",
    re.IGNORECASE,
)
_DISCOURSE_PREFIX = re.compile(
    r"^(?:now|then|next|immediately|instead|finally|first|second(?:ly)?|"
    r"subsequently|afterwards?|after\s+that|always|from\s+now\s+on|"
    r"in\s+the\s+future)\b[\s,;:\-]*",
    re.IGNORECASE,
)
_IMPERATIVE = re.compile(
    rf"^(?:please\s+|kindly\s+)?(?:{_ACTION_VERBS})\b",
    re.IGNORECASE,
)
_NEGATED_IMPERATIVE = re.compile(
    rf"^(?:do\s+not|don't|never)\s+(?:please\s+|kindly\s+)?(?:{_ACTION_VERBS})\b",
    re.IGNORECASE,
)
_BARE_MODAL_NEGATION = re.compile(
    rf"^(?:must|should|need\s+to|is\s+required\s+to)\s+(?:not|never)\s+"
    rf"(?:{_ACTION_VERBS})\b",
    re.IGNORECASE,
)
_IGNORE_META_INSTRUCTION = re.compile(
    r"^ignore\s+(?:(?:this|that|the)\s+)?(?:instruction|request|command)"
    r"(?:\s+to\b|\s*$)",
    re.IGNORECASE,
)
_OVERRIDE_DIRECTIVE = re.compile(
    r"^(?:ignore|disregard|override|bypass)\b",
    re.IGNORECASE,
)
_QUOTE_FORWARD_NEGATION = re.compile(
    r"(?:\b(?:do\s+not|don't|never)\s+(?:follow|execute|obey|act\s+on)\s+"
    r"(?:this|that|the)\s+(?:instruction|request|command)|"
    r"\b(?:ignore|disregard)\s+(?:this|that|the)\s+"
    r"(?:instruction|request|command))\s*[:\-]\s*$",
    re.IGNORECASE,
)
_QUOTE_BACKWARD_NEGATION = re.compile(
    r"\b(?:do\s+not|don't|never)\s+(?:follow|execute|obey|act\s+on)\b|"
    r"\bignore\s+(?:this|that|the)\s+(?:instruction|request|command)\b",
    re.IGNORECASE,
)
_QUOTED_SPAN = re.compile(r'"[^"\n]*"|\'[^\'\n]*\'')
_CLAUSE_SPLIT = re.compile(r"[.!?;:\n]+")
_CONTRAST_SPLIT = re.compile(r"\b(?:but|instead|then|however)\b", re.IGNORECASE)
_INCOMPLETE_SUBJECT_FRAGMENT = re.compile(
    r"^(?:(?:the\s+)?(?:agent|assistant)|you)"
    r"(?:\s+(?:"
    r"(?:must|should)(?:\s+(?:not|never))?|"
    r"need(?:s)?(?:\s+to)?(?:\s+(?:not|never))?|"
    r"has(?:\s+to)?(?:\s+(?:not|never))?|"
    r"is(?:\s+required)?(?:\s+to)?(?:\s+(?:not|never))?"
    r"))?$",
    re.IGNORECASE,
)
_MAX_ADJACENT_COMPOSITION_OBSERVATIONS = 3
_MAX_ADJACENT_COMPOSITION_CHARS = 512
_UNTRUSTED_THRESHOLD = TrustLevel.UNTRUSTED_INTERNAL
_TOOL_SEMANTICS: Final[
    dict[str, tuple[frozenset[str], frozenset[str], frozenset[str]]]
] = {
    "email_search": (
        frozenset({"search", "find", "lookup"}),
        frozenset({"email", "mail", "message", "inbox"}),
        frozenset(),
    ),
    "email_read": (
        frozenset({"read", "open", "review"}),
        frozenset({"email", "mail", "message"}),
        frozenset(),
    ),
    "email_draft": (
        frozenset({"draft", "compose", "write"}),
        frozenset({"email", "mail", "message"}),
        frozenset({"draft", "compose"}),
    ),
    "email_send": (
        frozenset({"send", "email", "mail", "message"}),
        frozenset({"email", "mail", "message"}),
        frozenset({"send", "email", "mail", "message"}),
    ),
    "document_search": (
        frozenset({"search", "find", "lookup"}),
        frozenset({"document", "file", "record"}),
        frozenset(),
    ),
    "document_read": (
        frozenset({"read", "open", "review"}),
        frozenset({"document", "file", "record"}),
        frozenset(),
    ),
    "wiki_search": (
        frozenset({"search", "find", "lookup"}),
        frozenset({"wiki", "knowledge"}),
        frozenset(),
    ),
    "ticket_read": (
        frozenset({"read", "open", "review"}),
        frozenset({"ticket"}),
        frozenset(),
    ),
    "ticket_update": (
        frozenset({"update", "close", "resolve"}),
        frozenset({"ticket"}),
        frozenset(),
    ),
    "customer_lookup": (
        frozenset({"lookup", "find", "search"}),
        frozenset({"customer", "client"}),
        frozenset(),
    ),
    "account_summary": (
        frozenset({"summarize", "review", "show"}),
        frozenset({"account", "balance"}),
        frozenset(),
    ),
    "case_document_read": (
        frozenset({"read", "open", "review"}),
        frozenset({"case", "document", "file"}),
        frozenset(),
    ),
    "case_note_create": (
        frozenset({"create", "add", "write"}),
        frozenset({"case", "note"}),
        frozenset(),
    ),
    "policy_search": (
        frozenset({"search", "find", "lookup"}),
        frozenset({"policy"}),
        frozenset(),
    ),
    "payment_prepare": (
        frozenset({"prepare", "initiate", "create"}),
        frozenset({"payment", "transfer"}),
        frozenset(),
    ),
    "payment_confirm": (
        frozenset({"confirm", "approve"}),
        frozenset({"payment", "transfer"}),
        frozenset(),
    ),
    "payment_execute": (
        frozenset({"execute", "pay", "transfer"}),
        frozenset({"payment", "transfer", "funds"}),
        frozenset({"pay", "transfer"}),
    ),
    "alert_search": (
        frozenset({"search", "find", "lookup"}),
        frozenset({"alert"}),
        frozenset(),
    ),
    "alert_read": (
        frozenset({"read", "open", "review"}),
        frozenset({"alert"}),
        frozenset(),
    ),
    "asset_lookup": (
        frozenset({"lookup", "look", "find", "search"}),
        frozenset({"asset", "host", "device"}),
        frozenset(),
    ),
    "intel_search": (
        frozenset({"search", "find", "lookup"}),
        frozenset({"intel", "intelligence", "threat", "indicator"}),
        frozenset(),
    ),
    "incident_create": (
        frozenset({"create", "open"}),
        frozenset({"incident"}),
        frozenset(),
    ),
    "incident_update": (
        frozenset({"update", "close", "resolve"}),
        frozenset({"incident"}),
        frozenset(),
    ),
    "remediation_prepare": (
        frozenset({"prepare", "plan", "create"}),
        frozenset({"remediation", "plan", "isolation", "host", "asset"}),
        frozenset(),
    ),
    "remediation_execute": (
        frozenset({"execute", "remediate", "isolate", "block"}),
        frozenset({"remediation", "isolation", "host", "asset"}),
        frozenset({"remediate", "isolate", "block"}),
    ),
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


class ClauseDisposition(IntEnum):
    """Security meaning of bounded natural-language text, before action coupling."""

    NEUTRAL = 0
    NEGATED = 1
    ACTIVE = 2


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

    if action.type is ActionKind.MEMORY_WRITE and _memory_write_is_directive(action):
        return _block("MEMORY_POISONING", 0.96, adapted)

    if action.type is ActionKind.TOOL_CALL and _coupled_instruction(action, adapted):
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
    if action.type is ActionKind.MEMORY_WRITE and _has_untrusted_evidence(adapted):
        return _decision(
            Verdict.ALLOW,
            0.32,
            "UNTRUSTED_MEMORY_INHERITED",
            adapted,
            "Factual memory is retained with the source's low-trust security label.",
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


def _memory_write_is_directive(action: CandidateAction) -> bool:
    content = action.content or ""
    return _classify_instruction_text(content) is ClauseDisposition.ACTIVE


def _coupled_instruction(action: CandidateAction, adapted: AdaptedRequest) -> bool:
    observations = adapted.request.observations
    index = 0
    while index < len(observations):
        observation = observations[index]
        if not _is_untrusted(observation.trust_level):
            index += 1
            continue

        content = _normalize_clause_text(observation.content)
        consumed_until = _completed_fragment_group(observations, index, action, content)
        if consumed_until == -1:
            return True
        if consumed_until is not None:
            index = consumed_until + 1
            continue
        if _observation_couples(
            action,
            content,
            semantic_coupling=_is_externally_untrusted(observation.trust_level),
        ):
            return True
        index += 1
    return False


def _completed_fragment_group(
    observations: tuple[Observation, ...],
    start: int,
    action: CandidateAction,
    initial: str,
) -> int | None:
    """Evaluate at most three adjacent untrusted fragments from an incomplete prefix.

    ``-1`` signals an active instruction coupled to the candidate action. A
    non-negative index signals a completed negated instruction whose fragments
    must not be reinterpreted independently. ``None`` means no complete bounded
    group was found, so normal per-observation evaluation should continue.
    """

    if not _is_incomplete_subject_fragment(initial):
        return None

    combined = initial
    semantic_coupling = _is_externally_untrusted(observations[start].trust_level)
    upper_bound = min(
        len(observations), start + _MAX_ADJACENT_COMPOSITION_OBSERVATIONS
    )
    for end in range(start + 1, upper_bound):
        candidate = observations[end]
        if not _is_untrusted(candidate.trust_level):
            break
        semantic_coupling = semantic_coupling or _is_externally_untrusted(
            candidate.trust_level
        )
        combined = f"{combined} {_normalize_clause_text(candidate.content)}"
        if len(combined) > _MAX_ADJACENT_COMPOSITION_CHARS:
            break

        disposition = _classify_instruction_text(combined)
        if disposition is ClauseDisposition.ACTIVE:
            return (
                -1
                if _observation_couples(
                    action, combined, semantic_coupling=semantic_coupling
                )
                else None
            )
        if disposition is ClauseDisposition.NEGATED:
            return end
        if not _is_incomplete_subject_fragment(combined):
            break
    return None


def _is_incomplete_subject_fragment(content: str) -> bool:
    normalized = _DISCOURSE_PREFIX.sub("", _normalize_clause_text(content))
    return _INCOMPLETE_SUBJECT_FRAGMENT.fullmatch(normalized) is not None


def _observation_couples(
    action: CandidateAction, content: str, *, semantic_coupling: bool
) -> bool:
    if not content or _classify_instruction_text(content) is not ClauseDisposition.ACTIVE:
        return False
    lowered = content.lower()
    if action.tool is not None:
        tool_tokens = {action.tool.lower(), action.tool.lower().replace("_", " ")}
        if any(token in lowered for token in tool_tokens):
            return True
    argument_values = (
        value.strip().lower()
        for value in action.arguments.values()
        if isinstance(value, str) and len(value.strip()) >= 4
    )
    if any(value in lowered for value in argument_values):
        return True
    if action.tool is None or not semantic_coupling:
        return False
    semantics = _TOOL_SEMANTICS.get(action.tool)
    if semantics is None:
        return False
    operations, objects, standalone_operations = semantics
    tokens = frozenset(re.findall(r"[a-z0-9]+", lowered))
    return bool(
        standalone_operations.intersection(tokens)
        or (operations.intersection(tokens) and objects.intersection(tokens))
    )


def _classify_instruction_text(content: str) -> ClauseDisposition:
    """Classify clauses with negation precedence and explicit quote semantics.

    Labels such as ``training`` or ``example`` have no authority. An imperative
    inside quotes remains active unless the surrounding text explicitly says not
    to follow, execute, or obey it. Remaining clauses are normalized and checked
    independently so a negated clause cannot hide a later active one.
    """

    normalized = _normalize_clause_text(content, preserve_newlines=True)
    quoted_spans = list(_QUOTED_SPAN.finditer(normalized))
    saw_negation = False
    previous_end = 0
    for index, quoted in enumerate(quoted_spans):
        quote_content = quoted.group()[1:-1]
        if _classify_unquoted_text(quote_content) is ClauseDisposition.ACTIVE:
            next_start = (
                quoted_spans[index + 1].start()
                if index + 1 < len(quoted_spans)
                else len(normalized)
            )
            before = normalized[previous_end : quoted.start()]
            after = normalized[quoted.end() : next_start]
            forward_negation = _QUOTE_FORWARD_NEGATION.search(before) is not None
            # A forward negation at the end of the inter-quote text belongs to
            # the next quote, not to the quote that precedes it.
            backward_context = _QUOTE_FORWARD_NEGATION.sub("", after)
            backward_negation = (
                _QUOTE_BACKWARD_NEGATION.search(backward_context) is not None
            )
            if not (forward_negation or backward_negation):
                return ClauseDisposition.ACTIVE
            saw_negation = True
        previous_end = quoted.end()

    without_quotes = _QUOTED_SPAN.sub(" ", normalized)
    remainder = _classify_unquoted_text(without_quotes)
    if remainder is ClauseDisposition.ACTIVE:
        return ClauseDisposition.ACTIVE
    if remainder is ClauseDisposition.NEGATED or saw_negation:
        return ClauseDisposition.NEGATED
    return ClauseDisposition.NEUTRAL


def _classify_unquoted_text(content: str) -> ClauseDisposition:
    saw_negation = False
    for clause in _CLAUSE_SPLIT.split(content):
        cleaned = _normalize_clause_text(clause).strip("\"'")
        if not cleaned:
            continue
        for part in _CONTRAST_SPLIT.split(cleaned):
            disposition = _classify_atomic_clause(part)
            if disposition is ClauseDisposition.ACTIVE:
                return ClauseDisposition.ACTIVE
            if disposition is ClauseDisposition.NEGATED:
                saw_negation = True
    return ClauseDisposition.NEGATED if saw_negation else ClauseDisposition.NEUTRAL


def _classify_atomic_clause(clause: str) -> ClauseDisposition:
    normalized = _normalize_clause_text(clause).strip("\"'")
    if not normalized:
        return ClauseDisposition.NEUTRAL
    normalized = _DISCOURSE_PREFIX.sub("", normalized)

    subject_modal = _SUBJECT_MODAL.search(normalized)
    if subject_modal is not None:
        return (
            ClauseDisposition.NEGATED
            if subject_modal.group("negation") is not None
            else ClauseDisposition.ACTIVE
        )
    if (
        _NEGATED_IMPERATIVE.search(normalized) is not None
        or _BARE_MODAL_NEGATION.search(normalized) is not None
        or _IGNORE_META_INSTRUCTION.search(normalized) is not None
    ):
        return ClauseDisposition.NEGATED
    if (
        _IMPERATIVE.search(normalized) is not None
        or _OVERRIDE_DIRECTIVE.search(normalized) is not None
    ):
        return ClauseDisposition.ACTIVE
    return ClauseDisposition.NEUTRAL


def _normalize_clause_text(content: str, *, preserve_newlines: bool = False) -> str:
    if preserve_newlines:
        lines = (" ".join(line.split()) for line in content.splitlines())
        return "\n".join(line for line in lines if line).strip()
    return " ".join(content.split()).strip()


def _is_untrusted(trust_level: TrustLevel) -> bool:
    return list(TrustLevel).index(trust_level) >= list(TrustLevel).index(_UNTRUSTED_THRESHOLD)


def _is_externally_untrusted(trust_level: TrustLevel) -> bool:
    return list(TrustLevel).index(trust_level) >= list(TrustLevel).index(
        TrustLevel.UNTRUSTED_EXTERNAL
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
    metadata = {
        "least_trust": adapted.least_trust.value,
        "max_sensitivity": adapted.max_sensitivity.value,
    }
    if adapted.request.candidate_action.type is ActionKind.MEMORY_WRITE:
        metadata["memory_trust"] = adapted.least_trust.value
    return GuardDecision(
        verdict=verdict,
        risk_score=risk,
        confidence=0.99,
        reason_codes=(code,),
        explanation=explanation,
        metadata=metadata,
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
