"""Defensive parsing of policy facts supplied by the benchmark."""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from aegisgraph.contracts import CandidateAction

_TOOL_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_EMAIL_PATTERN = re.compile(r"^[^\s@,;<>]+@[^\s@,;<>]+$")
STATIC_CONSEQUENTIAL_TOOLS = frozenset(
    {"email_send", "payment_confirm", "payment_execute", "remediation_execute"}
)


@dataclass(frozen=True)
class PolicyFacts:
    allowed_tools: frozenset[str]
    confirmation_required_tools: frozenset[str]
    consequential_tools: frozenset[str]
    internal_email_domains: frozenset[str]
    valid: bool
    errors: tuple[str, ...]


def parse_policy_facts(context: object) -> PolicyFacts:
    """Extract only declarative allow/confirmation/domain facts from policy JSON."""

    if not isinstance(context, Mapping):
        return _invalid("policy_context must be a mapping")

    errors: list[str] = []
    allowed = _string_set(context, "allowed_tools", required=True, errors=errors)
    confirmation = _string_set(
        context, "confirmation_required_tools", required=False, errors=errors
    )
    consequential = _string_set(context, "consequential_tools", required=False, errors=errors)
    domains = _domain_set(context, errors)
    return PolicyFacts(
        allowed_tools=allowed,
        confirmation_required_tools=confirmation,
        consequential_tools=consequential,
        internal_email_domains=domains,
        valid=not errors,
        errors=tuple(errors),
    )


def is_consequential(action: CandidateAction, facts: PolicyFacts) -> bool:
    tool = action.tool
    if tool is None:
        return False
    if tool in STATIC_CONSEQUENTIAL_TOOLS or tool in facts.consequential_tools:
        return True
    status = action.arguments.get("status")
    normalized_status = status.strip().lower() if isinstance(status, str) else None
    return (tool == "ticket_update" and normalized_status in {"closed", "resolved"}) or (
        tool == "incident_update" and normalized_status == "closed"
    )


def requires_confirmation(action: CandidateAction, facts: PolicyFacts) -> bool:
    return action.tool in facts.confirmation_required_tools or is_consequential(action, facts)


def recipient_is_external(action: CandidateAction, facts: PolicyFacts) -> bool:
    """Treat external, missing, or ambiguous outbound email destinations as unsafe."""

    destinations: list[str] = []
    destination_field_seen = False
    for key, value in action.arguments.items():
        if key.lower() not in {
            "to",
            "recipient",
            "recipients",
            "email",
            "destination",
            "cc",
            "bcc",
        }:
            continue
        destination_field_seen = True
        if not isinstance(value, str):
            return True
        destinations.extend(part.strip() for part in re.split(r"[,;]", value) if part.strip())

    if action.tool == "email_send" and (not destination_field_seen or not destinations):
        return True
    if any(_EMAIL_PATTERN.fullmatch(item) is None for item in destinations):
        return True
    email_domains = [item.rsplit("@", 1)[1].lower() for item in destinations]
    if not email_domains:
        return False
    return any(
        not any(
            domain == internal or domain.endswith(f".{internal}")
            for internal in facts.internal_email_domains
        )
        for domain in email_domains
    )


def _string_set(
    context: Mapping[object, object],
    key: str,
    *,
    required: bool,
    errors: list[str],
) -> frozenset[str]:
    value = context.get(key)
    if value is None:
        if required:
            errors.append(f"{key} is required")
        return frozenset()
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        errors.append(f"{key} must be a list")
        return frozenset()
    result: set[str] = set()
    for item in value:
        if not isinstance(item, str) or _TOOL_PATTERN.fullmatch(item) is None:
            errors.append(f"{key} contains an invalid tool")
            continue
        result.add(item)
    return frozenset(result)


def _domain_set(context: Mapping[object, object], errors: list[str]) -> frozenset[str]:
    value = context.get("internal_email_domains")
    if value is None:
        return frozenset()
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        errors.append("internal_email_domains must be a list")
        return frozenset()
    result: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            errors.append("internal_email_domains contains a non-string")
            continue
        normalized = item.strip().lower().lstrip(".")
        if _DOMAIN_PATTERN.fullmatch(normalized) is None:
            errors.append("internal_email_domains contains an invalid domain")
            continue
        result.add(normalized)
    return frozenset(result)


def _invalid(error: str) -> PolicyFacts:
    return PolicyFacts(
        allowed_tools=frozenset(),
        confirmation_required_tools=frozenset(),
        consequential_tools=frozenset(),
        internal_email_domains=frozenset(),
        valid=False,
        errors=(error,),
    )
