"""Caller-side enforcement boundary for a decision receipt.

A decision only has meaning if the caller binds it to the exact action it was
taken for. This module is dependency-free, deterministic and has no side effects:
:func:`enforce` decides whether a receipt authorizes a candidate action, and
:func:`execute_guarded` calls a caller-supplied executor only when it does.

Receipts are the ``aegisgraph/v1`` decision responses as plain mappings, so the
same object a service returned over the wire can be passed through unchanged.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from aegisgraph.contracts import CandidateAction, PolicyIdentity

_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{24}$")


class RefusalReason(StrEnum):
    """Why an enforcement boundary refused to execute a candidate action."""

    MISSING_RECEIPT = "missing_receipt"
    MALFORMED_RECEIPT = "malformed_receipt"
    EXPIRED_RECEIPT = "expired_receipt"
    DIGEST_MISMATCH = "digest_mismatch"
    POLICY_MISMATCH = "policy_mismatch"
    VERDICT_BLOCKED = "verdict_blocked"
    UNRESOLVED_ESCALATION = "unresolved_escalation"
    REWRITE_NOT_REVALIDATED = "rewrite_not_revalidated"


@dataclass(frozen=True)
class EnforcementOutcome:
    """The enforcement decision for one receipt/action pair."""

    allowed: bool
    reason: RefusalReason | None
    detail: str


@dataclass(frozen=True)
class ToolResult:
    """What a caller-supplied executor reported for an authorized action."""

    tool: str
    status: str
    detail: str


@dataclass(frozen=True)
class GuardedExecution:
    """The enforcement outcome together with what the executor actually did."""

    outcome: EnforcementOutcome
    executed: bool
    result: ToolResult | None = None


def enforce(
    receipt: Mapping[str, Any],
    action: CandidateAction,
    *,
    expected_policy: PolicyIdentity,
    now: datetime | None = None,
) -> EnforcementOutcome:
    """Return whether ``receipt`` authorizes exactly ``action``.

    The checks run in a fixed order so every refusal class is reachable and each
    refusal names the first invariant that failed:

    1. the receipt exists and carries a decision identity,
    2. the recorded verdict is ``allow`` (block/escalate/rewrite are refused),
    3. the policy identity matches the caller's expected policy,
    4. the receipt has not expired,
    5. both digests match the candidate action exactly.
    """

    if not isinstance(receipt, Mapping) or not receipt:
        return _refuse(RefusalReason.MISSING_RECEIPT, "no decision receipt was supplied")
    receipt_id = receipt.get("receipt_id")
    if not isinstance(receipt_id, str) or not receipt_id:
        return _refuse(
            RefusalReason.MISSING_RECEIPT, "the receipt carries no decision identity"
        )

    verdict = receipt.get("decision")
    if not isinstance(verdict, str):
        return _refuse(RefusalReason.MALFORMED_RECEIPT, "the receipt carries no verdict")
    if verdict != "allow":
        known = {
            "block": (
                RefusalReason.VERDICT_BLOCKED,
                "the decision blocked the candidate action",
            ),
            "escalate": (
                RefusalReason.UNRESOLVED_ESCALATION,
                "the decision escalated and no reviewer resolution is recorded",
            ),
            "rewrite": (
                RefusalReason.REWRITE_NOT_REVALIDATED,
                "the decision replaced the action and the replacement was not revalidated",
            ),
        }
        reason, detail = known.get(verdict, (RefusalReason.MALFORMED_RECEIPT, "unknown verdict"))
        return _refuse(reason, detail)

    policy_set = receipt.get("policy_set")
    if not isinstance(policy_set, Mapping):
        return _refuse(RefusalReason.MALFORMED_RECEIPT, "the receipt carries no policy identity")
    if (
        policy_set.get("id") != expected_policy.id
        or policy_set.get("version") != expected_policy.version
    ):
        return _refuse(
            RefusalReason.POLICY_MISMATCH,
            "the receipt was issued under a different policy set",
        )

    action_digest_value = receipt.get("action_digest")
    execution_digest_value = receipt.get("execution_digest")
    if not _is_digest(action_digest_value) or not _is_digest(execution_digest_value):
        return _refuse(
            RefusalReason.MALFORMED_RECEIPT, "the receipt carries no usable action identity"
        )

    valid_until = _parse_timestamp(receipt.get("valid_until"))
    if valid_until is None:
        return _refuse(RefusalReason.MALFORMED_RECEIPT, "the receipt carries no validity window")
    if valid_until <= (now or datetime.now(UTC)):
        return _refuse(RefusalReason.EXPIRED_RECEIPT, "the receipt is no longer valid")

    if (
        action.digest() != action_digest_value
        or action.execution_digest() != execution_digest_value
    ):
        return _refuse(
            RefusalReason.DIGEST_MISMATCH,
            "the candidate action is not the action the receipt was issued for",
        )
    return EnforcementOutcome(allowed=True, reason=None, detail="receipt authorizes this action")


def execute_guarded(
    executor: Callable[[CandidateAction], ToolResult],
    receipt: Mapping[str, Any],
    action: CandidateAction,
    **kwargs: Any,
) -> GuardedExecution:
    """Run ``executor`` only when enforcement allows the exact action.

    ``kwargs`` are forwarded to :func:`enforce` (``expected_policy``, ``now``). On
    any refusal the executor is never called, so a refused action cannot produce a
    side effect.
    """

    outcome = enforce(receipt, action, **kwargs)
    if not outcome.allowed:
        return GuardedExecution(outcome=outcome, executed=False)
    return GuardedExecution(outcome=outcome, executed=True, result=executor(action))


def _refuse(reason: RefusalReason, detail: str) -> EnforcementOutcome:
    return EnforcementOutcome(allowed=False, reason=reason, detail=detail)


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST_PATTERN.fullmatch(value) is not None


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


__all__ = [
    "EnforcementOutcome",
    "GuardedExecution",
    "RefusalReason",
    "ToolResult",
    "enforce",
    "execute_guarded",
]
