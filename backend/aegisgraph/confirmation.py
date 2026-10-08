"""The real confirmation channel (finding F2, decision D4).

A confirmation grant is a *record*, not a string the caller can mint. The caller
presents ``run_id:step_id:execution_digest:expiry`` in ``confirmations_granted``;
:func:`authorize_confirmations` keeps only the grants that were issued through
``POST /api/v1/confirmations``, are still unexpired and are bound to this run and
step. A syntactically perfect grant that was never issued is dropped, so the
action escalates instead of being allowed — which is what closes F2 rather than
merely reformatting it.

Dropping is fail-closed by construction: the engine treats a missing grant as "not
granted". Every drop is counted in an audit event that carries no request content.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from aegisgraph.contracts import parse_confirmation_grant
from aegisgraph.sentinel import SentinelRequest
from aegisgraph.store import (
    EVENT_CONFIRMATION_REFUSED,
    AuditRecord,
    ReceiptStore,
)

REFUSAL_MALFORMED = "malformed"
REFUSAL_NOT_ISSUED = "not_issued"
REFUSAL_EXPIRED = "expired"

@dataclass(frozen=True)
class ConfirmationAuthorization[RequestT: SentinelRequest]:
    """The bounded result of authorizing the grants a request presents."""

    request: RequestT
    accepted: tuple[str, ...]
    refused: tuple[str, ...]
    refusal_reasons: tuple[str, ...]


def authorize_confirmations[RequestT: SentinelRequest](
    request: RequestT,
    *,
    tenant_id: str,
    store: ReceiptStore,
    now: datetime,
) -> ConfirmationAuthorization[RequestT]:
    """Return the request carrying only grants that exist in the store (D4)."""

    presented = request.history_digest.confirmations_granted
    if not presented:
        return ConfirmationAuthorization[RequestT](
            request=request, accepted=(), refused=(), refusal_reasons=()
        )

    moment = now.astimezone(UTC)
    accepted: list[str] = []
    refused: list[str] = []
    reasons: list[str] = []
    for value in presented:
        reason = _refusal_reason(value, tenant_id=tenant_id, store=store, now=moment)
        if reason is None:
            accepted.append(value)
        else:
            refused.append(value)
            reasons.append(reason)

    if not refused:
        return ConfirmationAuthorization[RequestT](
            request=request, accepted=tuple(accepted), refused=(), refusal_reasons=()
        )
    return ConfirmationAuthorization[RequestT](
        request=_with_grants(request, accepted),
        accepted=tuple(accepted),
        refused=tuple(refused),
        refusal_reasons=tuple(dict.fromkeys(reasons)),
    )


def record_refusal[RequestT: SentinelRequest](
    authorization: ConfirmationAuthorization[RequestT],
    *,
    tenant_id: str,
    principal_id: str,
    store: ReceiptStore,
    now: datetime,
    request_id: str,
) -> None:
    """Write one content-free audit event for the grants that were dropped."""

    if not authorization.refused:
        return
    store.record_audit_event(
        AuditRecord(
            tenant_id=tenant_id,
            event_type=EVENT_CONFIRMATION_REFUSED,
            actor_id=principal_id,
            subject=request_id,
            details={
                "presented": len(authorization.accepted) + len(authorization.refused),
                "accepted": len(authorization.accepted),
                "refused": len(authorization.refused),
                "reasons": list(authorization.refusal_reasons),
            },
            created_at=now,
        )
    )


def _refusal_reason(
    value: str, *, tenant_id: str, store: ReceiptStore, now: datetime
) -> str | None:
    grant = parse_confirmation_grant(value)
    if grant is None:
        return REFUSAL_MALFORMED
    if grant.expires_at <= int(now.timestamp()):
        return REFUSAL_EXPIRED
    if not store.grant_exists(
        tenant_id,
        run_id=grant.run_id,
        step_id=grant.step_id,
        execution_digest=grant.execution_digest,
        now=now,
    ):
        return REFUSAL_NOT_ISSUED
    return None


def _with_grants[RequestT: SentinelRequest](request: RequestT, grants: list[str]) -> RequestT:
    payload = request.model_dump(mode="json")
    history = dict(payload["history_digest"])
    history["confirmations_granted"] = list(grants)
    payload["history_digest"] = history
    return type(request).model_validate(payload)


__all__ = [
    "REFUSAL_EXPIRED",
    "REFUSAL_MALFORMED",
    "REFUSAL_NOT_ISSUED",
    "ConfirmationAuthorization",
    "authorize_confirmations",
    "record_refusal",
]
