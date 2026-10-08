"""Authenticated, tenant-scoped administration surfaces (D1, D3, D4, D6).

* ``POST /api/v1/confirmations`` — the only way a confirmation grant comes into
  existence (D4). Scope ``confirmation:grant``.
* ``GET /api/v1/receipts`` — bounded, cursor-paged, tenant-scoped read of the
  durable decision trail. Scope ``receipt:read``.
* ``GET``/``POST /api/v1/policies`` and the activation endpoint — versioned policy
  administration with immutable versions and one audit event per change. Scopes
  ``policy:read`` and ``policy:write``.
* ``GET /api/v1/audit-events`` — the append-only audit trail. Scope ``receipt:read``
  or ``policy:read``, so a policy administrator can verify its own change was recorded.

Every response is tenant-scoped: a caller can only ever observe its own tenant's
rows, and a missing row is reported as ``404`` rather than ``403`` so the endpoint
does not become a cross-tenant existence oracle.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field

from aegisgraph.access import ProblemError, StoreDep, require_any_scope, require_scopes
from aegisgraph.auth import (
    SCOPE_CONFIRMATION_GRANT,
    SCOPE_POLICY_READ,
    SCOPE_POLICY_WRITE,
    SCOPE_RECEIPT_READ,
    Principal,
)
from aegisgraph.contracts import PolicyIdentity
from aegisgraph.models import MAX_POLICY_DOCUMENT_BYTES
from aegisgraph.policy import parse_policy_facts
from aegisgraph.store import (
    AUDIT_PAGE_LIMIT_MAX,
    DEFAULT_RECEIPT_PAGE_LIMIT,
    EVENT_CONFIRMATION_ISSUED,
    EVENT_POLICY_ACTIVATED,
    EVENT_POLICY_CREATED,
    POLICY_PAGE_LIMIT_MAX,
    RECEIPT_PAGE_LIMIT_MAX,
    AuditRecord,
    GrantRecord,
    PolicyRecord,
    ReceiptRecord,
    ReceiptStore,
    UnknownPolicySetError,
    canonical_json,
    digest_of,
)

POLICY_SET_IMMUTABLE = "POLICY_SET_IMMUTABLE"
POLICY_DOCUMENT_INVALID = "POLICY_DOCUMENT_INVALID"
POLICY_DOCUMENT_TOO_LARGE = "POLICY_DOCUMENT_TOO_LARGE"
RECEIPT_NOT_FOUND = "RECEIPT_NOT_FOUND"

router = APIRouter()

ConfirmationPrincipal = Annotated[Principal, Depends(require_scopes(SCOPE_CONFIRMATION_GRANT))]
ReceiptReader = Annotated[Principal, Depends(require_scopes(SCOPE_RECEIPT_READ))]
TrailReader = Annotated[
    Principal, Depends(require_any_scope(SCOPE_RECEIPT_READ, SCOPE_POLICY_READ))
]
PolicyReader = Annotated[Principal, Depends(require_scopes(SCOPE_POLICY_READ))]
PolicyWriter = Annotated[Principal, Depends(require_scopes(SCOPE_POLICY_WRITE))]


class ConfirmationRequest(BaseModel):
    """A request to issue one confirmation grant for one exact action (D4)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str = Field(min_length=1, max_length=256)
    step_id: int = Field(ge=0)
    execution_digest: str = Field(pattern=r"^[0-9a-f]{24}$")
    ttl_seconds: int = Field(default=300, ge=1, le=86_400)


class ConfirmationResponse(BaseModel):
    """The issued grant and its binding; the grant value is what a caller presents."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    grant: str
    run_id: str
    step_id: int
    execution_digest: str
    issued_by: str
    issued_at: datetime
    expires_at: datetime


class ReceiptView(BaseModel):
    """One durable receipt as an auditor reads it: digests, verdict, identity only."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    receipt_id: str
    request_id: str
    surface: str
    policy_set: PolicyIdentity
    verdict: str
    risk_score: float
    confidence: float
    reason_codes: tuple[str, ...]
    action_digest: str
    execution_digest: str
    payload_digest: str
    principal_id: str
    run_id: str | None
    step_id: int | None
    decided_at: datetime
    valid_until: datetime
    metadata_redacted_at: datetime | None


class ReceiptPage(BaseModel):
    """One bounded page of receipts plus the cursor for the next page."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    items: tuple[ReceiptView, ...]
    next_cursor: str | None


class PolicyView(BaseModel):
    """One immutable policy version and its activation state."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    version: str
    checksum: str
    active: bool
    created_by: str
    created_at: datetime
    activated_at: datetime | None
    document: Mapping[str, Any]


class PolicyPage(BaseModel):
    """The tenant's policy versions, oldest first."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    items: tuple[PolicyView, ...]


class PolicyCreateRequest(BaseModel):
    """Register one immutable policy version, optionally activating it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    version: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    document: Mapping[str, Any]
    activate: bool = False


class PolicyActivateRequest(BaseModel):
    """Activate an already stored policy version."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class AuditEventView(BaseModel):
    """One append-only audit event."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: int | None
    event_type: str
    actor_id: str
    subject: str | None
    details: Mapping[str, Any]
    created_at: datetime


class AuditEventPage(BaseModel):
    """The tenant's most recent audit events, newest first."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    items: tuple[AuditEventView, ...]


@router.post("/api/v1/confirmations", response_model=ConfirmationResponse, status_code=201)
async def issue_confirmation(
    body: ConfirmationRequest,
    principal: ConfirmationPrincipal,
    store: StoreDep,
) -> ConfirmationResponse:
    """Issue a confirmation grant bound to one run, step and exact action (D4)."""

    now = datetime.now(UTC)
    record = GrantRecord(
        tenant_id=principal.tenant_id,
        run_id=body.run_id,
        step_id=body.step_id,
        execution_digest=body.execution_digest,
        issued_by=principal.principal_id,
        issued_at=now,
        expires_at=now + timedelta(seconds=body.ttl_seconds),
    )
    stored = store.issue_grant(record)
    store.record_audit_event(
        AuditRecord(
            tenant_id=principal.tenant_id,
            event_type=EVENT_CONFIRMATION_ISSUED,
            actor_id=principal.principal_id,
            subject=f"{body.run_id}:{body.step_id}",
            details={
                "execution_digest": body.execution_digest,
                "expires_at": stored.expires_at.isoformat(),
            },
            created_at=now,
        )
    )
    return ConfirmationResponse(
        grant=stored.as_wire_value(),
        run_id=stored.run_id,
        step_id=stored.step_id,
        execution_digest=stored.execution_digest,
        issued_by=stored.issued_by,
        issued_at=stored.issued_at,
        expires_at=stored.expires_at,
    )


@router.get("/api/v1/receipts", response_model=ReceiptPage)
async def list_receipts(
    principal: ReceiptReader,
    store: StoreDep,
    limit: Annotated[int, Query(ge=1, le=RECEIPT_PAGE_LIMIT_MAX)] = DEFAULT_RECEIPT_PAGE_LIMIT,
    cursor: Annotated[str | None, Query(max_length=256)] = None,
) -> ReceiptPage:
    """Return one bounded page of this tenant's receipts, newest first (D1)."""

    records, next_cursor = store.list_receipts(
        principal.tenant_id, limit=limit, cursor=cursor
    )
    return ReceiptPage(
        items=tuple(_receipt_view(record) for record in records), next_cursor=next_cursor
    )


@router.get("/api/v1/receipts/{receipt_id}", response_model=ReceiptView)
async def get_receipt(
    receipt_id: str,
    principal: ReceiptReader,
    store: StoreDep,
) -> ReceiptView:
    """Return one receipt of this tenant; another tenant's receipt is a 404 (D1)."""

    record = store.get_receipt(principal.tenant_id, receipt_id)
    if record is None:
        raise ProblemError(RECEIPT_NOT_FOUND, "no such receipt for this tenant", status_code=404)
    return _receipt_view(record)


@router.get("/api/v1/policies", response_model=PolicyPage)
async def list_policies(
    principal: PolicyReader,
    store: StoreDep,
    limit: Annotated[int, Query(ge=1, le=POLICY_PAGE_LIMIT_MAX)] = POLICY_PAGE_LIMIT_MAX,
) -> PolicyPage:
    """Return this tenant's policy versions and their activation state (D3)."""

    records = store.list_policy_sets(principal.tenant_id, limit=limit)
    return PolicyPage(items=tuple(_policy_view(record) for record in records))


@router.post("/api/v1/policies", response_model=PolicyView, status_code=201)
async def create_policy(
    body: PolicyCreateRequest,
    principal: PolicyWriter,
    store: StoreDep,
) -> PolicyView:
    """Store one immutable policy version and audit the change (D3, D6)."""

    document = dict(body.document)
    encoded = canonical_json(document)
    if len(encoded.encode("utf-8")) > MAX_POLICY_DOCUMENT_BYTES:
        raise ProblemError(
            POLICY_DOCUMENT_TOO_LARGE,
            f"the policy document exceeds {MAX_POLICY_DOCUMENT_BYTES} bytes",
            status_code=413,
        )
    facts = parse_policy_facts(document)
    if not facts.valid:
        raise ProblemError(
            POLICY_DOCUMENT_INVALID,
            "the policy document is not a usable policy set: " + "; ".join(facts.errors[:4]),
            status_code=422,
        )

    now = datetime.now(UTC)
    checksum = digest_of(document)
    existing = store.get_policy_set(principal.tenant_id, body.id, body.version)
    if existing is not None and existing.checksum != checksum:
        raise ProblemError(
            POLICY_SET_IMMUTABLE,
            f"policy set {body.id!r} version {body.version!r} already exists with a different "
            "document; publish a new version instead",
            status_code=409,
        )
    record = existing or store.create_policy_set(
        PolicyRecord(
            tenant_id=principal.tenant_id,
            id=body.id,
            version=body.version,
            document=document,
            checksum=checksum,
            active=False,
            created_by=principal.principal_id,
            created_at=now,
        )
    )
    if existing is None:
        store.record_audit_event(
            AuditRecord(
                tenant_id=principal.tenant_id,
                event_type=EVENT_POLICY_CREATED,
                actor_id=principal.principal_id,
                subject=f"{body.id}:{body.version}",
                details={"checksum": checksum},
                created_at=now,
            )
        )
    if body.activate:
        record = _activate(
            store, principal.tenant_id, body.id, body.version, principal.principal_id, now
        )
    return _policy_view(record)


@router.post("/api/v1/policies/{policy_id}/activate", response_model=PolicyView)
async def activate_policy(
    policy_id: str,
    body: PolicyActivateRequest,
    principal: PolicyWriter,
    store: StoreDep,
) -> PolicyView:
    """Activate one stored policy version and audit the change (D3, D6)."""

    now = datetime.now(UTC)
    record = _activate(
        store, principal.tenant_id, policy_id, body.version, principal.principal_id, now
    )
    return _policy_view(record)


@router.get("/api/v1/audit-events", response_model=AuditEventPage)
async def list_audit_events(
    principal: TrailReader,
    store: StoreDep,
    limit: Annotated[int, Query(ge=1, le=AUDIT_PAGE_LIMIT_MAX)] = AUDIT_PAGE_LIMIT_MAX,
) -> AuditEventPage:
    """Return this tenant's most recent audit events, newest first (D6)."""

    records = store.list_audit_events(principal.tenant_id, limit=limit)
    return AuditEventPage(
        items=tuple(
            AuditEventView(
                id=record.id,
                event_type=record.event_type,
                actor_id=record.actor_id,
                subject=record.subject,
                details=dict(record.details),
                created_at=record.created_at,
            )
            for record in records
        )
    )


def _activate(
    store: ReceiptStore,
    tenant_id: str,
    policy_id: str,
    version: str,
    actor_id: str,
    now: datetime,
) -> PolicyRecord:
    try:
        record = store.activate_policy_set(tenant_id, policy_id, version, now=now)
    except UnknownPolicySetError as error:
        raise ProblemError(
            "POLICY_SET_UNKNOWN",
            f"policy set {policy_id!r} version {version!r} is not stored for this tenant",
            status_code=404,
        ) from error
    store.record_audit_event(
        AuditRecord(
            tenant_id=tenant_id,
            event_type=EVENT_POLICY_ACTIVATED,
            actor_id=actor_id,
            subject=f"{policy_id}:{version}",
            details={"checksum": record.checksum},
            created_at=now,
        )
    )
    return record


def _receipt_view(record: ReceiptRecord) -> ReceiptView:
    return ReceiptView(
        receipt_id=record.receipt_id,
        request_id=record.request_id,
        surface=record.surface,
        policy_set=PolicyIdentity(id=record.policy_set_id, version=record.policy_set_version),
        verdict=record.verdict,
        risk_score=record.risk_score,
        confidence=record.confidence,
        reason_codes=record.reason_codes,
        action_digest=record.action_digest,
        execution_digest=record.execution_digest,
        payload_digest=record.payload_digest,
        principal_id=record.principal_id,
        run_id=record.run_id,
        step_id=record.step_id,
        decided_at=record.decided_at,
        valid_until=record.valid_until,
        metadata_redacted_at=record.metadata_redacted_at,
    )


def _policy_view(record: PolicyRecord) -> PolicyView:
    return PolicyView(
        id=record.id,
        version=record.version,
        checksum=record.checksum,
        active=record.active,
        created_by=record.created_by,
        created_at=record.created_at,
        activated_at=record.activated_at,
        document=record.document,
    )


__all__ = [
    "AuditEventPage",
    "AuditEventView",
    "ConfirmationRequest",
    "ConfirmationResponse",
    "PolicyActivateRequest",
    "PolicyCreateRequest",
    "PolicyPage",
    "PolicyView",
    "ReceiptPage",
    "ReceiptView",
    "router",
]
