"""Durable, tenant-scoped receipt, grant, policy and audit persistence (F7, D1, D4, D6).

One interface, two implementations:

* :class:`SqlStore` — PostgreSQL through SQLAlchemy 2. It is the production store
  and the only one that survives a restart.
* :class:`MemoryStore` — process-local, used when no ``DATABASE_URL`` is
  configured. It is the labelled development mode and is refused in production
  by :func:`aegisgraph.settings.validate_settings`.

Every query is tenant-scoped (D1): a store method that reads or writes takes the
``tenant_id`` from the resolved principal, never from a request body. Receipt
writes are idempotent on ``(tenant_id, request_id)``; a repeated request returns
the stored receipt, and a repeated ``request_id`` carrying a *different* action is
refused instead of silently reusing the first decision.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, runtime_checkable

from sqlalchemy import and_, func, insert, or_, select, update
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.engine import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from aegisgraph.models import (
    APPEND_ONLY_STATEMENTS,
    AuditEvent,
    Base,
    ConfirmationGrant,
    EvaluationRun,
    PolicySet,
    Receipt,
    ReceiptMetadata,
)
from aegisgraph.settings import Settings

RECEIPT_PAGE_LIMIT_MAX = 100
DEFAULT_RECEIPT_PAGE_LIMIT = 20
POLICY_PAGE_LIMIT_MAX = 100
AUDIT_PAGE_LIMIT_MAX = 200

EVENT_POLICY_CREATED = "policy_set_created"
EVENT_POLICY_ACTIVATED = "policy_set_activated"
EVENT_CONFIRMATION_ISSUED = "confirmation_grant_issued"
EVENT_CONFIRMATION_REFUSED = "confirmation_grant_refused"
EVENT_RETENTION_APPLIED = "retention_applied"
EVENT_RECEIPT_CONFLICT = "receipt_request_conflict"

RETENTION_ACTOR = "retention"


class ReceiptConflictError(RuntimeError):
    """A ``request_id`` was reused for a different candidate action."""

    def __init__(self, tenant_id: str, request_id: str) -> None:
        super().__init__(
            f"request_id {request_id!r} was already used for a different action in tenant "
            f"{tenant_id!r}"
        )
        self.tenant_id = tenant_id
        self.request_id = request_id


class UnknownPolicySetError(RuntimeError):
    """An activation named a policy version that does not exist."""


@dataclass(frozen=True)
class ReceiptRecord:
    """One durable decision record, plus its retention-scoped metadata."""

    tenant_id: str
    request_id: str
    receipt_id: str
    surface: str
    principal_id: str
    auth_method: str
    policy_set_id: str
    policy_set_version: str
    verdict: str
    risk_score: float
    confidence: float
    reason_codes: tuple[str, ...]
    action_digest: str
    execution_digest: str
    payload_digest: str
    decided_at: datetime
    valid_until: datetime
    created_at: datetime
    run_id: str | None = None
    step_id: int | None = None
    metadata: dict[str, Any] | None = None
    metadata_redacted_at: datetime | None = None


@dataclass(frozen=True)
class GrantRecord:
    """An issued confirmation grant, bound to one run, step and exact action (D4)."""

    tenant_id: str
    run_id: str
    step_id: int
    execution_digest: str
    issued_by: str
    issued_at: datetime
    expires_at: datetime

    def as_wire_value(self) -> str:
        """Render the grant value a caller presents in ``confirmations_granted``."""

        return (
            f"{self.run_id}:{self.step_id}:{self.execution_digest}:"
            f"{int(self.expires_at.timestamp())}"
        )


@dataclass(frozen=True)
class PolicyRecord:
    """One immutable policy version and its activation state."""

    tenant_id: str
    id: str
    version: str
    document: dict[str, Any]
    checksum: str
    active: bool
    created_by: str
    created_at: datetime
    activated_at: datetime | None = None


@dataclass(frozen=True)
class AuditRecord:
    """One append-only audit event."""

    tenant_id: str
    event_type: str
    actor_id: str
    details: dict[str, Any]
    created_at: datetime
    subject: str | None = None
    id: int | None = None


@dataclass(frozen=True)
class RetentionReport:
    """What one retention pass redacted (D6)."""

    cutoff: datetime
    payloads_redacted: int
    runs_redacted: int
    tenants: tuple[str, ...] = field(default=())


@runtime_checkable
class ReceiptStore(Protocol):
    """Tenant-scoped persistence used by the decision, admin and audit surfaces."""

    durable: bool

    def store_receipt(self, record: ReceiptRecord) -> ReceiptRecord:
        """Insert once per ``(tenant_id, request_id)`` and return the stored record."""

    def get_receipt(self, tenant_id: str, receipt_id: str) -> ReceiptRecord | None: ...

    def list_receipts(
        self, tenant_id: str, *, limit: int, cursor: str | None = None
    ) -> tuple[list[ReceiptRecord], str | None]:
        """Return one bounded page ordered newest-first, with the next cursor."""

    def issue_grant(self, record: GrantRecord) -> GrantRecord: ...

    def grant_exists(
        self,
        tenant_id: str,
        *,
        run_id: str,
        step_id: int,
        execution_digest: str,
        now: datetime,
    ) -> bool: ...

    def create_policy_set(self, record: PolicyRecord) -> PolicyRecord:
        """Store one immutable policy version; a duplicate returns the stored one."""

    def get_policy_set(
        self, tenant_id: str, policy_id: str, version: str
    ) -> PolicyRecord | None: ...

    def list_policy_sets(
        self, tenant_id: str, *, limit: int = POLICY_PAGE_LIMIT_MAX
    ) -> list[PolicyRecord]: ...

    def activate_policy_set(
        self, tenant_id: str, policy_id: str, version: str, *, now: datetime
    ) -> PolicyRecord: ...

    def active_policy_set(self, tenant_id: str, policy_id: str) -> PolicyRecord | None: ...

    def record_audit_event(self, record: AuditRecord) -> None: ...

    def list_audit_events(
        self, tenant_id: str, *, limit: int = AUDIT_PAGE_LIMIT_MAX
    ) -> list[AuditRecord]: ...

    def apply_retention(self, *, now: datetime, days: int) -> RetentionReport: ...

    def ready(self) -> bool: ...


def canonical_json(value: object) -> str:
    """Return the stable JSON encoding used for digests."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest_of(value: object) -> str:
    """Return the SHA-256 hex digest of a canonical JSON encoding."""

    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def encode_cursor(decided_at: datetime, request_id: str) -> str:
    """Encode the keyset cursor for the receipt page."""

    raw = f"{decided_at.astimezone(UTC).isoformat()}|{request_id}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, str] | None:
    """Decode a cursor, returning ``None`` for anything malformed."""

    padded = cursor + "=" * (-len(cursor) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    timestamp, separator, request_id = raw.partition("|")
    if not separator or not request_id:
        return None
    try:
        decided_at = datetime.fromisoformat(timestamp)
    except ValueError:
        return None
    if decided_at.tzinfo is None:
        return None
    return decided_at, request_id


def _retention_cutoff(now: datetime, days: int) -> datetime:
    return now - timedelta(days=max(days, 0))


class MemoryStore:
    """Process-local store for the labelled development mode.

    It implements the same guarantees as the SQL store — append-only receipts and
    audit events, idempotent receipt writes, tenant scoping and redaction-based
    retention — so behaviour does not silently change with the backend.
    """

    durable = False

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._receipts: dict[tuple[str, str], ReceiptRecord] = {}
        self._grants: dict[tuple[str, str, int, str], GrantRecord] = {}
        self._policies: dict[tuple[str, str, str], PolicyRecord] = {}
        self._audit: list[AuditRecord] = []

    def store_receipt(self, record: ReceiptRecord) -> ReceiptRecord:
        key = (record.tenant_id, record.request_id)
        with self._lock:
            stored = self._receipts.get(key)
            if stored is not None:
                return _existing_or_conflict(stored, record)
            self._receipts[key] = record
            return record


    def get_receipt(self, tenant_id: str, receipt_id: str) -> ReceiptRecord | None:
        with self._lock:
            for record in self._receipts.values():
                if record.tenant_id == tenant_id and record.receipt_id == receipt_id:
                    return record
        return None

    def list_receipts(
        self, tenant_id: str, *, limit: int, cursor: str | None = None
    ) -> tuple[list[ReceiptRecord], str | None]:
        with self._lock:
            records = [item for item in self._receipts.values() if item.tenant_id == tenant_id]
        records.sort(key=lambda item: (item.decided_at, item.request_id), reverse=True)
        page = _keyset_page(records, limit=limit, cursor=cursor)
        return page

    def issue_grant(self, record: GrantRecord) -> GrantRecord:
        key = (
            record.tenant_id,
            record.run_id,
            record.step_id,
            record.execution_digest,
        )
        with self._lock:
            self._grants[key] = record
        return record

    def grant_exists(
        self,
        tenant_id: str,
        *,
        run_id: str,
        step_id: int,
        execution_digest: str,
        now: datetime,
    ) -> bool:
        key = (tenant_id, run_id, step_id, execution_digest)
        with self._lock:
            record = self._grants.get(key)
        return record is not None and record.expires_at > now

    def create_policy_set(self, record: PolicyRecord) -> PolicyRecord:
        key = (record.tenant_id, record.id, record.version)
        with self._lock:
            stored = self._policies.get(key)
            if stored is not None:
                return stored
            self._policies[key] = record
            return record

    def get_policy_set(self, tenant_id: str, policy_id: str, version: str) -> PolicyRecord | None:
        with self._lock:
            return self._policies.get((tenant_id, policy_id, version))

    def list_policy_sets(
        self, tenant_id: str, *, limit: int = POLICY_PAGE_LIMIT_MAX
    ) -> list[PolicyRecord]:
        with self._lock:
            records = [item for item in self._policies.values() if item.tenant_id == tenant_id]
        records.sort(key=lambda item: (item.id, item.created_at, item.version))
        return records[:limit]

    def activate_policy_set(
        self, tenant_id: str, policy_id: str, version: str, *, now: datetime
    ) -> PolicyRecord:
        with self._lock:
            target = self._policies.get((tenant_id, policy_id, version))
            if target is None:
                raise UnknownPolicySetError(
                    f"policy set {policy_id!r} version {version!r} is unknown"
                )
            for key, record in list(self._policies.items()):
                if key[:2] == (tenant_id, policy_id) and record.active:
                    self._policies[key] = replace(record, active=False)
            activated = replace(target, active=True, activated_at=now)
            self._policies[(tenant_id, policy_id, version)] = activated
        return activated

    def active_policy_set(self, tenant_id: str, policy_id: str) -> PolicyRecord | None:
        with self._lock:
            for record in self._policies.values():
                if record.tenant_id == tenant_id and record.id == policy_id and record.active:
                    return record
        return None

    def record_audit_event(self, record: AuditRecord) -> None:
        with self._lock:
            self._audit.append(replace(record, id=len(self._audit) + 1))

    def list_audit_events(
        self, tenant_id: str, *, limit: int = AUDIT_PAGE_LIMIT_MAX
    ) -> list[AuditRecord]:
        with self._lock:
            records = [item for item in self._audit if item.tenant_id == tenant_id]
        records.sort(key=lambda item: item.id or 0, reverse=True)
        return records[:limit]

    def apply_retention(self, *, now: datetime, days: int) -> RetentionReport:
        cutoff = _retention_cutoff(now, days)
        tenants: set[str] = set()
        payloads = 0
        with self._lock:
            for key, record in list(self._receipts.items()):
                if record.metadata is not None and record.created_at < cutoff:
                    self._receipts[key] = replace(
                        record, metadata=None, metadata_redacted_at=now
                    )
                    tenants.add(record.tenant_id)
                    payloads += 1
        return RetentionReport(
            cutoff=cutoff,
            payloads_redacted=payloads,
            runs_redacted=0,
            tenants=tuple(sorted(tenants)),
        )

    def ready(self) -> bool:
        return True


def _existing_or_conflict(stored: ReceiptRecord, candidate: ReceiptRecord) -> ReceiptRecord:
    """Return the stored receipt, or refuse a reused ``request_id`` (F7, D1).

    A repeated ``request_id`` that describes the *same* action is the documented
    idempotent case. A repeated ``request_id`` carrying a different action must
    never silently return the first decision, so it is refused instead.
    """

    if (
        stored.action_digest != candidate.action_digest
        or stored.execution_digest != candidate.execution_digest
    ):
        raise ReceiptConflictError(candidate.tenant_id, candidate.request_id)
    return stored


def _keyset_page(
    records: Sequence[ReceiptRecord], *, limit: int, cursor: str | None
) -> tuple[list[ReceiptRecord], str | None]:
    bounded = max(1, min(limit, RECEIPT_PAGE_LIMIT_MAX))
    if cursor is not None:
        decoded = decode_cursor(cursor)
        if decoded is None:
            return [], None
        decided_at, request_id = decoded
        records = [
            item
            for item in records
            if (item.decided_at, item.request_id) < (decided_at, request_id)
        ]
    page = list(records[:bounded])
    if len(records) <= bounded or not page:
        return page, None
    last = page[-1]
    return page, encode_cursor(last.decided_at, last.request_id)


class SqlStore:
    """PostgreSQL-backed store; the only store that survives a restart (F7)."""

    durable = True

    def __init__(self, database_url: str, *, engine: Engine | None = None) -> None:
        self._engine = (
            engine if engine is not None else create_engine(database_url, pool_pre_ping=True)
        )
        self._session_factory = sessionmaker(self._engine, expire_on_commit=False)

    @property
    def engine(self) -> Engine:
        return self._engine

    def create_schema(self) -> None:
        """Create every table and the append-only guarantees (used by tests)."""

        with self._engine.begin() as connection:
            Base.metadata.create_all(connection)
            _install_append_only(connection)

    def store_receipt(self, record: ReceiptRecord) -> ReceiptRecord:
        statement = (
            postgresql_insert(Receipt)
            .values(**_receipt_values(record))
            .on_conflict_do_nothing(index_elements=["tenant_id", "request_id"])
            .returning(Receipt.request_id)
        )
        with self._session_factory() as session:
            inserted = session.execute(statement).scalar_one_or_none()
            if inserted is None:
                existing = _load_receipt(session, record.tenant_id, record.request_id)
                if existing is None:  # pragma: no cover - concurrent delete of an append-only row
                    raise ReceiptConflictError(record.tenant_id, record.request_id)
                session.commit()
                return _existing_or_conflict(existing, record)
            session.execute(
                postgresql_insert(ReceiptMetadata)
                .values(
                    tenant_id=record.tenant_id,
                    request_id=record.request_id,
                    metadata_digest=record.payload_digest,
                    payload=record.metadata,
                    created_at=record.created_at,
                )
                .on_conflict_do_nothing(index_elements=["tenant_id", "request_id"])
            )
            session.commit()
        return record

    def get_receipt(self, tenant_id: str, receipt_id: str) -> ReceiptRecord | None:
        with self._session_factory() as session:
            statement = (
                select(Receipt, ReceiptMetadata)
                .outerjoin(
                    ReceiptMetadata,
                    (ReceiptMetadata.tenant_id == Receipt.tenant_id)
                    & (ReceiptMetadata.request_id == Receipt.request_id),
                )
                .where(Receipt.tenant_id == tenant_id, Receipt.receipt_id == receipt_id)
            )
            row = session.execute(statement).first()
            return None if row is None else _to_record(row[0], row[1])

    def list_receipts(
        self, tenant_id: str, *, limit: int, cursor: str | None = None
    ) -> tuple[list[ReceiptRecord], str | None]:
        bounded = max(1, min(limit, RECEIPT_PAGE_LIMIT_MAX))
        statement = (
            select(Receipt, ReceiptMetadata)
            .outerjoin(
                ReceiptMetadata,
                (ReceiptMetadata.tenant_id == Receipt.tenant_id)
                & (ReceiptMetadata.request_id == Receipt.request_id),
            )
            .where(Receipt.tenant_id == tenant_id)
            .order_by(Receipt.decided_at.desc(), Receipt.request_id.desc())
            .limit(bounded + 1)
        )
        if cursor is not None:
            decoded = decode_cursor(cursor)
            if decoded is None:
                return [], None
            decided_at, request_id = decoded
            statement = statement.where(
                or_(
                    Receipt.decided_at < decided_at,
                    and_(
                        Receipt.decided_at == decided_at,
                        Receipt.request_id < request_id,
                    ),
                )
            )
        with self._session_factory() as session:
            rows = session.execute(statement).all()
        records = [_to_record(row[0], row[1]) for row in rows]
        if len(records) <= bounded:
            return records, None
        page = records[:bounded]
        last = page[-1]
        return page, encode_cursor(last.decided_at, last.request_id)

    def issue_grant(self, record: GrantRecord) -> GrantRecord:
        statement = (
            postgresql_insert(ConfirmationGrant)
            .values(
                tenant_id=record.tenant_id,
                run_id=record.run_id,
                step_id=record.step_id,
                execution_digest=record.execution_digest,
                issued_by=record.issued_by,
                issued_at=record.issued_at,
                expires_at=record.expires_at,
            )
            .on_conflict_do_nothing(constraint="uq_confirmation_grants_binding")
        )
        with self._session_factory() as session:
            session.execute(statement)
            session.commit()
        return record

    def grant_exists(
        self,
        tenant_id: str,
        *,
        run_id: str,
        step_id: int,
        execution_digest: str,
        now: datetime,
    ) -> bool:
        statement = select(func.count()).select_from(ConfirmationGrant).where(
            ConfirmationGrant.tenant_id == tenant_id,
            ConfirmationGrant.run_id == run_id,
            ConfirmationGrant.step_id == step_id,
            ConfirmationGrant.execution_digest == execution_digest,
            ConfirmationGrant.expires_at > now,
        )
        with self._session_factory() as session:
            return bool(session.execute(statement).scalar_one())

    def create_policy_set(self, record: PolicyRecord) -> PolicyRecord:
        statement = (
            postgresql_insert(PolicySet)
            .values(
                tenant_id=record.tenant_id,
                id=record.id,
                version=record.version,
                document=record.document,
                checksum=record.checksum,
                active=record.active,
                activated_at=record.activated_at,
                created_by=record.created_by,
                created_at=record.created_at,
            )
            .on_conflict_do_nothing(index_elements=["tenant_id", "id", "version"])
        )
        with self._session_factory() as session:
            session.execute(statement)
            session.commit()
        stored = self.get_policy_set(record.tenant_id, record.id, record.version)
        if stored is None:  # pragma: no cover - the insert above cannot vanish
            raise UnknownPolicySetError(f"policy set {record.id!r} {record.version!r} vanished")
        return stored

    def get_policy_set(self, tenant_id: str, policy_id: str, version: str) -> PolicyRecord | None:
        statement = select(PolicySet).where(
            PolicySet.tenant_id == tenant_id,
            PolicySet.id == policy_id,
            PolicySet.version == version,
        )
        with self._session_factory() as session:
            row = session.execute(statement).scalar_one_or_none()
        return None if row is None else _to_policy(row)

    def list_policy_sets(
        self, tenant_id: str, *, limit: int = POLICY_PAGE_LIMIT_MAX
    ) -> list[PolicyRecord]:
        statement = (
            select(PolicySet)
            .where(PolicySet.tenant_id == tenant_id)
            .order_by(PolicySet.id, PolicySet.created_at, PolicySet.version)
            .limit(max(1, min(limit, POLICY_PAGE_LIMIT_MAX)))
        )
        with self._session_factory() as session:
            rows = session.execute(statement).scalars().all()
        return [_to_policy(row) for row in rows]

    def activate_policy_set(
        self, tenant_id: str, policy_id: str, version: str, *, now: datetime
    ) -> PolicyRecord:
        with self._session_factory() as session:
            target = session.execute(
                select(PolicySet).where(
                    PolicySet.tenant_id == tenant_id,
                    PolicySet.id == policy_id,
                    PolicySet.version == version,
                )
            ).scalar_one_or_none()
            if target is None:
                raise UnknownPolicySetError(
                    f"policy set {policy_id!r} version {version!r} is unknown"
                )
            session.execute(
                update(PolicySet)
                .where(PolicySet.tenant_id == tenant_id, PolicySet.id == policy_id)
                .values(active=False, activated_at=None)
            )
            session.execute(
                update(PolicySet)
                .where(
                    PolicySet.tenant_id == tenant_id,
                    PolicySet.id == policy_id,
                    PolicySet.version == version,
                )
                .values(active=True, activated_at=now)
            )
            session.commit()
            row = session.execute(
                select(PolicySet).where(
                    PolicySet.tenant_id == tenant_id,
                    PolicySet.id == policy_id,
                    PolicySet.version == version,
                )
            ).scalar_one()
        return _to_policy(row)

    def active_policy_set(self, tenant_id: str, policy_id: str) -> PolicyRecord | None:
        statement = select(PolicySet).where(
            PolicySet.tenant_id == tenant_id,
            PolicySet.id == policy_id,
            PolicySet.active.is_(True),
        )
        with self._session_factory() as session:
            row = session.execute(statement).scalar_one_or_none()
        return None if row is None else _to_policy(row)

    def record_audit_event(self, record: AuditRecord) -> None:
        with self._session_factory() as session:
            session.execute(
                insert(AuditEvent).values(
                    tenant_id=record.tenant_id,
                    event_type=record.event_type,
                    actor_id=record.actor_id,
                    subject=record.subject,
                    details=record.details,
                    created_at=record.created_at,
                )
            )
            session.commit()

    def list_audit_events(
        self, tenant_id: str, *, limit: int = AUDIT_PAGE_LIMIT_MAX
    ) -> list[AuditRecord]:
        statement = (
            select(AuditEvent)
            .where(AuditEvent.tenant_id == tenant_id)
            .order_by(AuditEvent.id.desc())
            .limit(max(1, min(limit, AUDIT_PAGE_LIMIT_MAX)))
        )
        with self._session_factory() as session:
            rows = session.execute(statement).scalars().all()
        return [
            AuditRecord(
                tenant_id=row.tenant_id,
                event_type=row.event_type,
                actor_id=row.actor_id,
                details=dict(row.details),
                created_at=row.created_at,
                subject=row.subject,
                id=row.id,
            )
            for row in rows
        ]

    def apply_retention(self, *, now: datetime, days: int) -> RetentionReport:
        cutoff = _retention_cutoff(now, days)
        tenants: set[str] = set()
        with self._session_factory() as session:
            redacted = session.execute(
                update(ReceiptMetadata)
                .where(ReceiptMetadata.created_at < cutoff, ReceiptMetadata.payload.is_not(None))
                .values(payload=None, redacted_at=now)
                .returning(ReceiptMetadata.tenant_id)
            ).scalars().all()
            tenants.update(redacted)
            runs = session.execute(
                update(EvaluationRun)
                .where(
                    EvaluationRun.created_at < cutoff,
                    EvaluationRun.run_metadata.is_not(None),
                )
                .values(run_metadata=None, redacted_at=now)
                .returning(EvaluationRun.tenant_id)
            ).scalars().all()
            tenants.update(runs)
            session.commit()
        return RetentionReport(
            cutoff=cutoff,
            payloads_redacted=len(redacted),
            runs_redacted=len(runs),
            tenants=tuple(sorted(tenants)),
        )

    def ready(self) -> bool:
        try:
            with self._session_factory() as session:
                session.execute(select(1))
        except Exception:
            return False
        return True


def _install_append_only(connection: Any) -> None:
    """Install the append-only triggers, one statement at a time."""

    for statement in APPEND_ONLY_STATEMENTS:
        connection.exec_driver_sql(statement)


def _receipt_values(record: ReceiptRecord) -> dict[str, Any]:
    return {
        "tenant_id": record.tenant_id,
        "request_id": record.request_id,
        "receipt_id": record.receipt_id,
        "surface": record.surface,
        "run_id": record.run_id,
        "step_id": record.step_id,
        "principal_id": record.principal_id,
        "auth_method": record.auth_method,
        "policy_set_id": record.policy_set_id,
        "policy_set_version": record.policy_set_version,
        "verdict": record.verdict,
        "risk_score": record.risk_score,
        "confidence": record.confidence,
        "reason_codes": list(record.reason_codes),
        "action_digest": record.action_digest,
        "execution_digest": record.execution_digest,
        "payload_digest": record.payload_digest,
        "decided_at": record.decided_at,
        "valid_until": record.valid_until,
        "created_at": record.created_at,
    }


def _load_receipt(session: Session, tenant_id: str, request_id: str) -> ReceiptRecord | None:
    statement = (
        select(Receipt, ReceiptMetadata)
        .outerjoin(
            ReceiptMetadata,
            (ReceiptMetadata.tenant_id == Receipt.tenant_id)
            & (ReceiptMetadata.request_id == Receipt.request_id),
        )
        .where(Receipt.tenant_id == tenant_id, Receipt.request_id == request_id)
    )
    row = session.execute(statement).first()
    if row is None:
        return None
    return _to_record(row[0], row[1])


def _to_record(receipt: Receipt, metadata: ReceiptMetadata | None) -> ReceiptRecord:
    return ReceiptRecord(
        tenant_id=receipt.tenant_id,
        request_id=receipt.request_id,
        receipt_id=receipt.receipt_id,
        surface=receipt.surface,
        principal_id=receipt.principal_id,
        auth_method=receipt.auth_method,
        policy_set_id=receipt.policy_set_id,
        policy_set_version=receipt.policy_set_version,
        verdict=receipt.verdict,
        risk_score=receipt.risk_score,
        confidence=receipt.confidence,
        reason_codes=tuple(receipt.reason_codes),
        action_digest=receipt.action_digest,
        execution_digest=receipt.execution_digest,
        payload_digest=receipt.payload_digest,
        decided_at=receipt.decided_at,
        valid_until=receipt.valid_until,
        created_at=receipt.created_at,
        run_id=receipt.run_id,
        step_id=receipt.step_id,
        metadata=None if metadata is None else metadata.payload,
        metadata_redacted_at=None if metadata is None else metadata.redacted_at,
    )


def _to_policy(row: PolicySet) -> PolicyRecord:
    return PolicyRecord(
        tenant_id=row.tenant_id,
        id=row.id,
        version=row.version,
        document=dict(row.document),
        checksum=row.checksum,
        active=row.active,
        created_by=row.created_by,
        created_at=row.created_at,
        activated_at=row.activated_at,
    )


_STORES: dict[str | None, ReceiptStore] = {}
_STORES_LOCK = threading.Lock()


def open_store(settings: Settings) -> ReceiptStore:
    """Return the process store for this configuration (durable when configured)."""

    key = settings.database_url
    with _STORES_LOCK:
        store = _STORES.get(key)
        if store is None:
            store = SqlStore(key) if key else MemoryStore()
            _STORES[key] = store
        return store


def reset_store_cache() -> None:
    """Drop the process store cache (tests and after a configuration change)."""

    with _STORES_LOCK:
        _STORES.clear()


def apply_retention(
    store: ReceiptStore, *, now: datetime | None = None, days: int | None = None
) -> RetentionReport:
    """Redact payload-adjacent data past the window and record an audit event (D6).

    Digests, verdicts, reason codes, policy identity and actor identity are never
    touched: the audit trail is retained indefinitely.
    """

    moment = now or datetime.now(UTC)
    window = max(days if days is not None else 90, 0)
    report = store.apply_retention(now=moment, days=window)
    for tenant_id in report.tenants:
        store.record_audit_event(
            AuditRecord(
                tenant_id=tenant_id,
                event_type=EVENT_RETENTION_APPLIED,
                actor_id=RETENTION_ACTOR,
                subject=None,
                details={
                    "cutoff": report.cutoff.isoformat(),
                    "retention_days": window,
                    "payloads_redacted": report.payloads_redacted,
                    "runs_redacted": report.runs_redacted,
                },
                created_at=moment,
            )
        )
    return report


__all__ = [
    "AUDIT_PAGE_LIMIT_MAX",
    "DEFAULT_RECEIPT_PAGE_LIMIT",
    "EVENT_CONFIRMATION_ISSUED",
    "EVENT_CONFIRMATION_REFUSED",
    "EVENT_POLICY_ACTIVATED",
    "EVENT_POLICY_CREATED",
    "EVENT_RECEIPT_CONFLICT",
    "EVENT_RETENTION_APPLIED",
    "POLICY_PAGE_LIMIT_MAX",
    "RECEIPT_PAGE_LIMIT_MAX",
    "RETENTION_ACTOR",
    "AuditRecord",
    "GrantRecord",
    "MemoryStore",
    "PolicyRecord",
    "ReceiptConflictError",
    "ReceiptRecord",
    "ReceiptStore",
    "RetentionReport",
    "SqlStore",
    "UnknownPolicySetError",
    "apply_retention",
    "canonical_json",
    "decode_cursor",
    "digest_of",
    "encode_cursor",
    "open_store",
    "reset_store_cache",
]
