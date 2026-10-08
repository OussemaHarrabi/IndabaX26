"""SQLAlchemy 2 persistence models and the append-only guarantees (F7, D6).

PostgreSQL is the only supported database: the append-only enforcement below is
implemented with triggers, and JSON columns use ``JSONB`` so the immutability
trigger can compare documents with ``IS DISTINCT FROM``.

The durable tables are:

``receipts``
    One row per decision, keyed by ``(tenant_id, request_id)`` (D1). Append-only:
    an ``UPDATE`` or a ``DELETE`` raises. It carries digests, verdict, reason
    codes, policy identity and actor identity, which D6 retains indefinitely.
``receipt_metadata``
    The payload-adjacent half of a receipt: request-derived metadata that is
    digest-only by default and deleted by the retention procedure (D6). It is a
    separate table precisely so the audit row above can stay immutable.
``policy_sets``
    Immutable policy versions. The only mutable column is the ``active`` flag, and
    every change is also written to ``audit_events``.
``confirmation_grants``
    Grants issued through ``POST /api/v1/confirmations`` (D4).
``audit_events``
    Append-only administrative and security trail.
``evaluation_runs``
    Run metadata reserved for the evaluation milestones; it holds no verdicts.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Final

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

MAX_POLICY_DOCUMENT_BYTES: Final[int] = 262_144
"""Upper bound for a stored policy document, enforced at the API boundary."""

_APPEND_ONLY_FUNCTION: Final[str] = """
CREATE OR REPLACE FUNCTION aegisgraph_reject_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION USING
        MESSAGE = 'aegisgraph: ' || TG_TABLE_NAME || ' is append-only; ' || TG_OP
                  || ' is refused',
        ERRCODE = '55000';
END;
$$
"""

_POLICY_SET_FUNCTION: Final[str] = """
CREATE OR REPLACE FUNCTION aegisgraph_policy_set_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'aegisgraph: policy_sets is append-only; DELETE is refused'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.version IS DISTINCT FROM OLD.version
       OR NEW.document IS DISTINCT FROM OLD.document
       OR NEW.checksum IS DISTINCT FROM OLD.checksum
       OR NEW.created_by IS DISTINCT FROM OLD.created_by
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
    THEN
        RAISE EXCEPTION
            'aegisgraph: policy_sets versions are immutable; only the activation flag may change'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$
"""

APPEND_ONLY_TABLES: Final[tuple[str, ...]] = ("receipts", "audit_events")
"""Tables where any mutation at all is refused."""

APPEND_ONLY_STATEMENTS: Final[tuple[str, ...]] = (
    _APPEND_ONLY_FUNCTION,
    _POLICY_SET_FUNCTION,
    *(
        f"DROP TRIGGER IF EXISTS aegisgraph_{table}_append_only ON {table}"
        for table in APPEND_ONLY_TABLES
    ),
    *(
        f"CREATE TRIGGER aegisgraph_{table}_append_only BEFORE UPDATE OR DELETE ON {table} "
        "FOR EACH ROW EXECUTE FUNCTION aegisgraph_reject_mutation()"
        for table in APPEND_ONLY_TABLES
    ),
    "DROP TRIGGER IF EXISTS aegisgraph_policy_sets_immutable ON policy_sets",
    "CREATE TRIGGER aegisgraph_policy_sets_immutable BEFORE UPDATE OR DELETE ON policy_sets "
    "FOR EACH ROW EXECUTE FUNCTION aegisgraph_policy_set_immutable()",
)
"""DDL that installs the append-only guarantees, one statement per element.

Each element is a single SQL statement, so it can be executed by a driver that
refuses multi-statement strings. Alembic migrations and the test schema helper
both iterate this tuple, which keeps one source of truth for the guarantees.
"""

APPEND_ONLY_SQL: Final[str] = ";\n".join(APPEND_ONLY_STATEMENTS)
"""The same DDL as one readable script, for documentation and review."""


class Base(DeclarativeBase):
    """Declarative base for every AegisGraph table."""


class Receipt(Base):
    """The durable, append-only audit row for one decision (F7, D1, D6)."""

    __tablename__ = "receipts"

    tenant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    request_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    receipt_id: Mapped[str] = mapped_column(String(64), nullable=False)
    surface: Mapped[str] = mapped_column(String(32), nullable=False)
    run_id: Mapped[str | None] = mapped_column(String(256))
    step_id: Mapped[int | None] = mapped_column(Integer)
    principal_id: Mapped[str] = mapped_column(String(256), nullable=False)
    auth_method: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_set_id: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_set_version: Mapped[str] = mapped_column(String(64), nullable=False)
    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    reason_codes: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    action_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    execution_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    decision_body: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("ix_receipts_tenant_decided_at", "tenant_id", "decided_at"),
        Index("ix_receipts_tenant_receipt_id", "tenant_id", "receipt_id", unique=True),
    )


class ReceiptMetadata(Base):
    """Payload-adjacent metadata for a receipt; the retention window applies here."""

    __tablename__ = "receipt_metadata"

    tenant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    request_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    metadata_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any] | None] = mapped_column("metadata", JSONB)
    redacted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class PolicySet(Base):
    """An immutable policy version with a single mutable activation flag (D3)."""

    __tablename__ = "policy_sets"

    tenant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    version: Mapped[str] = mapped_column(String(64), primary_key=True)
    document: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (Index("ix_policy_sets_tenant_active", "tenant_id", "id", "active"),)


class ConfirmationGrant(Base):
    """A grant issued by ``POST /api/v1/confirmations`` and bound to one step (D4)."""

    __tablename__ = "confirmation_grants"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    run_id: Mapped[str] = mapped_column(String(256), nullable=False)
    step_id: Mapped[int] = mapped_column(Integer, nullable=False)
    execution_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    issued_by: Mapped[str] = mapped_column(String(256), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "run_id",
            "step_id",
            "execution_digest",
            name="uq_confirmation_grants_binding",
        ),
        Index("ix_confirmation_grants_tenant_expires_at", "tenant_id", "expires_at"),
    )


class AuditEvent(Base):
    """An append-only administrative or security event."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(256), nullable=False)
    subject: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        Index("ix_audit_events_tenant_created_at", "tenant_id", "created_at"),
        Index("ix_audit_events_tenant_event_type", "tenant_id", "event_type"),
    )


class EvaluationRun(Base):
    """Run metadata reserved for the evaluation milestones (no verdicts here)."""

    __tablename__ = "evaluation_runs"

    tenant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    step_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    run_metadata: Mapped[dict[str, Any] | None] = mapped_column("metadata", JSONB)
    redacted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


__all__ = [
    "APPEND_ONLY_SQL",
    "APPEND_ONLY_STATEMENTS",
    "APPEND_ONLY_TABLES",
    "MAX_POLICY_DOCUMENT_BYTES",
    "AuditEvent",
    "Base",
    "ConfirmationGrant",
    "EvaluationRun",
    "PolicySet",
    "Receipt",
    "ReceiptMetadata",
]
