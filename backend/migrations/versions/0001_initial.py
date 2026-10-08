"""Initial AegisGraph persistence schema (M2).

Creates the durable receipt/audit/policy/confirmation tables and installs the
append-only guarantees from :mod:`aegisgraph.models`, which is the single source of
truth for that DDL.

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-08

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from aegisgraph.models import APPEND_ONLY_STATEMENTS
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSONB = postgresql.JSONB(astext_type=sa.Text())


def upgrade() -> None:
    op.create_table(
        "receipts",
        sa.Column("tenant_id", sa.String(128), primary_key=True),
        sa.Column("request_id", sa.String(128), primary_key=True),
        sa.Column("receipt_id", sa.String(64), nullable=False),
        sa.Column("surface", sa.String(32), nullable=False),
        sa.Column("run_id", sa.String(256)),
        sa.Column("step_id", sa.Integer()),
        sa.Column("principal_id", sa.String(256), nullable=False),
        sa.Column("auth_method", sa.String(32), nullable=False),
        sa.Column("policy_set_id", sa.String(128), nullable=False),
        sa.Column("policy_set_version", sa.String(64), nullable=False),
        sa.Column("verdict", sa.String(16), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("reason_codes", JSONB, nullable=False),
        sa.Column("action_digest", sa.String(64), nullable=False),
        sa.Column("execution_digest", sa.String(64), nullable=False),
        sa.Column("payload_digest", sa.String(64), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_receipts_tenant_decided_at", "receipts", ["tenant_id", "decided_at"])
    op.create_index(
        "ix_receipts_tenant_receipt_id", "receipts", ["tenant_id", "receipt_id"], unique=True
    )

    op.create_table(
        "receipt_metadata",
        sa.Column("tenant_id", sa.String(128), primary_key=True),
        sa.Column("request_id", sa.String(128), primary_key=True),
        sa.Column("metadata_digest", sa.String(64), nullable=False),
        sa.Column("metadata", JSONB),
        sa.Column("redacted_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    op.create_table(
        "policy_sets",
        sa.Column("tenant_id", sa.String(128), primary_key=True),
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("version", sa.String(64), primary_key=True),
        sa.Column("document", JSONB, nullable=False),
        sa.Column("checksum", sa.String(64), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("activated_at", sa.DateTime(timezone=True)),
        sa.Column("created_by", sa.String(256), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_policy_sets_tenant_active", "policy_sets", ["tenant_id", "id", "active"])

    op.create_table(
        "confirmation_grants",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("run_id", sa.String(256), nullable=False),
        sa.Column("step_id", sa.Integer(), nullable=False),
        sa.Column("execution_digest", sa.String(64), nullable=False),
        sa.Column("issued_by", sa.String(256), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "tenant_id",
            "run_id",
            "step_id",
            "execution_digest",
            name="uq_confirmation_grants_binding",
        ),
    )
    op.create_index(
        "ix_confirmation_grants_tenant_expires_at",
        "confirmation_grants",
        ["tenant_id", "expires_at"],
    )

    op.create_table(
        "audit_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("actor_id", sa.String(256), nullable=False),
        sa.Column("subject", sa.Text()),
        sa.Column(
            "details", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_audit_events_tenant_created_at", "audit_events", ["tenant_id", "created_at"]
    )
    op.create_index(
        "ix_audit_events_tenant_event_type", "audit_events", ["tenant_id", "event_type"]
    )

    op.create_table(
        "evaluation_runs",
        sa.Column("tenant_id", sa.String(128), primary_key=True),
        sa.Column("run_id", sa.String(256), primary_key=True),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("ended_at", sa.DateTime(timezone=True)),
        sa.Column("step_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("metadata", JSONB),
        sa.Column("redacted_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    for statement in APPEND_ONLY_STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    op.drop_table("evaluation_runs")
    op.drop_table("audit_events")
    op.drop_table("confirmation_grants")
    op.drop_table("policy_sets")
    op.drop_table("receipt_metadata")
    op.drop_table("receipts")
    op.execute("DROP FUNCTION IF EXISTS aegisgraph_reject_mutation()")
    op.execute("DROP FUNCTION IF EXISTS aegisgraph_policy_set_immutable()")
