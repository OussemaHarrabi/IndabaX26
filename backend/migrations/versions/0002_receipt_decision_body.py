"""Store the exact decision body on a receipt so a replay is faithful (H3-02).

Revision ID: 0002_receipt_decision_body
Revises: 0001_initial
Create Date: 2026-10-08

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_receipt_decision_body"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSONB = postgresql.JSONB(astext_type=sa.Text())


def upgrade() -> None:
    op.add_column(
        "receipts",
        sa.Column("decision_body", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
    )


def downgrade() -> None:
    op.drop_column("receipts", "decision_body")
