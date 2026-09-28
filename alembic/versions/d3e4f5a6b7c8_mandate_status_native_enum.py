"""Align user_payment_mandates.status with the model's native enum.

Revision ID: d3e4f5a6b7c8
Revises: c2d3e4f5a6b7
Create Date: 2026-09-26

`models.UserPaymentMandate.status` is `Enum(MandateStatus)`, i.e. a native
`mandatestatus` type on PostgreSQL, but migration d0e1f2a3b4c5 created the
column as `varchar(20)` with a lowercase server default of 'active'. So:

- `alembic check` reports permanent drift (model wants the enum type, the
  database has a string column);
- the ORM writes the enum label while the column default is a different case,
  which is a latent mismatch for any row that ever falls back to the default;
- this is the same drift class that made ParentStatus.SUSPENDED unreachable.

This migration creates the native type and converts the column. Existing values
are mapped case-insensitively so rows written by the ORM ('ACTIVE'/'REVOKED')
and rows written by the column default ('active') both survive.

SQLite/MySQL are skipped: they store the label as TEXT, where the model and
migration already agree.
"""
from alembic import op
import sqlalchemy as sa

revision = "d3e4f5a6b7c8"
down_revision = "c2d3e4f5a6b7"
branch_labels = None
depends_on = None

LABELS = ("ACTIVE", "REVOKED", "EXPIRED")


def _ensure_type() -> None:
    """CREATE TYPE has no IF NOT EXISTS in PostgreSQL, so guard it."""
    op.execute(
        "DO $$ BEGIN "
        "  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'mandatestatus') THEN "
        "    CREATE TYPE mandatestatus AS ENUM ('ACTIVE', 'REVOKED', 'EXPIRED'); "
        "  END IF; "
        "END $$;"
    )


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    _ensure_type()
    with op.get_context().autocommit_block():
        for label in LABELS:
            op.execute(f"ALTER TYPE mandatestatus ADD VALUE IF NOT EXISTS '{label}'")
    op.execute("ALTER TABLE user_payment_mandates ALTER COLUMN status DROP DEFAULT")
    op.execute(
        "UPDATE user_payment_mandates SET status = upper(status) "
        "WHERE status IS NOT NULL AND status <> upper(status)"
    )
    op.execute(
        "ALTER TABLE user_payment_mandates ALTER COLUMN status "
        "TYPE mandatestatus USING status::mandatestatus"
    )
    op.execute(
        "ALTER TABLE user_payment_mandates ALTER COLUMN status "
        "SET DEFAULT 'ACTIVE'::mandatestatus"
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.execute("ALTER TABLE user_payment_mandates ALTER COLUMN status DROP DEFAULT")
    op.execute(
        "ALTER TABLE user_payment_mandates ALTER COLUMN status "
        "TYPE varchar(20) USING status::text"
    )
    op.execute("ALTER TABLE user_payment_mandates ALTER COLUMN status SET DEFAULT 'active'")