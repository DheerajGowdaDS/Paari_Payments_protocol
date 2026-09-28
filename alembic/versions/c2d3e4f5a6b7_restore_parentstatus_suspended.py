"""Restore the SUSPENDED parent-authority state on Postgres.

Revision ID: c2d3e4f5a6b7
Revises: b1c2d3e4f5a6
Create Date: 2026-09-26

`models.ParentStatus` has carried `SUSPENDED` since the trust-provider work,
but the baseline migration created the native Postgres enum type with only
PENDING_VERIFICATION / ACTIVE / REJECTED / REVOKED, and no later revision
extended it. So on PostgreSQL:

    UPDATE parent_authorities SET status = 'SUSPENDED'   -- DataError

An operator therefore could not suspend a parent authority at all on the
production database, while SQLite (which stores the label as TEXT) accepted it
silently. The SQLite-only test suite could never surface this.

`ALTER TYPE ... ADD VALUE` is executed outside a transaction block because
PostgreSQL refuses to add an enum label inside one when the type is in use.
"""
from alembic import op

revision = "c2d3e4f5a6b7"
down_revision = "b1c2d3e4f5a6"
branch_labels = None
depends_on = None

# Values present in models.ParentStatus. Anything missing is added.
EXPECTED = ("PENDING_VERIFICATION", "ACTIVE", "SUSPENDED", "REJECTED", "REVOKED")


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return  # SQLite/MySQL store the label as text; nothing to do.
    with op.get_context().autocommit_block():
        for label in EXPECTED:
            op.execute(
                f"ALTER TYPE parentstatus ADD VALUE IF NOT EXISTS '{label}'"
            )


def downgrade() -> None:
    # Removing an enum label is not supported by PostgreSQL. Rolling back to
    # the previous revision leaves SUSPENDED present but unused, which is
    # harmless: models no longer offer it, so nothing can write it.
    pass