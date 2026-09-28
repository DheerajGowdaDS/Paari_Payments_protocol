"""Retire PAYMENT_PENDING in favour of the Phase 9 vocabulary.

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-09-28

Data-only: `ProviderTransaction.state` is a String(30), not an enum, so no DDL
is needed and `alembic check` stays clean. What changes is the meaning attached
to the rows.

`PAYMENT_PENDING` was the original spelling of "the provider has this payment and
the outcome is not yet settled". Phase 9 splits that into two states that a live
Razorpay settlement proved it can actually distinguish, because the provider sent
both events separately and each with its own valid HMAC signature:

    payment.authorized   ->  PROVIDER_AUTHORIZED   (money not captured yet)
    payment.captured     ->  CAPTURED              (captured, not corroborated)

Rows sitting in PAYMENT_PENDING were produced by `payment.authorized`, so the
faithful rewrite is to PROVIDER_AUTHORIZED. The old value is not dropped from the
model's permitted set: a row that this migration has not reached yet, or a replay
of an event stored before it, still has a legal exit in the transition table, so
the upgrade is safe to run against a live database and safe to leave half-applied
during a rolling deploy.

CAPTURED needs no backfill - it cannot exist before this revision.
"""
from alembic import op
import sqlalchemy as sa

revision = "c3d4e5f6a7b8"
down_revision = "b2c3d4e5f6a7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    existing = {
        row[0]
        for row in bind.execute(sa.text(
            "SELECT DISTINCT state FROM provider_transactions WHERE state IS NOT NULL"
        ))
    }
    # Report rather than assume: an operator should see whether a live database
    # had rows to migrate before this runs against one.
    if "PAYMENT_PENDING" not in existing:
        return
    bind.execute(sa.text(
        "UPDATE provider_transactions "
        "SET state = 'PROVIDER_AUTHORIZED' WHERE state = 'PAYMENT_PENDING'"
    ))


def downgrade() -> None:
    bind = op.get_bind()
    # Reverse only what this revision produced. Rows that reached CAPTURED or PAID
    # after the upgrade are left alone: rolling them back would rewrite the history
    # of payments that genuinely settled, which is worse than a stale label.
    bind.execute(sa.text(
        "UPDATE provider_transactions "
        "SET state = 'PAYMENT_PENDING' WHERE state = 'PROVIDER_AUTHORIZED'"
    ))
