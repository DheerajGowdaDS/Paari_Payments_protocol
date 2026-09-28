"""Provenance flag for LLM-attributed payment intents.

Revision ID: b1c2d3e4f5a6
Revises: ab12cd34e5f6
Create Date: 2026-09-26

`llm_attributed` makes "this payment claimed an LLM origin" a first-class,
queryable fact instead of something an auditor has to infer from four nullable
strings. It is written only when the caller actually asserted causal
identifiers; payments with no causal ids get a `payment_proposed` audit event
instead of `llm_tool_call`, and this column keeps the two distinguishable.

This is a NEW revision rather than an edit to ab12cd34e5f6 on purpose: that
revision is already applied on live databases, so a change folded into it
would silently never reach them.
"""
from alembic import op
import sqlalchemy as sa

revision = "b1c2d3e4f5a6"
down_revision = "ab12cd34e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "payment_intents",
        sa.Column("llm_attributed", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("payment_intents", "llm_attributed")