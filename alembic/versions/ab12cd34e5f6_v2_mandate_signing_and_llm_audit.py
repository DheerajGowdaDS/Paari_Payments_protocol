"""Paari v2 governance: signed user mandates, LLM causal audit, advanced spend limits.

Revision ID: ab12cd34e5f6
Revises: d0e1f2a3b4c5
Create Date: 2026-09-26
"""
from alembic import op
import sqlalchemy as sa
from app.database import UTCDateTime

revision = "ab12cd34e5f6"
down_revision = "d0e1f2a3b4c5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("user_payment_mandates", sa.Column("signing_key_id", sa.String(100), nullable=True))
    op.add_column("user_payment_mandates", sa.Column("signature_b64", sa.String(500), nullable=True))
    op.add_column("user_payment_mandates", sa.Column("user_public_key_pem", sa.String(2000), nullable=True))
    # UTCDateTime, not DateTime(timezone=True): SQLite silently drops tzinfo on
    # a plain DateTime, which is the exact P0 documented in app/database.py and
    # the repo-wide "never use DateTime(timezone=True)" constraint.
    op.add_column("user_payment_mandates", sa.Column("signed_at", UTCDateTime, nullable=True))

    op.add_column("payment_intents", sa.Column("llm_run_id", sa.String(120), nullable=True))
    op.add_column("payment_intents", sa.Column("llm_model", sa.String(200), nullable=True))
    op.add_column("payment_intents", sa.Column("llm_tool_call_id", sa.String(120), nullable=True))
    op.add_column("payment_intents", sa.Column("llm_tool_name", sa.String(80), nullable=True))

    op.add_column("user_payment_mandates", sa.Column("max_per_hour", sa.Integer(), nullable=True))
    op.add_column("user_payment_mandates", sa.Column("max_per_merchant_per_day", sa.Integer(), nullable=True))
    op.add_column("user_payment_mandates", sa.Column("max_category_per_day", sa.Integer(), nullable=True))

    # NOTE: `payment_intents.llm_attributed` is deliberately NOT added here.
    # This revision is already applied on live databases, so editing it would
    # never reach them. It lives in a later revision instead.


def downgrade() -> None:
    op.drop_column("user_payment_mandates", "max_category_per_day")
    op.drop_column("user_payment_mandates", "max_per_merchant_per_day")
    op.drop_column("user_payment_mandates", "max_per_hour")
    op.drop_column("payment_intents", "llm_tool_name")
    op.drop_column("payment_intents", "llm_tool_call_id")
    op.drop_column("payment_intents", "llm_model")
    op.drop_column("payment_intents", "llm_run_id")
    op.drop_column("user_payment_mandates", "signature_b64")
    op.drop_column("user_payment_mandates", "user_public_key_pem")
    op.drop_column("user_payment_mandates", "signed_at")
    op.drop_column("user_payment_mandates", "signing_key_id")
