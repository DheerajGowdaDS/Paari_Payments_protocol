"""Add hash_version to audit_events for digest integrity v2.

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-09-28

Existing rows get hash_version=1 (legacy detail-only digest). New rows
get hash_version=2 (full metadata digest covering kind, agent_id,
parent_id, org_id, transaction_id, created_at).
"""
from alembic import op
import sqlalchemy as sa

revision = "b2c3d4e5f6a7"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("audit_events", recreate="auto") as batch_op:
        batch_op.add_column(
            sa.Column("hash_version", sa.Integer(), nullable=False, server_default="1")
        )


def downgrade() -> None:
    with op.batch_alter_table("audit_events", recreate="auto") as batch_op:
        batch_op.drop_column("hash_version")
