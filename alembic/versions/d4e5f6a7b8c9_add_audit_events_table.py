"""add audit_events hash-chained table

Revision ID: d4e5f6a7b8c9
Revises: 9f3c2e1a4b5d
Create Date: 2026-09-17

Task 4: append-only audit log. Hand-written, same pattern as 0002/0003.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

import app.database


revision: str = 'd4e5f6a7b8c9'
down_revision: Union[str, None] = '9f3c2e1a4b5d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'audit_events',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('org_id', sa.String(64), nullable=True),
        sa.Column('transaction_id', sa.String(100), nullable=False, index=True),
        sa.Column('agent_id', sa.String(64), nullable=False, index=True),
        sa.Column('parent_id', sa.String(64), nullable=True),
        sa.Column('kind', sa.String(40), nullable=False),
        sa.Column('detail', sa.JSON(), nullable=False),
        sa.Column('prev_hash', sa.String(64), nullable=False),
        sa.Column('event_hash', sa.String(64), nullable=False),
        sa.Column('created_at', app.database.UTCDateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('audit_events')
