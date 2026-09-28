"""add provider_transactions reconciled_at

Revision ID: 9f3c2e1a4b5d
Revises: ac7a06f11369
Create Date: 2026-09-17

Task 3: the reconciler stamps when provider truth was last adopted.
Hand-written, same pattern as 0002.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

import app.database


revision: str = '9f3c2e1a4b5d'
down_revision: Union[str, None] = 'ac7a06f11369'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'provider_transactions',
        sa.Column('reconciled_at', app.database.UTCDateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('provider_transactions', 'reconciled_at')
