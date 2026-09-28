"""Task 7: rate_buckets table (shared counters; org_id nullable per Amendment 4)."""
from alembic import op
import sqlalchemy as sa

from app.database import UTCDateTime

revision = "a7b8c9d0e1f2"
down_revision = "f6a7b8c9d0e1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rate_buckets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.String(64), nullable=True),
        sa.Column("scope", sa.String(100), nullable=False, index=True),
        sa.Column("window_start", UTCDateTime(), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint("scope", "window_start", name="uq_rate_buckets_scope_window"),
    )


def downgrade() -> None:
    op.drop_table("rate_buckets")
