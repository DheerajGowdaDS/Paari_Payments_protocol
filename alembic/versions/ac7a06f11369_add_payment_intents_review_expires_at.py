"""Review expiry for parked payment intents."""
from alembic import op
import sqlalchemy as sa

revision = "ac7a06f11369"
down_revision = "cd2aba0d4cab"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("payment_intents", sa.Column("review_expires_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("payment_intents", "review_expires_at")
