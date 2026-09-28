"""Task 5: Agent.protocol_version (NULL = legacy onboarding)."""
from alembic import op
import sqlalchemy as sa

revision = "e5f6a7b8c9d0"
down_revision = "d4e5f6a7b8c9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agents", sa.Column("protocol_version", sa.String(10), nullable=True))


def downgrade() -> None:
    op.drop_column("agents", "protocol_version")
