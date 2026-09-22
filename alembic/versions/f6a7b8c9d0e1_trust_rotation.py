"""Trust-tier, key-rotation and revocation fields introduced in Phase 6."""
from alembic import op
import sqlalchemy as sa

revision = "f6a7b8c9d0e1"
down_revision = "e5f6a7b8c9d0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("parent_authorities", sa.Column("trust_tier", sa.String(20), nullable=True, server_default="self_asserted"))
    op.add_column("parent_authorities", sa.Column("kyb_provider_ref", sa.String(200), nullable=True))
    op.execute("UPDATE parent_authorities SET trust_tier='self_asserted' WHERE trust_tier IS NULL")
    with op.batch_alter_table("parent_authorities") as batch:
        batch.alter_column("trust_tier", existing_type=sa.String(20), nullable=False)
    op.add_column("agents", sa.Column("old_public_key_pem", sa.String(2000), nullable=True))
    op.add_column("credentials", sa.Column("superseded_by", sa.String(64), nullable=True))
    op.add_column("credentials", sa.Column("rotates_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("agents", sa.Column("key_sunset_at", sa.DateTime(timezone=True), nullable=True))

def downgrade() -> None:
    op.drop_column("credentials", "rotates_at")
    op.drop_column("credentials", "superseded_by")
    op.drop_column("agents", "key_sunset_at")
    op.drop_column("agents", "old_public_key_pem")
    op.drop_column("parent_authorities", "kyb_provider_ref")
    op.drop_column("parent_authorities", "trust_tier")
