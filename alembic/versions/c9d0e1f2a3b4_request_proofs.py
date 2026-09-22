"""Paari v1 sender-constrained request proof replay table."""
from alembic import op
import sqlalchemy as sa
import app.database

revision = "c9d0e1f2a3b4"
down_revision = "b8c9d0e1f2a3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "request_proofs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("jti", sa.String(100), nullable=False, unique=True, index=True),
        sa.Column("agent_id", sa.String(64), nullable=False),
        sa.Column("org_id", sa.String(64), nullable=False),
        sa.Column("issued_at", app.database.UTCDateTime(timezone=True), nullable=False),
        sa.Column("expires_at", app.database.UTCDateTime(timezone=True), nullable=False),
        sa.Column("created_at", app.database.UTCDateTime(timezone=True), nullable=False),
    )
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.create_foreign_key("fk_request_proofs_agent", "request_proofs", "agents", ["agent_id"], ["agent_id"])


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.drop_constraint("fk_request_proofs_agent", "request_proofs", type_="foreignkey")
    op.drop_table("request_proofs")
