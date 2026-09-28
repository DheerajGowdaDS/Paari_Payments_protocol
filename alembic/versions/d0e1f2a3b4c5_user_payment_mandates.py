"""Add user payment mandates and provider mandate bindings."""
from alembic import op
import sqlalchemy as sa

revision = "d0e1f2a3b4c5"
down_revision = "c9d0e1f2a3b4"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "user_payment_mandates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("mandate_id", sa.String(length=64), nullable=False, unique=True),
        sa.Column("org_id", sa.String(length=64), nullable=False, index=True),
        sa.Column("user_id", sa.String(length=128), nullable=False, index=True),
        sa.Column("agent_id", sa.String(length=64), sa.ForeignKey("agents.agent_id"), nullable=False, index=True),
        sa.Column("max_per_transaction", sa.Integer(), nullable=False),
        sa.Column("max_daily_amount", sa.Integer(), nullable=False),
        sa.Column("currency", sa.String(length=10), nullable=False),
        sa.Column("allowed_merchants", sa.JSON(), nullable=True),
        sa.Column("allowed_categories", sa.JSON(), nullable=True),
        sa.Column("require_review_above", sa.Integer(), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approval_reference", sa.String(length=200), nullable=True),
    )
    op.create_index("ix_user_payment_mandates_active_lookup", "user_payment_mandates", ["agent_id", "org_id", "status", "expires_at"])

    op.create_table(
        "payment_instrument_bindings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("binding_id", sa.String(length=64), nullable=False, unique=True),
        sa.Column("org_id", sa.String(length=64), nullable=False, index=True),
        sa.Column("mandate_id", sa.String(length=64), sa.ForeignKey("user_payment_mandates.mandate_id"), nullable=False, index=True),
        sa.Column("provider", sa.String(length=50), nullable=False),
        sa.Column("provider_customer_ref", sa.String(length=200), nullable=True),
        sa.Column("provider_mandate_ref", sa.String(length=200), nullable=False),
        sa.Column("provider_instrument_ref", sa.String(length=200), nullable=True),
        sa.Column("currency", sa.String(length=10), nullable=False),
        sa.Column("max_amount_minor_units", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("uq_provider_mandate_ref", "payment_instrument_bindings", ["provider", "provider_mandate_ref"], unique=True)

    with op.batch_alter_table("payment_intents") as batch_op:
        batch_op.add_column(sa.Column("mandate_id", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("merchant_category", sa.String(length=80), nullable=True))
        batch_op.create_foreign_key("fk_payment_intents_mandate_id", "user_payment_mandates", ["mandate_id"], ["mandate_id"])
        batch_op.create_index("ix_payment_intents_mandate_id", ["mandate_id"])

    with op.batch_alter_table("bounded_authorizations") as batch_op:
        batch_op.add_column(sa.Column("mandate_id", sa.String(length=64), nullable=True))
        batch_op.create_foreign_key("fk_bounded_authorizations_mandate_id", "user_payment_mandates", ["mandate_id"], ["mandate_id"])
        batch_op.create_index("ix_bounded_authorizations_mandate_id", ["mandate_id"])


def downgrade():
    with op.batch_alter_table("bounded_authorizations") as batch_op:
        batch_op.drop_index("ix_bounded_authorizations_mandate_id")
        batch_op.drop_constraint("fk_bounded_authorizations_mandate_id", type_="foreignkey")
        batch_op.drop_column("mandate_id")
    with op.batch_alter_table("payment_intents", recreate="always") as batch_op:
        batch_op.drop_index("ix_payment_intents_mandate_id")
        batch_op.drop_constraint("fk_payment_intents_mandate_id", type_="foreignkey")
        batch_op.drop_column("merchant_category")
        batch_op.drop_column("mandate_id")
    op.drop_index("uq_provider_mandate_ref", table_name="payment_instrument_bindings")
    op.drop_table("payment_instrument_bindings")
    op.drop_index("ix_user_payment_mandates_active_lookup", table_name="user_payment_mandates")
    op.drop_table("user_payment_mandates")
