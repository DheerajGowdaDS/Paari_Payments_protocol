"""Record which provider environment a transaction really came from.

Revision ID: a1b2c3d4e5f6
Revises: f5a6b7c8d9e0
Create Date: 2026-09-26

Paari's exportable evidence product is the proof bundle, and `payment_result`
in it asserted `provider: "razorpay"` plus `webhook_verified: true` from a
single column - whether a `webhook_event_id` was stored. Nothing recorded WHOSE
webhook that was. A run against the local simulator
(`scripts/stub_razorpay.py`, `scripts/llm_agent_e2e.py --settle`) therefore
minted a durable, schema-pinned `PAID / webhook_verified / provider=razorpay`
artifact with the same shape as one the real provider reported, and
`schemas/paari-payment-result.v1.schema.json` sets `additionalProperties: false`,
so there was no legal place in the artifact to record the difference.

Console banners are ephemeral; this bundle is what an auditor, a counterparty
merchant, or a future marketing claim quotes. So the distinction moves from
prose onto the row.

Existing rows get `unknown` rather than a guessed value: the default is the
honest answer, and `unknown` is what the boot guard and the bundle refuse to
present as a real settlement.

Batch mode is used because `provider_transactions` carries foreign keys, and on
SQLite a plain ALTER would rebuild the table and drop them.
"""
from alembic import op
import sqlalchemy as sa

revision = "a1b2c3d4e5f6"
down_revision = "f5a6b7c8d9e0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("provider_transactions", recreate="auto") as batch_op:
        batch_op.add_column(
            sa.Column("provider_environment", sa.String(length=16),
                      nullable=False, server_default="unknown")
        )
        batch_op.add_column(
            sa.Column("provider_key_id_prefix", sa.String(length=24), nullable=True)
        )
        batch_op.add_column(
            sa.Column("provider_api_base", sa.String(length=200), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("provider_transactions", recreate="auto") as batch_op:
        batch_op.drop_column("provider_api_base")
        batch_op.drop_column("provider_key_id_prefix")
        batch_op.drop_column("provider_environment")
