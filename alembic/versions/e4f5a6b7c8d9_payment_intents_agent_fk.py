"""Close the payment_intents -> agents referential-integrity gap.

Revision ID: e4f5a6b7c8d9
Revises: d3e4f5a6b7c8
Create Date: 2026-09-26

`models.PaymentIntent.agent_id` declares ForeignKey("agents.agent_id"), but
migration b8c9d0e1f2a3 deliberately skipped the constraint. Its header records
why:

    "_deny_unauthenticated writes platform-scope denial rows with
     agent_id='unauthenticated', which can never reference agents.agent_id"

That reason is now stale. No code path writes an 'unauthenticated' agent_id any
more (grep for it returns only this repository's own migration comments), and
the existing database contains zero orphan payment_intents, so the exception no
longer protects anything - it only leaves the money-path table without database
-level referential integrity that every other tenant-scoped table has.

This revision therefore applies the constraint the model has always claimed.
The migration is deliberately defensive: it verifies there are no orphans first
and aborts with a clear message rather than failing deep inside ALTER TABLE.

The ORPHAN_CHECKS guard in b8c9d0e1f2a3 is left untouched - it is historical and
harmless.
"""
from alembic import op
import sqlalchemy as sa

revision = "e4f5a6b7c8d9"
down_revision = "d3e4f5a6b7c8"
branch_labels = None
depends_on = None

FK_NAME = "fk_payment_intents_agent_id_agents"


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        # SQLite rebuilds the table through the model metadata and does not
        # enforce foreign keys by default; the model-level ForeignKey is the
        # declaration there. Adding it on SQLite would only slow the suite
        # down while changing no behaviour.
        return

    orphans = bind.execute(sa.text(
        "SELECT pi.agent_id, count(*) FROM payment_intents pi "
        "LEFT JOIN agents a ON pi.agent_id = a.agent_id "
        "WHERE a.agent_id IS NULL GROUP BY pi.agent_id LIMIT 20"
    )).fetchall()
    if orphans:
        sample = [row[0] for row in orphans]
        raise RuntimeError(
            f"migration e4f5a6b7c8d9: {len(sample)} distinct orphan "
            f"payment_intents.agent_id values; sample: {sample}. Delete or "
            "reassign those intents, then re-run upgrade."
        )

    op.execute(
        f"ALTER TABLE payment_intents ADD CONSTRAINT {FK_NAME} "
        "FOREIGN KEY (agent_id) REFERENCES agents(agent_id)"
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.execute(
        f"ALTER TABLE payment_intents DROP CONSTRAINT IF EXISTS {FK_NAME}"
    )