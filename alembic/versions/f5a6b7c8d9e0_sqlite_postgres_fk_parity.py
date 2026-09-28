"""Make every declared foreign key exist on BOTH backends.

Revision ID: f5a6b7c8d9e0
Revises: e4f5a6b7c8d9
Create Date: 2026-09-26

Why this revision exists
------------------------
`alembic check` reported eight missing foreign keys on SQLite. They are missing
because of a dialect gate, not a design decision: b8c9d0e1f2a3 (multitenancy),
c9d0e1f2a3b4 (request_proofs) and e4f5a6b7c8d9 (payment_intents.agent_id) each
wrap their `create_foreign_key` in `if bind.dialect.name == "postgresql"`, so
on SQLite the constraint was never emitted at all.

The consequence is worse than noisy migration state. The models declare
referential integrity on the money path (`payment_intents`,
`bounded_authorizations`, `provider_transactions`); on the default development
backend those declarations were fiction. A dangling `agent_id` inserted into a
dev database would be accepted there and rejected in production, which is the
exact class of bug Phase 2 was written to close - and closing it only on the
backend that already had it left the guarantee untestable in the environment
where the suite actually runs.

This revision therefore:
  * adds every model-declared foreign key that is absent from the live schema,
    on both backends, by introspection rather than by a hardcoded list of what
    each dialect "should" need;
  * refuses to run if any target column currently holds orphan rows, rather
    than failing inside a table rebuild;
  * is idempotent, so the Postgres path that already has some of these
    constraints is not asked to create them twice.

On SQLite a foreign key cannot be `ALTER TABLE ... ADD CONSTRAINT`-ed, so the
tables are rebuilt through `batch_alter_table`. Batch mode reflects the
existing database schema (not `Base.metadata`) and temporarily disables
`PRAGMA foreign_keys` for the rebuild, which is why this works on a populated
database.
"""
from alembic import op
import sqlalchemy as sa

revision = "f5a6b7c8d9e0"
down_revision = "e4f5a6b7c8d9"
branch_labels = None
depends_on = None

# (table, local column, referred table, referred column) - every FK that
# app/models.py declares on these tables. Order is fixed so the rebuild is
# deterministic, child-before-unrelated and never depending on a parent that is
# itself being rebuilt in the same pass.
REQUIRED_FKS = [
    ("payment_intents", "agent_id", "agents", "agent_id"),
    ("payment_intents", "mandate_id", "user_payment_mandates", "mandate_id"),
    ("mfa_challenges", "intent_id", "payment_intents", "intent_id"),
    ("bounded_authorizations", "intent_id", "payment_intents", "intent_id"),
    ("bounded_authorizations", "agent_id", "agents", "agent_id"),
    ("bounded_authorizations", "mandate_id", "user_payment_mandates", "mandate_id"),
    ("provider_transactions", "authorization_id", "bounded_authorizations", "authorization_id"),
    ("provider_transactions", "intent_id", "payment_intents", "intent_id"),
    ("provider_transactions", "agent_id", "agents", "agent_id"),
    ("user_payment_mandates", "agent_id", "agents", "agent_id"),
    ("payment_instrument_bindings", "mandate_id", "user_payment_mandates", "mandate_id"),
    ("request_proofs", "agent_id", "agents", "agent_id"),
]


def _fk_name(table: str, col: str, ref_table: str) -> str:
    return f"fk_{table}_{col}_{ref_table}"


def _existing_fk_columns(inspector, table: str) -> set[tuple[str, str]]:
    """(local column, referred table) pairs already enforced on `table`."""
    present: set[tuple[str, str]] = set()
    for fk in inspector.get_foreign_keys(table):
        for local, remote in zip(fk["constrained_columns"], fk["referred_columns"]):
            present.add((local, fk["referred_table"]))
    return present


def _assert_no_orphans(bind, table: str, col: str, ref_table: str, ref_col: str) -> None:
    orphans = bind.execute(sa.text(
        f"SELECT c.{col} FROM {table} c "
        f"LEFT JOIN {ref_table} p ON c.{col} = p.{ref_col} "
        f"WHERE c.{col} IS NOT NULL AND p.{ref_col} IS NULL LIMIT 20"
    )).fetchall()
    if orphans:
        raise RuntimeError(
            f"migration f5a6b7c8d9e0: {table}.{col} has orphan rows referencing "
            f"{ref_table}.{ref_col}; sample: {[r[0] for r in orphans]}. "
            "Reassign or delete those rows first - this migration will not "
            "silently discard data to make a constraint fit."
        )


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    is_sqlite = bind.dialect.name == "sqlite"

    tables = set(inspector.get_table_names())
    missing = []
    for table, col, ref_table, ref_col in REQUIRED_FKS:
        if table not in tables or ref_table not in tables:
            continue  # nothing to attach to on a database that predates the table
        if (col, ref_table) in _existing_fk_columns(inspector, table):
            continue
        _assert_no_orphans(bind, table, col, ref_table, ref_col)
        missing.append((table, col, ref_table, ref_col))

    for table, col, ref_table, ref_col in missing:
        name = _fk_name(table, col, ref_table)
        if is_sqlite:
            # SQLite has no ADD CONSTRAINT; rebuild the table with the FK added.
            with op.batch_alter_table(table, recreate="always") as batch_op:
                batch_op.create_foreign_key(
                    name, ref_table, [col], [ref_col]
                )
        else:
            op.create_foreign_key(name, table, ref_table, [col], [ref_col])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    is_sqlite = bind.dialect.name == "sqlite"

    for table, col, ref_table, ref_col in reversed(REQUIRED_FKS):
        if table not in inspector.get_table_names():
            continue
        name = _fk_name(table, col, ref_table)
        existing = {
            (fk.get("name"), tuple(fk["constrained_columns"]))
            for fk in inspector.get_foreign_keys(table)
        }
        # Drop only constraints this revision created: named like ours, or
        # unnamed but matching the column signature the previous revisions used.
        if not any(n == name or (n is None and cols == (col,)) for n, cols in existing):
            continue
        if is_sqlite:
            with op.batch_alter_table(table, recreate="always") as batch_op:
                batch_op.drop_constraint(name, type_="foreignkey")
        else:
            op.drop_constraint(name, table, type_="foreignkey")
