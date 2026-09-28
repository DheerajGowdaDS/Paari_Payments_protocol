"""Task 8: multi-tenancy. Creates organizations + provider_accounts, adds
org_id to every table (backfilled to the default org), enforces NOT NULL,
and adds real Postgres FK constraints for the string references.

Deliberate exception: payment_intents.agent_id gets NO Postgres FK
constraint. _deny_unauthenticated writes platform-scope denial rows with
agent_id='unauthenticated', which can never reference agents.agent_id;
integrity there is enforced at the application layer. The model-level
ForeignKey declaration stays as documentation/join hint only.
"""
from alembic import op
import sqlalchemy as sa

import app.database

revision = "b8c9d0e1f2a3"
down_revision = "a7b8c9d0e1f2"
branch_labels = None
depends_on = None

DEFAULT_ORG = "default"

ORG_TABLES = [
    "parent_authorities",
    "delegation_records",
    "revocation_records",
    "agents",
    "credentials",
    "auth_nonces",
    "payment_intents",
    "mfa_challenges",
    "bounded_authorizations",
    "provider_transactions",
    "audit_events",
    "rate_buckets",
]

# The models declared org_id on audit_events/rate_buckets (Tasks 4/7) and
# those migrations created the columns - everything else gets it here.
# (The ADD is conditional on inspection so re-upgrade after a downgrade,
# which must NOT drop 0004/0007-owned columns, always converges.)
ADD_ORG_COLUMN_TABLES = [t for t in ORG_TABLES if t not in ("audit_events", "rate_buckets")]

# (child_table, child_col, parent_table, parent_col, extra_where_sql)
ORPHAN_CHECKS = [
    ("payment_intents", "agent_id", "agents", "agent_id",
     "child.agent_id != 'unauthenticated'"),
    ("bounded_authorizations", "agent_id", "agents", "agent_id", None),
    ("bounded_authorizations", "intent_id", "payment_intents", "intent_id", None),
    ("provider_transactions", "authorization_id", "bounded_authorizations",
     "authorization_id", None),
    ("provider_transactions", "agent_id", "agents", "agent_id", None),
    ("provider_transactions", "intent_id", "payment_intents", "intent_id", None),
    ("mfa_challenges", "intent_id", "payment_intents", "intent_id", None),
]

# Same relations as real Postgres constraints (payment_intents.agent_id
# excluded - see module docstring).
PG_FOREIGN_KEYS = [
    ("bounded_authorizations", "agent_id", "agents", "agent_id"),
    ("bounded_authorizations", "intent_id", "payment_intents", "intent_id"),
    ("provider_transactions", "authorization_id", "bounded_authorizations",
     "authorization_id"),
    ("provider_transactions", "agent_id", "agents", "agent_id"),
    ("provider_transactions", "intent_id", "payment_intents", "intent_id"),
    ("mfa_challenges", "intent_id", "payment_intents", "intent_id"),
]


def _fk_name(child, col):
    return f"fk_0008_{child}_{col}"


def upgrade() -> None:
    bind = op.get_bind()
    is_pg = bind.dialect.name == "postgresql"

    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("created_at", app.database.UTCDateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "provider_accounts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.String(64), nullable=False, unique=True),
        sa.Column("key_id_label", sa.String(200), nullable=False, default="default"),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("created_at", app.database.UTCDateTime(timezone=True), nullable=False),
    )
    op.execute(
        sa.text("INSERT INTO organizations (org_id, name, created_at) VALUES ('default', 'Default organization', CURRENT_TIMESTAMP)")
    )

    existing = {
        table: {col["name"] for col in sa.inspect(bind).get_columns(table)}
        for table in ORG_TABLES
    }
    for table in ADD_ORG_COLUMN_TABLES:
        if "org_id" in existing[table]:
            continue
        with op.batch_alter_table(table) as batch_op:
            batch_op.add_column(sa.Column("org_id", sa.String(64), nullable=True))
    for table in ORG_TABLES:
        # DEFAULT_ORG is a hardcoded constant, not user input.
        op.execute(sa.text(f"UPDATE {table} SET org_id = 'default' WHERE org_id IS NULL"))

    for child, col, parent, parent_col, extra in ORPHAN_CHECKS:
        where = f"parent.{parent_col} IS NULL"
        if extra:
            where += f" AND {extra}"
        orphans = bind.execute(sa.text(
            f"SELECT child.{col} FROM {child} AS child "
            f"LEFT JOIN {parent} AS parent ON child.{col} = parent.{parent_col} "
            f"WHERE {where} LIMIT 20"
        )).fetchall()
        if orphans:
            sample = [row[0] for row in orphans]
            raise RuntimeError(
                f"migration 0008: orphan rows in {child}.{col} "
                f"(no matching {parent}.{parent_col}); sample: {sample}. "
                "Resolve or delete them, then re-run upgrade."
            )

    for table in ORG_TABLES:
        with op.batch_alter_table(table) as batch_op:
            batch_op.alter_column("org_id", existing_type=sa.String(64), nullable=False)

    if is_pg:
        for child, col, parent, parent_col in PG_FOREIGN_KEYS:
            op.create_foreign_key(_fk_name(child, col), child, parent, [col], [parent_col])


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for child, col, parent, parent_col in PG_FOREIGN_KEYS:
            op.drop_constraint(_fk_name(child, col), child, type_="foreignkey")
    # Only drop what this migration added - audit_events/rate_buckets
    # columns belong to 0004/0007 and must survive our downgrade, or the
    # next upgrade would face a missing column it no longer adds.
    for table in ADD_ORG_COLUMN_TABLES:
        with op.batch_alter_table(table) as batch_op:
            batch_op.drop_column("org_id")
    op.drop_table("provider_accounts")
    op.drop_table("organizations")
