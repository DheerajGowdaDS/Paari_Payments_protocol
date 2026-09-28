"""PostgreSQL-only migration and constraint tests.

Why these read `TEST_DATABASE_URL` and not `DATABASE_URL`
--------------------------------------------------------
Two things went wrong when this file used the deployment variable.

First, the tests were skipped by construction in any environment that had
correctly isolated itself: the suite targets `TEST_DATABASE_URL` (see
tests/conftest.py), so a run genuinely executing on PostgreSQL still printed
"DATABASE_URL not set to postgresql" and skipped. The FK-violation test — the
explicit acceptance criterion for closing the `payment_intents.agent_id`
integrity gap — and the Postgres `alembic check` therefore never ran, on either
backend. A skipped test is not a passing test, and this file's skips were
covering the two claims that most needed covering.

Second, when `DATABASE_URL` *was* set, these tests migrated and inserted into
whatever it pointed at — the deployment database.

So the target is the same disposable database the rest of the suite uses, and
`assert_disposable_database_url` is applied before the schema is touched.
"""
import uuid

import pytest

from tests.conftest import TEST_DATABASE_URL, _migrate_fresh


def _require_postgres():
    if not TEST_DATABASE_URL.startswith("postgresql"):
        pytest.skip(
            "this run targets "
            f"{TEST_DATABASE_URL.split('://')[0]!r}; PostgreSQL-only test. "
            "Set TEST_DATABASE_URL to a disposable PostgreSQL database "
            "whose name ends in _test to execute it."
        )


def test_alembic_migrates_postgres_and_reports_no_drift():
    """The whole chain applies cleanly, and the models and the live schema agree.

    `command.check` is the parity gate: it is the only assertion that the model,
    the migration chain, and the actual PostgreSQL schema describe the same
    objects, which is what Phase 3's acceptance criterion asked for.
    """
    _require_postgres()
    from alembic import command
    from alembic.config import Config
    import pathlib

    # Rebuild from empty so drift is measured against this revision chain, not
    # against whatever state a previous run left behind.
    _migrate_fresh(TEST_DATABASE_URL)

    cfg = Config(str(pathlib.Path("alembic.ini")))
    cfg.set_main_option("sqlalchemy.url", TEST_DATABASE_URL)
    command.check(cfg)


def test_payment_intents_agent_id_fk_enforced_on_postgres():
    """An intent naming a nonexistent agent must be rejected by the database.

    Self-contained: it migrates its own schema rather than depending on the
    previous test having run first, and it uses per-run unique keys so a repeat
    execution fails for the right reason. The assertion names the specific
    constraint instead of accepting any foreign-key error — otherwise an
    unrelated violation (a duplicate idempotency key, say) would look like the
    guarantee this test exists to prove.
    """
    _require_postgres()
    _migrate_fresh(TEST_DATABASE_URL)

    import sqlalchemy as sa
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.exc import IntegrityError
    from app import models

    suffix = uuid.uuid4().hex[:8]
    eng = sa.create_engine(TEST_DATABASE_URL)
    Session = sessionmaker(bind=eng)
    try:
        with Session() as s:
            pi = models.PaymentIntent(
                intent_id=f"pi_orphan_{suffix}",
                transaction_id=f"tx_orphan_{suffix}",
                idempotency_key=f"idem_orphan_{suffix}",
                org_id="default",
                agent_id="synthetic-nonexistent-agent",
                amount_minor_units=1000,
                currency="INR",
                merchant="Test Merchant",
                action="payment",
                decision=models.GovernanceDecision.DENY,
                reasons=["test"],
            )
            s.add(pi)
            with pytest.raises(IntegrityError) as exc_info:
                s.commit()
            assert "fk_payment_intents_agent_id_agents" in str(exc_info.value), (
                f"rejected, but not by the agent FK: {exc_info.value}")

        # Positive control: the same row with a real agent must be accepted, or
        # the rejection above could be any insert failure at all.
        with Session() as s:
            parent = models.ParentAuthority(name="P", parent_type="developer",
                                            contact="p@example.com",
                                            public_key_pem="k",
                                            status=models.ParentStatus.ACTIVE)
            s.add(parent)
            s.commit()
            agent = models.Agent(name="FK Control Agent", agent_type="assistant",
                                 purpose="test", public_key_pem="k",
                                 status=models.AgentStatus.ACTIVE,
                                 parent_pk=parent.id,
                                 delegation_id=f"deleg-{suffix}",
                                 granted_capabilities=["make_payment"],
                                 payment_limit_minor_units=1000, currency="INR")
            s.add(agent)
            s.commit()
            s.add(models.PaymentIntent(
                intent_id=f"pi_ok_{suffix}",
                transaction_id=f"tx_ok_{suffix}",
                idempotency_key=f"idem_ok_{suffix}",
                org_id="default",
                agent_id=agent.agent_id,
                amount_minor_units=1000,
                currency="INR",
                merchant="Test Merchant",
                action="payment",
                decision=models.GovernanceDecision.DENY,
                reasons=["test"],
            ))
            s.commit()
    finally:
        eng.dispose()
