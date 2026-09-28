"""Task D1: reconciliation worker with retry and dead-letter."""
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from tests.conftest import _migrate_fresh
from app.reconcile_worker import ReconciliationWorker, ReconciliationAlertSink
from app import models


def test_worker_dead_letters_after_max_attempts(paari_client):
    ctx = paari_client
    session = ctx.Session()
    # The bounded_authorization must have a real intent behind it: the Phase 6
    # multi-tenancy migration adds a real FK (intent_id -> payment_intents) on
    # Postgres, and SQLite only passes this test because FK enforcement is OFF
    # by default there. Creating the intent makes the fixture valid on both.
    intent = models.PaymentIntent(
        intent_id="reconcile-worker-intent",
        agent_id=ctx.agent_id,
        org_id="default",
        transaction_id="TXN-reconcile-worker",
        idempotency_key="idem-reconcile-worker",
        merchant="TestMerchant",
        amount_minor_units=1000,
        currency="INR",
        action="make_payment",
        decision=models.GovernanceDecision.ALLOW,
        reasons=["test fixture"],
    )
    session.add(intent)
    session.flush()
    auth = models.BoundedAuthorization(
        authorization_id="reconcile-worker-auth",
        intent_id="reconcile-worker-intent",
        agent_id=ctx.agent_id,
        org_id="default",
        transaction_id="TXN-reconcile-worker",
        merchant="TestMerchant",
        amount_minor_units=1000,
        currency="INR",
        token="token",
        expires_at=datetime.now(timezone.utc),
    )
    session.add(auth)
    txn = models.ProviderTransaction(
        authorization_id="reconcile-worker-auth",
        intent_id="reconcile-worker-intent",
        agent_id=ctx.agent_id,
        org_id="default",
        state="PROVIDER_UNKNOWN",
        attempts=0,
    )
    session.add(txn)
    session.commit()

    worker = ReconciliationWorker(interval_seconds=1, dead_letter_after=2)

    class FakeReconcile:
        def reconcile(self, authorization_id):
            return {"found": False, "order": None}

    import app.reconcile as reconcile_mod
    original = reconcile_mod.reconcile_one
    reconcile_mod.reconcile_one = lambda db, aid: {"status": "unreconciled", "state": "PROVIDER_UNKNOWN"}

    try:
        worker._run_batch(session)
        session.refresh(txn)
        assert txn.attempts == 1
        worker._run_batch(session)
        session.refresh(txn)
        assert txn.attempts >= 2
        assert txn.state == "PROVIDER_UNKNOWN"
        assert "dead-letter" in (txn.last_error or "")
    finally:
        reconcile_mod.reconcile_one = original
        session.close()


def test_worker_starts_without_an_explicit_url(tmp_path, monkeypatch):
    """The production path calls `start()` with no argument.

    That is precisely how the shipped worker died: app.main does
    `ReconciliationWorker(...).start()`, the old `start()` mapped a missing
    `db_url` to `engine=None`, no session factory was built, and every batch
    raised AttributeError while the log cheerfully reported the worker as
    started. Existing tests injected a session or passed a URL, so the only
    code path production takes was the one nobody exercised.
    """
    from app.reconcile_worker import ReconciliationWorker

    url = f"sqlite:///{(tmp_path / 'worker_default.db').as_posix()}"
    _migrate_fresh(url)
    monkeypatch.setattr("app.reconcile_worker.get_engine", lambda u=None: __import__(
        "sqlalchemy").create_engine(u or url))

    worker = ReconciliationWorker(interval_seconds=1)
    monkeypatch.setattr("app.database.DATABASE_URL", url)
    calls = []
    monkeypatch.setattr(worker, "_run_batch", lambda session: calls.append(session))
    worker.start()
    try:
        import time
        for _ in range(30):
            if calls:
                break
            time.sleep(0.1)
    finally:
        worker.stop()

    assert calls, "worker started via the production path but never ran a batch"
    assert calls[0] is not None, "worker ran a batch with a None session"
