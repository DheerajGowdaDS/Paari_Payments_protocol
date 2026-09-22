"""Task D1: reconciliation worker with retry and dead-letter."""
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from app.reconcile_worker import ReconciliationWorker, ReconciliationAlertSink
from app import models


def test_worker_dead_letters_after_max_attempts(paari_client):
    ctx = paari_client
    session = ctx.Session()
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
