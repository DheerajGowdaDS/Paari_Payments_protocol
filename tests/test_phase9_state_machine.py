"""Phase 9: provider authorisation, capture and settlement are three different facts.

The Blueprint asked for AUTHORIZED -> PROVIDER_SUBMITTED -> PROVIDER_AUTHORIZED ->
CAPTURED -> PAID so that nobody could read "the agent's payment is done" as
"the provider captured" as "Paari confirms settlement". Until a live Razorpay
Test-Mode settlement delivered `payment.authorized` and `payment.captured` as two
separately-signed events, the argument against those states was that a provider
might never give two distinct observations to name. It does. So the states are
real, and these tests pin what each one is allowed to mean.

The load-bearing rule underneath all of this:

    **The webhook handler cannot mint PAID.**

A webhook is an inbound announcement - signed, authenticated, value-checked, but
still a single message saying "this happened". PAID is Paari's own terminal
judgement, and it now requires the capture to be corroborated by a direct read of
the provider's API. `payment.captured` moves the row to CAPTURED; PAID follows
when `app.reconcile.confirm_capture` agrees, either immediately in the same
request or later via the reconciliation worker.

That is a deliberate behaviour change from "verified webhook => PAID", and the
tests below are what make it safe rather than merely different: a payment that
cannot be confirmed is held in a non-terminal state the reconciler keeps working
on, never silently marked settled and never lost.
"""
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone

import pytest

from tests.conftest import make_intent

SECRET = "phase9_webhook_secret"  # noqa: S105 (test-only fiction)


def _sign(body: bytes) -> str:
    return hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()


class Phase9Provider:
    """A provider seam whose confirmation behaviour can be dialled per test.

    `announcement` is what the signed webhook says happened. `truth` is what the
    provider's API returns when Paari asks directly. They are separate on
    purpose: the whole point of CAPTURED is the window where the two disagree or
    where the second one cannot be obtained.
    """

    key_id = "rzp_key_phase9"

    def __init__(self, order_id, truth=None, confirm_raises=False):
        self.order_id = order_id
        self.truth = truth          # dict | None -> provider read result
        self.confirm_raises = confirm_raises
        self.reads = 0

    def create_payment(self, authorization_id, amount_minor_units, currency, notes):
        return {"id": self.order_id, "receipt": authorization_id,
                "amount": amount_minor_units, "currency": currency, "status": "created"}

    def verify_webhook(self, raw_body, signature):
        from app.providers.razorpay import verify_webhook_signature
        return verify_webhook_signature(raw_body, signature, SECRET)

    def get_payment(self, payment_id):
        self.reads += 1
        if self.confirm_raises:
            raise RuntimeError("provider unreachable")
        return self.truth

    def fetch_payments(self, order_id):
        self.reads += 1
        if self.confirm_raises:
            raise RuntimeError("provider unreachable")
        return [self.truth] if self.truth else []


def _consume(ctx, monkeypatch, provider, suffix):
    import app.routers.payments as payments_router

    monkeypatch.setattr(payments_router, "get_provider", lambda: provider)
    monkeypatch.setenv("RAZORPAY_WEBHOOK_SECRET", SECRET)
    body = make_intent(ctx, suffix=suffix)
    auth_id = body["authorization"]["authorization_id"]
    r = ctx.client.post(f"/payments/authorizations/{auth_id}/consume",
                        json={"session_token": ctx.session_token})
    assert r.status_code == 200, r.text
    return body["transaction_id"], auth_id


def _deliver(ctx, event_type, order_id, payment_id, amount=120000, currency="INR",
             event_id=None):
    raw = json.dumps({
        "id": event_id or f"evt_{uuid.uuid4().hex[:8]}",
        "event": event_type,
        "payload": {"payment": {"entity": {
            "id": payment_id, "order_id": order_id,
            "amount": amount, "currency": currency}}},
    }).encode()
    r = ctx.client.post("/payments/webhooks/razorpay", content=raw,
                        headers={"X-Razorpay-Signature": _sign(raw),
                                 "Content-Type": "application/json"})
    return r, raw


def _state(ctx, order_id):
    import app.models as models

    db = ctx.Session()
    try:
        txn = db.query(models.ProviderTransaction).filter_by(
            razorpay_order_id=order_id).first()
        return (txn.state if txn else None), txn
    finally:
        db.close()


def _kinds(ctx, tx):
    import app.models as models

    db = ctx.Session()
    try:
        return [e.kind for e in db.query(models.AuditEvent)
                .filter_by(transaction_id=tx).order_by(models.AuditEvent.id).all()]
    finally:
        db.close()


# --------------------------------------------------------------------------
# The three facts are three states
# --------------------------------------------------------------------------

def test_payment_authorized_yields_provider_authorized_not_paid(paari_client, monkeypatch):
    """An authorisation is not money moved."""
    ctx = paari_client
    provider = Phase9Provider("order_p9_auth")
    tx, _auth = _consume(ctx, monkeypatch, provider, "p9-auth")

    r, _ = _deliver(ctx, "payment.authorized", "order_p9_auth", "pay_p9_auth")
    assert r.status_code == 200, r.text
    state, _ = _state(ctx, "order_p9_auth")
    assert state == "PROVIDER_AUTHORIZED", state


def test_captured_without_confirmation_stops_at_captured(paari_client, monkeypatch):
    """The state that PAID used to claim on one message.

    This is the heart of Phase 9: a correctly-signed `payment.captured` is not
    enough. With no corroborating read available the row waits in a non-terminal
    state instead of being called settled.
    """
    ctx = paari_client
    provider = Phase9Provider("order_p9_uncertain", truth=None)
    tx, _auth = _consume(ctx, monkeypatch, provider, "p9-uncertain")

    r, _ = _deliver(ctx, "payment.captured", "order_p9_uncertain", "pay_p9_uncertain")
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "CAPTURED", r.json()
    state, _ = _state(ctx, "order_p9_uncertain")
    assert state == "CAPTURED", state


def test_unreachable_provider_holds_at_captured_rather_than_guessing(
        paari_client, monkeypatch):
    """A transport failure must not be resolved in the flattering direction.

    Marking PAID because the confirmation call threw would turn an outage into
    false settlement records. Staying CAPTURED costs a reconciliation cycle.
    """
    ctx = paari_client
    provider = Phase9Provider("order_p9_down", truth={"id": "pay_x"},
                              confirm_raises=True)
    tx, _auth = _consume(ctx, monkeypatch, provider, "p9-down")

    r, _ = _deliver(ctx, "payment.captured", "order_p9_down", "pay_p9_down")
    assert r.status_code == 200, r.text
    state, txn = _state(ctx, "order_p9_down")
    assert state == "CAPTURED", state
    assert "unreachable" in (txn.last_error or ""), txn.last_error


def test_captured_plus_corroborating_read_reaches_paid(paari_client, monkeypatch):
    """Positive control for the three tests above.

    Without it, every 'stops at CAPTURED' assertion could be satisfied by a
    confirmation path that is simply broken.
    """
    ctx = paari_client
    provider = Phase9Provider("order_p9_ok", truth={
        "id": "pay_p9_ok", "status": "captured", "amount": 120000, "currency": "INR"})
    tx, _auth = _consume(ctx, monkeypatch, provider, "p9-ok")

    r, _ = _deliver(ctx, "payment.captured", "order_p9_ok", "pay_p9_ok")
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "PAID", r.json()
    state, txn = _state(ctx, "order_p9_ok")
    assert state == "PAID"
    assert txn.razorpay_payment_id == "pay_p9_ok"
    kinds = _kinds(ctx, tx)
    assert "webhook_applied" in kinds and "settlement_confirmed" in kinds, kinds


def test_full_observed_sequence_walks_the_whole_chain(paari_client, monkeypatch):
    """The exact two-event sequence Razorpay delivered live, replayed in order."""
    ctx = paari_client
    provider = Phase9Provider("order_p9_seq", truth={
        "id": "pay_p9_seq", "status": "captured", "amount": 120000, "currency": "INR"})
    tx, _auth = _consume(ctx, monkeypatch, provider, "p9-seq")

    _deliver(ctx, "payment.authorized", "order_p9_seq", "pay_p9_seq")
    assert _state(ctx, "order_p9_seq")[0] == "PROVIDER_AUTHORIZED"
    _deliver(ctx, "payment.captured", "order_p9_seq", "pay_p9_seq")
    assert _state(ctx, "order_p9_seq")[0] == "PAID"
    # AUTHORIZED is never observed on a row that has an order: the chain is
    # PROVIDER_SUBMITTED -> PROVIDER_AUTHORIZED -> CAPTURED -> PAID.
    assert provider.reads >= 1, "no corroborating read was ever attempted"


def test_out_of_order_captured_before_authorized_still_settles(paari_client, monkeypatch):
    """PROVIDER_SUBMITTED -> CAPTURED must be legal.

    Providers that do not emit an authorisation event at all are common, and a
    state machine that demanded the intermediate step would reject real money.
    """
    ctx = paari_client
    provider = Phase9Provider("order_p9_ooo", truth={
        "id": "pay_p9_ooo", "status": "captured", "amount": 120000, "currency": "INR"})
    tx, _auth = _consume(ctx, monkeypatch, provider, "p9-ooo")

    r, _ = _deliver(ctx, "payment.captured", "order_p9_ooo", "pay_p9_ooo")
    assert r.status_code == 200, r.text
    assert _state(ctx, "order_p9_ooo")[0] == "PAID"


# --------------------------------------------------------------------------
# Corroboration must still check the value
# --------------------------------------------------------------------------

def test_confirmation_with_wrong_amount_does_not_settle(paari_client, monkeypatch):
    """The webhook said captured; the provider's own record says a different
    amount. The announcement loses."""
    ctx = paari_client
    provider = Phase9Provider("order_p9_val", truth={
        "id": "pay_p9_val", "status": "captured", "amount": 1, "currency": "INR"})
    tx, _auth = _consume(ctx, monkeypatch, provider, "p9-val")

    _deliver(ctx, "payment.captured", "order_p9_val", "pay_p9_val")
    state, txn = _state(ctx, "order_p9_val")
    assert state == "CAPTURED", state
    assert "amount mismatch" in (txn.last_error or ""), txn.last_error


def test_provider_denying_the_capture_moves_to_indeterminate_not_paid(
        paari_client, monkeypatch):
    """A capture later contradicted is neither settled nor cleanly failed."""
    ctx = paari_client
    provider = Phase9Provider("order_p9_deny", truth={
        "id": "pay_p9_deny", "status": "failed", "amount": 120000, "currency": "INR",
        "error_code": "bank_declined"})
    tx, _auth = _consume(ctx, monkeypatch, provider, "p9-deny")

    _deliver(ctx, "payment.captured", "order_p9_deny", "pay_p9_deny")
    state, _ = _state(ctx, "order_p9_deny")
    assert state == "PROVIDER_UNKNOWN", state
    assert "settlement_not_confirmed" in _kinds(ctx, tx)


# --------------------------------------------------------------------------
# Reconciliation is the other road to PAID
# --------------------------------------------------------------------------

def test_reconciler_promotes_a_waiting_captured_row(paari_client, monkeypatch):
    """Nothing is stranded in CAPTURED.

    Holding a payment short of PAID is only honest if something keeps trying to
    confirm it. This is the promise the previous test makes: CAPTURED is
    non-terminal, so the reconciler visits it and promotes it once the provider
    read agrees.
    """
    import app.reconcile as reconcile_mod

    ctx = paari_client
    provider = Phase9Provider("order_p9_recon", truth=None, confirm_raises=True)
    tx, auth_id = _consume(ctx, monkeypatch, provider, "p9-recon")
    _deliver(ctx, "payment.captured", "order_p9_recon", "pay_p9_recon")
    assert _state(ctx, "order_p9_recon")[0] == "CAPTURED"

    # Provider comes back and confirms.
    provider.confirm_raises = False
    provider.truth = {"id": "pay_p9_recon", "status": "captured",
                      "amount": 120000, "currency": "INR"}
    monkeypatch.setattr(reconcile_mod, "get_provider", lambda: provider)
    db = ctx.Session()
    try:
        result = reconcile_mod.reconcile_one(db, auth_id)
    finally:
        db.close()
    assert result["state"] == "PAID", result
    assert _state(ctx, "order_p9_recon")[0] == "PAID"


def test_captured_is_not_terminal_so_the_worker_keeps_visiting_it():
    """The one-line reason CAPTURED must not join TERMINAL_STATES.

    If it did, the reconciler's `state.notin_(TERMINAL_STATES)` filter would skip
    every waiting row and each one would be frozen just short of settled.
    """
    from app.transitions import TERMINAL_STATES, TRANSITION_TABLE

    assert "CAPTURED" not in TERMINAL_STATES
    assert TRANSITION_TABLE["CAPTURED"], "CAPTURED has no exit: rows would be stranded"


def test_declined_is_terminal_and_stops_being_rescanned():
    """A dead-end state missing from TERMINAL_STATES is an infinite work queue.

    DECLINED was given no outgoing edges but was never added to the terminal set,
    so the reconciler filter kept selecting every declined payment forever.
    """
    from app.transitions import TERMINAL_STATES, TRANSITION_TABLE

    assert TRANSITION_TABLE["DECLINED"] == ()
    assert "DECLINED" in TERMINAL_STATES


# --------------------------------------------------------------------------
# The structural rule
# --------------------------------------------------------------------------

def test_webhook_mapping_contains_no_terminal_state():
    """Guards the rule that a webhook cannot mint PAID.

    Behavioural tests can be satisfied by an accident of fixtures. This one reads
    the handler's own event->state mapping, so adding "PAID" back to it - which is
    exactly the regression that would let a single inbound message record a
    terminal settlement - fails here first and says why.
    """
    import pathlib
    import re

    source = (pathlib.Path(__file__).resolve().parents[1]
              / "app" / "routers" / "payments.py").read_text(encoding="utf-8")
    match = re.search(r'target = \{\s*(?:"payment\.authorized".*?)"payment\.failed"[^}]*\}',
                      source, re.S)
    assert match, "could not find the webhook event->state mapping; it was renamed"
    mapping = match.group(0)
    assert '"PAID"' not in mapping, (
        "the webhook handler can again mint PAID directly; settlement would rest "
        "on one inbound message instead of two independent provider signals")
    assert '"CAPTURED"' in mapping and '"PROVIDER_AUTHORIZED"' in mapping


def test_legacy_payment_pending_rows_still_have_a_legal_exit():
    """Backward compatibility for rows written before the vocabulary change."""
    from app.transitions import TRANSITION_TABLE, transition_txn

    class _Row:
        def __init__(self):
            self.state = "PAYMENT_PENDING"
            self.last_error = None

    assert "CAPTURED" in TRANSITION_TABLE["PAYMENT_PENDING"]
    row = _Row()
    transition_txn(row, "CAPTURED")
    assert row.state == "CAPTURED"


def test_migration_rewrites_pending_rows(tmp_path, monkeypatch):
    """The data migration is idempotent and leaves settled rows alone."""
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    import pathlib

    monkeypatch.delenv("ALEMBIC_URL", raising=False)
    db_path = tmp_path / "p9.db"
    url = f"sqlite:///{db_path.as_posix()}"
    cfg = Config(str(pathlib.Path("alembic.ini")))
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")

    eng = sa.create_engine(url)
    with eng.begin() as c:
        c.execute(sa.text(
            "INSERT INTO provider_transactions (authorization_id, intent_id, agent_id, "
            "org_id, state, created_at, updated_at, attempts, provider_environment) "
            "VALUES ('a1','i1','ag1','default','PAYMENT_PENDING','2026-09-28 00:00:00',"
            "'2026-09-28 00:00:00',0,'test')"))
        c.execute(sa.text(
            "INSERT INTO provider_transactions (authorization_id, intent_id, agent_id, "
            "org_id, state, created_at, updated_at, attempts, provider_environment) "
            "VALUES ('a2','i2','ag1','default','PAID','2026-09-28 00:00:00',"
            "'2026-09-28 00:00:00',0,'test')"))

    command.stamp(cfg, "b2c3d4e5f6a7")
    command.upgrade(cfg, "head")

    with eng.connect() as c:
        states = {r[0]: r[1] for r in c.execute(sa.text(
            "SELECT authorization_id, state FROM provider_transactions")).fetchall()}
    assert states["a1"] == "PROVIDER_AUTHORIZED", states
    assert states["a2"] == "PAID", "the migration touched a settled row"

    # Head is still the single linear tip and drift is still clean after it.
    script = ScriptDirectory.from_config(cfg)
    assert script.get_heads() == ["c3d4e5f6a7b8"]
