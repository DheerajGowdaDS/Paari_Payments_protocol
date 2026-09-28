"""The webhook value guard must be proven, not merely present.

`app/routers/payments.py` refuses to let a validly signed provider event settle a
different amount or currency than the bounded authorization Paari actually
issued. That guard is the difference between "the provider authenticated the
sender" and "the provider authenticated what it is paying for", and until these
tests existed it had never been executed: `docs/CONFORMANCE.md` lists
"webhook signature/value mismatch rejection" as a REQUIRED interoperability test
while no test in the repository produced a value mismatch. A guard that no test
touches is a guard a refactor can delete for free.

Signed-but-wrong-value events are the interesting case precisely because the
signature is VALID. Every other failure mode in this area (bad signature, unknown
order, replay) is already covered; those reject at the door. These reach the
handler authenticated, which is where a mistake costs money.

`rejected_value_mismatch` returns HTTP 200 by design: a non-2xx answer tells the
provider the delivery failed and earns a retry storm, while the audit row records
the refusal. The tests assert that shape so the choice stays deliberate.
"""
import hashlib
import hmac
import json

import pytest

from tests.conftest import make_intent

WEBHOOK_SECRET = "test_value_guard_secret"  # noqa: S105 (test-only fiction)


def _signed(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _consume_order(ctx, monkeypatch, suffix):
    """Drive a real intent -> consume so the authorization bounds exist."""
    import app.routers.payments as payments_router

    class FakeProvider:
        def create_payment(self, authorization_id, amount_minor_units, currency, notes):
            return {"id": "order_value_guard", "status": "created",
                    "receipt": authorization_id, "amount": amount_minor_units,
                    "currency": currency}

        def get_payment(self, payment_id):
            """Corroboration for Phase 9: PAID now needs a direct provider read as
            well as the signed webhook, so the seam must answer when asked."""
            return {"id": payment_id, "status": "captured",
                    "amount": getattr(self, "_amount", 120000),
                    "currency": getattr(self, "_currency", "INR")}

        def fetch_payments(self, order_id):
            return [self.get_payment("pay_sim_1")]

        def verify_webhook(self, raw_body, signature):
            import os
            from app.providers.razorpay import verify_webhook_signature
            return verify_webhook_signature(
                raw_body, signature, os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")
            )

    monkeypatch.setattr(payments_router, "get_provider", lambda: FakeProvider())
    monkeypatch.setenv("RAZORPAY_WEBHOOK_SECRET", WEBHOOK_SECRET)
    body = make_intent(ctx, suffix=suffix)
    auth_id = body["authorization"]["authorization_id"]
    r = ctx.client.post(f"/payments/authorizations/{auth_id}/consume",
                        json={"session_token": ctx.session_token})
    assert r.status_code == 200, r.text
    return auth_id


def _event(order_id, payment_id, event_id, amount, currency):
    return {
        "id": event_id,
        "event": "payment.captured",
        "payload": {"payment": {"entity": {
            "id": payment_id, "order_id": order_id,
            "amount": amount, "currency": currency,
        }}},
    }


def _deliver(ctx, event):
    raw = json.dumps(event).encode()
    return ctx.client.post(
        "/payments/webhooks/razorpay", content=raw,
        headers={"X-Razorpay-Signature": _signed(WEBHOOK_SECRET, raw),
                 "Content-Type": "application/json"},
    )


def _txn(ctx):
    import app.models as models

    db = ctx.Session()
    try:
        return db.query(models.ProviderTransaction).filter_by(
            razorpay_order_id="order_value_guard").first()
    finally:
        db.close()


def _audit_kinds(ctx, kind):
    import app.models as models

    db = ctx.Session()
    try:
        return db.query(models.AuditEvent).filter_by(kind=kind).all()
    finally:
        db.close()


def test_control_matching_value_does_settle(paari_client, monkeypatch):
    """Positive control. Without it every assertion below could be satisfied by
    a guard that rejects all webhooks, which would look like safety and prove
    nothing."""
    ctx = paari_client
    _consume_order(ctx, monkeypatch, "vg-ok")
    r = _deliver(ctx, _event("order_value_guard", "pay_ok", "evt_ok", 120000, "INR"))
    assert r.status_code == 200, r.text
    assert _txn(ctx).state == "PAID"
    assert _txn(ctx).razorpay_payment_id == "pay_ok"


def test_signed_event_with_wrong_amount_is_refused_and_does_not_settle(paari_client, monkeypatch):
    ctx = paari_client
    _consume_order(ctx, monkeypatch, "vg-amount")
    before = _txn(ctx).state
    # One rupee less than authorized, with a perfectly valid signature.
    r = _deliver(ctx, _event("order_value_guard", "pay_wrong_amt", "evt_wrong_amt",
                             119999, "INR"))
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "rejected_value_mismatch", r.json()
    assert _txn(ctx).state == before, "a refused event must not move money state"
    assert _txn(ctx).webhook_event_id is None, "a refused event must not be recorded as applied"
    assert _audit_kinds(ctx, "webhook_rejected_value_mismatch"), (
        "the refusal must be durably auditable, not just an HTTP response")


def test_signed_event_with_wrong_currency_is_refused(paari_client, monkeypatch):
    ctx = paari_client
    _consume_order(ctx, monkeypatch, "vg-currency")
    before = _txn(ctx).state
    # Right number, wrong currency: 120000 USD is not 120000 INR.
    r = _deliver(ctx, _event("order_value_guard", "pay_wrong_ccy", "evt_wrong_ccy",
                             120000, "USD"))
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "rejected_value_mismatch", r.json()
    assert _txn(ctx).state == before


def test_signed_event_with_missing_value_fields_is_refused(paari_client, monkeypatch):
    """A provider event that omits the amount is not evidence of an amount.

    Treating absent as matching would let a stripped payload settle a payment,
    so the guard requires both fields to be present before it can compare.
    """
    ctx = paari_client
    _consume_order(ctx, monkeypatch, "vg-absent")
    before = _txn(ctx).state
    r = _deliver(ctx, _event("order_value_guard", "pay_no_amt", "evt_no_amt", None, None))
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "rejected_value_mismatch", r.json()
    assert _txn(ctx).state == before


def test_refused_value_mismatch_is_not_consume_replay_idempotency(paari_client, monkeypatch):
    """A rejected event must not burn the event id as applied, or a later
    corrected event for the same provider payment would be swallowed as a
    duplicate and the payment would never settle."""
    ctx = paari_client
    _consume_order(ctx, monkeypatch, "vg-retry")
    wrong = _event("order_value_guard", "pay_retry", "evt_retry", 1, "INR")
    assert _deliver(ctx, wrong).json()["status"] == "rejected_value_mismatch"
    right = _event("order_value_guard", "pay_retry", "evt_retry", 120000, "INR")
    r = _deliver(ctx, right)
    assert r.status_code == 200, r.text
    assert _txn(ctx).state == "PAID", (
        f"corrected event after a value rejection was swallowed: {r.json()}")
