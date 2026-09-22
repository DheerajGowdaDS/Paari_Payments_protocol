"""Phase 5 webhook: verified Razorpay events drive ProviderTransaction state.

RED expectations (pre-fix): POST /payments/webhooks/razorpay -> 404.
"""
import hashlib
import hmac
import json

from tests.conftest import make_intent

WEBHOOK_SECRET = "test_webhook_secret"  # noqa: S105 (test-only fiction)


def _signed(secret, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _consume_with_order(ctx, monkeypatch, suffix):
    import app.routers.payments as payments_router

    class FakeProvider:
        def create_payment(self, authorization_id, amount_minor_units, currency, notes):
            return {"id": "order_test_wh", "status": "created", "receipt": authorization_id, "amount": amount_minor_units, "currency": currency}

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
    r = ctx.client.post(
        f"/payments/authorizations/{auth_id}/consume",
        json={"session_token": ctx.session_token},
    )
    assert r.status_code == 200, r.text
    return auth_id


def _capture_event(order_id, payment_id, event_id):
    return {
        "id": event_id,
        "event": "payment.captured",
        "payload": {
            "payment": {
                "entity": {
                    "id": payment_id,
                    "order_id": order_id,
                    "amount": 120000,
                    "currency": "INR",
                }
            }
        },
    }


def _txn_state(ctx):
    import app.models as models

    db = ctx.Session()
    txn = db.query(models.ProviderTransaction).filter_by(
        razorpay_order_id="order_test_wh"
    ).first()
    db.close()
    return txn


def test_webhook_bad_signature_rejected_no_state_change(paari_client, monkeypatch):
    ctx = paari_client
    _consume_with_order(ctx, monkeypatch, "wh-badsig")
    raw = json.dumps(_capture_event("order_test_wh", "pay_1", "evt_bad")).encode()
    r = ctx.client.post(
        "/payments/webhooks/razorpay",
        content=raw,
        headers={"X-Razorpay-Signature": "wrong", "Content-Type": "application/json"},
    )
    assert r.status_code == 401, r.text
    assert _txn_state(ctx).state == "PROVIDER_SUBMITTED"


def test_webhook_payment_captured_marks_paid(paari_client, monkeypatch):
    ctx = paari_client
    _consume_with_order(ctx, monkeypatch, "wh-paid")
    raw = json.dumps(_capture_event("order_test_wh", "pay_1", "evt_1")).encode()
    r = ctx.client.post(
        "/payments/webhooks/razorpay",
        content=raw,
        headers={
            "X-Razorpay-Signature": _signed(WEBHOOK_SECRET, raw),
            "Content-Type": "application/json",
        },
    )
    assert r.status_code == 200, r.text
    txn = _txn_state(ctx)
    assert txn.state == "PAID"
    assert txn.razorpay_payment_id == "pay_1"
    assert txn.webhook_event_id == "evt_1"


def test_webhook_replay_same_event_is_idempotent(paari_client, monkeypatch):
    ctx = paari_client
    _consume_with_order(ctx, monkeypatch, "wh-replay")
    raw = json.dumps(_capture_event("order_test_wh", "pay_1", "evt_dup")).encode()
    headers = {
        "X-Razorpay-Signature": _signed(WEBHOOK_SECRET, raw),
        "Content-Type": "application/json",
    }
    assert ctx.client.post("/payments/webhooks/razorpay", content=raw, headers=headers).status_code == 200
    second = ctx.client.post("/payments/webhooks/razorpay", content=raw, headers=headers)
    assert second.status_code == 200, second.text
    assert second.json()["status"] == "duplicate_ignored"
    assert _txn_state(ctx).state == "PAID"


def test_webhook_unknown_order_acknowledged_without_state(paari_client, monkeypatch):
    ctx = paari_client
    _consume_with_order(ctx, monkeypatch, "wh-unknown")
    monkeypatch.setenv("RAZORPAY_WEBHOOK_SECRET", WEBHOOK_SECRET)
    raw = json.dumps(_capture_event("order_nonexistent", "pay_x", "evt_x")).encode()
    r = ctx.client.post(
        "/payments/webhooks/razorpay",
        content=raw,
        headers={
            "X-Razorpay-Signature": _signed(WEBHOOK_SECRET, raw),
            "Content-Type": "application/json",
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "ignored"
    assert _txn_state(ctx).state == "PROVIDER_SUBMITTED"
