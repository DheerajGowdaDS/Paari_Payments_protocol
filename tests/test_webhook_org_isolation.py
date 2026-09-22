"""Task E1: webhook org-account verification."""
import hashlib
import hmac
import json
import os

from app import models as m
from app.provider_accounts import get_provider_for_org
from app.protocol.errors import PaariErrorCode
import app.routers.payments as payments_router

from tests.conftest import make_intent


def _make_provider_for_org_test(db, org_id, key_id, key_secret, webhook_secret):
    import app.providers.razorpay as razorpay
    # Ensure env vars exist for the tag-based lookup.
    tag = "".join(ch for ch in org_id if ch.isalnum()).upper()
    os.environ[f"RAZORPAY_KEY_ID__{tag}"] = key_id
    os.environ[f"RAZORPAY_KEY_SECRET__{tag}"] = key_secret
    os.environ[f"RAZORPAY_WEBHOOK_SECRET__{tag}"] = webhook_secret
    acct = m.ProviderAccount(org_id=org_id, key_id_label=f"{org_id}-keys", is_default=False)
    db.add(acct)
    db.commit()
    db.refresh(acct)
    return get_provider_for_org(db, org_id), key_id, acct.id


def test_webhook_rejects_invalid_signature(paari_client, monkeypatch):
    from app.providers.base import get_provider as _real_get_provider
    monkeypatch.setattr(payments_router, "get_provider", _real_get_provider)
    monkeypatch.setenv("RAZORPAY_WEBHOOK_SECRET", "test_secret")
    body = b'{"event":"payment.captured","payload":{"payment":{"entity":{"id":"pay_123","order_id":"order_123","amount":1000,"currency":"INR","status":"captured"}}},"id":"evt_123"}'
    r = paari_client.client.post(
        "/v1/payments/webhooks/razorpay",
        content=body,
        headers={"X-Razorpay-Signature": "invalid_sig"},
    )
    assert r.status_code == 401


def test_webhook_cross_org_replay_rejected(paari_client, monkeypatch):
    """Cross-org webhook replay must be rejected even with a valid signature."""
    ctx = paari_client

    # Default-org credentials
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_key_default")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "secret_default")
    monkeypatch.setenv("RAZORPAY_WEBHOOK_SECRET", "default_webhook_secret")

    # Create org-b with its own provider account and Razorpay credentials
    db = ctx.Session()
    try:
        org_b_id = "org-b"
        db.add(m.Organization(org_id=org_b_id, name="Org B"))
        provider_b, org_b_key_id, _ = _make_provider_for_org_test(
            db, org_b_id, "rzp_key_org_b", "secret_org_b", "webhook_secret_org_b"
        )
        assert provider_b.key_id == org_b_key_id
    finally:
        db.close()

    # Create a payment in default org and consume it to obtain an order_id
    class FakeProvider:
        key_id = "rzp_key_default"

        def create_payment(self, authorization_id, amount_minor_units, currency, notes):
            return {
                "id": "order_default_1",
                "receipt": authorization_id,
                "amount": amount_minor_units,
                "currency": currency,
                "status": "created",
            }

        def verify_webhook(self, raw_body, signature):
            from app.providers.razorpay import verify_webhook_signature
            return verify_webhook_signature(
                raw_body, signature, os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")
            )

    monkeypatch.setattr(payments_router, "get_provider", lambda: FakeProvider())

    body = make_intent(ctx, suffix="cross-org")
    auth_id = body["authorization"]["authorization_id"]
    r = ctx.client.post(
        f"/payments/authorizations/{auth_id}/consume",
        json={"session_token": ctx.session_token},
    )
    assert r.status_code == 200, r.text

    # Cross-org replay: signature valid for default org, but account_id belongs to org-b
    raw = json.dumps({
        "id": "evt_cross_org_1",
        "event": "payment.captured",
        "account_id": org_b_key_id,
        "payload": {"payment": {"entity": {
            "id": "pay_cross_org_1",
            "order_id": "order_default_1",
            "amount": 120000,
            "currency": "INR",
            "status": "captured",
        }}},
    }).encode()
    sig = hmac.new(b"default_webhook_secret", raw, hashlib.sha256).hexdigest()
    r = ctx.client.post(
        "/v1/payments/webhooks/razorpay",
        content=raw,
        headers={"X-Razorpay-Signature": sig, "Content-Type": "application/json"},
    )
    assert r.status_code == 403, r.text
    assert r.json().get("code") == PaariErrorCode.WEBHOOK_ORG_MISMATCH.value

    # State must not change
    db = ctx.Session()
    try:
        txn = db.query(m.ProviderTransaction).filter_by(razorpay_order_id="order_default_1").first()
        assert txn is not None
        assert txn.state == "PROVIDER_SUBMITTED"

        audit = db.query(m.AuditEvent).filter_by(
            transaction_id="TXN-cross-org",
            kind="webhook_rejected_org_mismatch",
        ).first()
        assert audit is not None
        detail = audit.detail
        assert detail["from_state"] == "PROVIDER_SUBMITTED"
        assert detail["to_state"] == "PROVIDER_SUBMITTED"
        assert detail["expected_key_id"] == "rzp_key_default"
        assert detail["actual_account_id"] == org_b_key_id
    finally:
        db.close()


def test_webhook_same_org_still_applies(paari_client, monkeypatch):
    """Same-org webhook with matching account identifier still applies."""
    ctx = paari_client

    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_key_default")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "secret_default")
    monkeypatch.setenv("RAZORPAY_WEBHOOK_SECRET", "default_webhook_secret")

    class FakeProvider:
        key_id = "rzp_key_default"

        def create_payment(self, authorization_id, amount_minor_units, currency, notes):
            return {
                "id": "order_default_2",
                "receipt": authorization_id,
                "amount": amount_minor_units,
                "currency": currency,
                "status": "created",
            }

        def verify_webhook(self, raw_body, signature):
            from app.providers.razorpay import verify_webhook_signature
            return verify_webhook_signature(
                raw_body, signature, os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")
            )

    monkeypatch.setattr(payments_router, "get_provider", lambda: FakeProvider())

    body = make_intent(ctx, suffix="same-org")
    auth_id = body["authorization"]["authorization_id"]
    r = ctx.client.post(
        f"/payments/authorizations/{auth_id}/consume",
        json={"session_token": ctx.session_token},
    )
    assert r.status_code == 200, r.text

    raw = json.dumps({
        "id": "evt_same_org_1",
        "event": "payment.captured",
        "account_id": "rzp_key_default",
        "payload": {"payment": {"entity": {
            "id": "pay_same_org_1",
            "order_id": "order_default_2",
            "amount": 120000,
            "currency": "INR",
            "status": "captured",
        }}},
    }).encode()
    sig = hmac.new(b"default_webhook_secret", raw, hashlib.sha256).hexdigest()
    r = ctx.client.post(
        "/v1/payments/webhooks/razorpay",
        content=raw,
        headers={"X-Razorpay-Signature": sig, "Content-Type": "application/json"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "PAID"
