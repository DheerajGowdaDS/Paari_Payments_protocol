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

        def get_payment(self, payment_id):
            """Corroboration for Phase 9: PAID now needs a direct provider read as
            well as the signed webhook, so the seam must answer when asked."""
            return {"id": payment_id, "status": "captured",
                    "amount": getattr(self, "_amount", 120000),
                    "currency": getattr(self, "_currency", "INR")}

        def fetch_payments(self, order_id):
            return [self.get_payment("pay_sim_1")]

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

        def get_payment(self, payment_id):
            """Corroboration for Phase 9: PAID needs a direct provider read
            as well as the signed webhook."""
            return {"id": payment_id, "status": "captured",
                    "amount": getattr(self, "_amount", 120000),
                    "currency": getattr(self, "_currency", "INR")}

        def fetch_payments(self, order_id):
            return [self.get_payment("pay_sim_1")]

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


def _txn_state(ctx, order_id):
    """Current state of one provider transaction, read straight from the row."""
    import app.models as mod

    db = ctx.Session()
    try:
        txn = db.query(mod.ProviderTransaction).filter_by(razorpay_order_id=order_id).first()
        return txn.state if txn else None
    finally:
        db.close()


def _sign(secret, body):
    import hashlib
    import hmac
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_per_org_webhook_secrets_are_not_interchangeable(paari_client, monkeypatch):
    """The tenant boundary that actually holds in production is the secret.

    `test_webhook_cross_org_replay_rejected` proves the `account_id` guard using
    a top-level `rzp_*` value - but real Razorpay events nest an `acc_*` account
    id, which is not comparable to an API key id, as the handler's own comment
    says. So that guard does not fire on real traffic, and the defense that does
    was never tested: Paari verifies an inbound delivery with the webhook secret
    belonging to the organisation that owns the order. A delivery signed with
    another tenant's secret must therefore be refused even though it is
    perfectly well formed and correctly signed - for the wrong tenant.
    """
    import app.models as mod
    from app.provider_accounts import get_provider_for_org

    monkeypatch.setenv("RAZORPAY_WEBHOOK_SECRET__ORGA", "secret_org_a")
    monkeypatch.setenv("RAZORPAY_KEY_ID__ORGA", "rzp_key_org_a")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET__ORGA", "sk_org_a")
    monkeypatch.setenv("RAZORPAY_WEBHOOK_SECRET__ORGB", "secret_org_b")
    monkeypatch.setenv("RAZORPAY_KEY_ID__ORGB", "rzp_key_org_b")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET__ORGB", "sk_org_b")

    db = paari_client.Session()
    try:
        for oid in ("org-a", "org-b"):
            if not db.query(mod.ProviderAccount).filter_by(org_id=oid).first():
                db.add(mod.ProviderAccount(org_id=oid, key_id_label=f"{oid}-keys",
                                           is_default=False))
        db.commit()
        provider_a = get_provider_for_org(db, "org-a")
        provider_b = get_provider_for_org(db, "org-b")
    finally:
        db.close()

    body = b'{"id":"evt_iso","event":"payment.captured"}'

    # Control: each tenant's own secret verifies its own deliveries.
    assert provider_a.verify_webhook(body, _sign("secret_org_a", body)) is True
    assert provider_b.verify_webhook(body, _sign("secret_org_b", body)) is True
    # The isolation claim: a foreign tenant's correctly-signed delivery does not.
    assert provider_a.verify_webhook(body, _sign("secret_org_b", body)) is False
    assert provider_b.verify_webhook(body, _sign("secret_org_a", body)) is False
    # And the two adapters really are different objects, or the above is vacuous.
    assert provider_a.key_id != provider_b.key_id


def test_webhook_with_real_event_shape_still_requires_the_right_secret(
        paari_client, monkeypatch):
    """Handler-level proof using the payload shape Razorpay actually sends.

    No top-level `account_id`, and an `acc_*` id nested where the real events
    carry it - so the `rzp_` account guard deliberately does not apply and the
    signature is the only tenant check. This is the case the existing cross-org
    test cannot reach because it assumes a field the provider never sends.
    """
    import json

    default_secret = "isolation_default_secret"  # noqa: S105
    foreign_secret = "isolation_foreign_secret"   # noqa: S105
    monkeypatch.setenv("RAZORPAY_WEBHOOK_SECRET", default_secret)

    class Provider:
        key_id = "rzp_key_default"

        def create_payment(self, authorization_id, amount_minor_units, currency, notes):
            return {"id": "order_realshape", "receipt": authorization_id,
                    "amount": amount_minor_units, "currency": currency, "status": "created"}

        def get_payment(self, payment_id):
            """Corroboration for Phase 9: PAID needs a direct provider read
            as well as the signed webhook."""
            return {"id": payment_id, "status": "captured",
                    "amount": getattr(self, "_amount", 120000),
                    "currency": getattr(self, "_currency", "INR")}

        def fetch_payments(self, order_id):
            return [self.get_payment("pay_sim_1")]

        def verify_webhook(self, raw_body, signature):
            from app.providers.razorpay import verify_webhook_signature
            # The default org's provider is bound to the default secret, exactly
            # as a real adapter is bound to its own tenant's secret.
            return verify_webhook_signature(raw_body, signature, default_secret)

    monkeypatch.setattr(payments_router, "get_provider", lambda: Provider())

    body = make_intent(paari_client, suffix="realshape")
    auth_id = body["authorization"]["authorization_id"]
    r = paari_client.client.post(f"/payments/authorizations/{auth_id}/consume",
                                 json={"session_token": paari_client.session_token})
    assert r.status_code == 200, r.text

    raw = json.dumps({
        "event": "payment.captured",
        "id": "evt_realshape_1",
        "payload": {
            "account": {"entity": {"id": "acc_SPTBGxIMJFQtbe"}},
            "payment": {"entity": {"id": "pay_realshape", "order_id": "order_realshape",
                                   "amount": 120000, "currency": "INR"}},
        },
    }).encode()

    # Signed by a foreign tenant: valid HMAC, wrong party.
    foreign = paari_client.client.post(
        "/payments/webhooks/razorpay", content=raw,
        headers={"X-Razorpay-Signature": _sign(foreign_secret, raw),
                 "Content-Type": "application/json"})
    assert foreign.status_code == 401, foreign.text

    txn = _txn_state(paari_client, "order_realshape")
    assert txn == "PROVIDER_SUBMITTED", f"foreign delivery changed money state: {txn}"

    # Control: the owning tenant's secret is accepted, proving the 401 above was
    # about the signature and not about the payload shape being unprocessable.
    ok = paari_client.client.post(
        "/payments/webhooks/razorpay", content=raw,
        headers={"X-Razorpay-Signature": _sign(default_secret, raw),
                 "Content-Type": "application/json"})
    assert ok.status_code == 200, ok.text
    assert _txn_state(paari_client, "order_realshape") == "PAID"
