"""Task 8: organizations, tenant isolation, per-org provider accounts."""
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.models import Organization  # noqa: F401 (RED: model must exist)

from tests.conftest import make_intent, _register_and_auth

ADMIN_KEY = "test-admin-key"


def _as_admin(monkeypatch, org=None):
    import app.security as security
    monkeypatch.setattr(security, "_ADMIN_API_KEY", ADMIN_KEY)
    monkeypatch.setenv("PAARI_ADMIN_API_KEY", ADMIN_KEY)
    if org is None:
        monkeypatch.delenv("PAARI_ADMIN_ORG", raising=False)
    else:
        monkeypatch.setenv("PAARI_ADMIN_ORG", org)


def _admin_headers():
    return {"X-Admin-Api-Key": ADMIN_KEY}


def _make_org_stack(ctx, org_id, name_suffix):
    """Second-tenant stack: org row + ACTIVE parent in it + registered agent."""
    import app.models as models
    from app import crypto_utils

    db = ctx.Session()
    try:
        db.add(models.Organization(org_id=org_id, name=f"Org {name_suffix}"))
        parent_private, parent_public = crypto_utils.generate_agent_keypair()
        parent = models.ParentAuthority(
            name=f"Parent {name_suffix}", parent_type="developer",
            contact="b@example.com", public_key_pem=parent_public,
            status=models.ParentStatus.ACTIVE, org_id=org_id,
        )
        db.add(parent)
        db.commit()
        db.refresh(parent)
        parent_id = parent.parent_id
    finally:
        db.close()

    agent_id, session_token, agent_private, _cred = _register_and_auth(
        ctx.client, parent_id, parent_private, name_suffix)
    return {"org_id": org_id, "parent_id": parent_id,
            "agent_id": agent_id, "session_token": session_token}


def test_create_org_requires_admin(paari_client, monkeypatch):
    _as_admin(monkeypatch)
    ctx = paari_client
    r = ctx.client.post("/v1/orgs", json={"org_id": "acme", "name": "Acme"})
    assert r.status_code == 401, r.text  # no admin header
    r = ctx.client.post("/v1/orgs", json={"org_id": "acme", "name": "Acme"},
                        headers=_admin_headers())
    assert r.status_code == 200, r.text
    assert r.json()["org_id"] == "acme"


def test_bound_admin_cannot_create_orgs(paari_client, monkeypatch):
    _as_admin(monkeypatch, org="default")
    ctx = paari_client
    r = ctx.client.post("/v1/orgs", json={"org_id": "evil", "name": "Evil"},
                        headers=_admin_headers())
    assert r.status_code == 403, r.text


def test_cross_org_consume_forbidden(paari_client, monkeypatch):
    import app.models as models
    import app.routers.payments as payments_router

    _as_admin(monkeypatch)
    ctx = paari_client
    stack_b = _make_org_stack(ctx, "org-b", "-b")

    class FakeProvider:
        def create_payment(self, authorization_id, amount_minor_units, currency, notes):
            return {"id": "order_org_a", "receipt": authorization_id, "amount": amount_minor_units, "currency": currency, "status": "created"}

    monkeypatch.setattr(payments_router, "get_provider", lambda: FakeProvider())

    # Org A's authorization...
    body = make_intent(ctx, suffix="xorg")
    auth_id = body["authorization"]["authorization_id"]

    # ...consumed with org B's session -> 403, single-use untouched.
    r = ctx.client.post(
        f"/payments/authorizations/{auth_id}/consume",
        json={"session_token": stack_b["session_token"]},
    )
    assert r.status_code == 403, r.text

    db = ctx.Session()
    try:
        auth = db.query(models.BoundedAuthorization).filter_by(
            authorization_id=auth_id).first()
        assert auth.usage_count == 0
        txn = db.query(models.ProviderTransaction).filter_by(authorization_id=auth_id).first()
        assert txn is not None and txn.state == "AUTHORIZED"
    finally:
        db.close()


def test_cross_org_audit_denied(paari_client, monkeypatch):
    _as_admin(monkeypatch)
    ctx = paari_client
    stack_b = _make_org_stack(ctx, "org-b2", "-b2")
    body = make_intent(ctx, suffix="xorg-audit")
    r = ctx.client.get(
        "/v1/audit/TXN-xorg-audit", headers={"Authorization": f"Bearer {stack_b['session_token']}"})
    assert r.status_code == 403, r.text


def test_webhook_scopes_state_to_owning_org(paari_client, monkeypatch):
    import hashlib
    import hmac
    import os

    import app.models as models
    import app.routers.payments as payments_router

    _as_admin(monkeypatch)
    ctx = paari_client

    class FakeProvider:
        def create_payment(self, authorization_id, amount_minor_units, currency, notes):
            return {"id": "order_org_scope", "receipt": authorization_id, "amount": amount_minor_units, "currency": currency, "status": "created"}

        def verify_webhook(self, raw_body, signature):
            from app.providers.razorpay import verify_webhook_signature
            return verify_webhook_signature(
                raw_body, signature, os.environ.get("RAZORPAY_WEBHOOK_SECRET", ""))

    monkeypatch.setattr(payments_router, "get_provider", lambda: FakeProvider())
    monkeypatch.setenv("RAZORPAY_WEBHOOK_SECRET", "org_scope_secret")

    body = make_intent(ctx, suffix="xorg-wh")
    auth_id = body["authorization"]["authorization_id"]
    assert ctx.client.post(
        f"/payments/authorizations/{auth_id}/consume",
        json={"session_token": ctx.session_token}).status_code == 200

    raw = json.dumps({
        "id": "evt_org_1", "event": "payment.captured",
        "payload": {"payment": {"entity": {
            "id": "pay_org_1", "order_id": "order_org_scope",
            "amount": 120000, "currency": "INR"}}}}).encode()
    sig = hmac.new(b"org_scope_secret", raw, hashlib.sha256).hexdigest()
    r = ctx.client.post(
        "/payments/webhooks/razorpay", content=raw,
        headers={"X-Razorpay-Signature": sig, "Content-Type": "application/json"})
    assert r.status_code == 200, r.text

    db = ctx.Session()
    try:
        txn = db.query(models.ProviderTransaction).filter_by(
            authorization_id=auth_id).first()
        assert txn.state == "PAID"
        agent = db.query(models.Agent).filter_by(agent_id=ctx.agent_id).first()
        assert txn.org_id == agent.org_id == "default"
        applied = db.query(models.AuditEvent).filter_by(
            transaction_id="TXN-xorg-wh", kind="webhook_applied").first()
        assert applied is not None and applied.org_id == "default"
    finally:
        db.close()


def test_provider_account_routing(paari_client, monkeypatch):
    from app.provider_accounts import get_provider_for_org

    ctx = paari_client
    db = ctx.Session()
    try:
        import app.models as models
        assert db.query(models.ProviderAccount).filter_by(
            org_id="no-such-org").first() is None
    finally:
        db.close()

    # Unknown non-default org -> strict refusal; no cross-tenant fallback.
    from app.providers.razorpay import RazorpayConfigError
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_default")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "secret_default")
    db = ctx.Session()
    try:
        with pytest.raises(RazorpayConfigError):
            get_provider_for_org(db, "no-such-org")
    finally:
        db.close()

    # Org with its own account row + secrets -> its own adapter.
    monkeypatch.setenv("RAZORPAY_KEY_ID__ORGB", "rzp_test_orgb")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET__ORGB", "secret_orgb")
    monkeypatch.setenv("RAZORPAY_WEBHOOK_SECRET__ORGB", "webhook_orgb")
    db = ctx.Session()
    try:
        db.add(models.ProviderAccount(org_id="orgb", key_id_label="rzp_test_orgb",
                                      is_default=False))
        db.commit()
    finally:
        db.close()
    db = ctx.Session()
    try:
        adapter = get_provider_for_org(db, "orgb")
    finally:
        db.close()
    assert adapter.key_id == "rzp_test_orgb"


def test_bound_admin_cannot_approve_other_org(paari_client, monkeypatch):
    import app.models as models

    ctx = paari_client
    db = ctx.Session()
    try:
        db.add(models.Organization(org_id="org-c", name="C"))
        from app import crypto_utils
        _, pub_c = crypto_utils.generate_agent_keypair()
        parent_c = models.ParentAuthority(
            name="Parent C", parent_type="developer", contact="c@example.com",
            public_key_pem=pub_c, status=models.ParentStatus.PENDING_VERIFICATION,
            org_id="org-c")
        db.add(parent_c)
        db.commit()
        parent_c_id = parent_c.parent_id
    finally:
        db.close()

    _as_admin(monkeypatch, org="default")
    r = ctx.client.post(f"/parents/{parent_c_id}/approve", headers=_admin_headers())
    assert r.status_code == 403, r.text

    _as_admin(monkeypatch)  # unbound administers all
    r = ctx.client.post(f"/parents/{parent_c_id}/approve", headers=_admin_headers())
    assert r.status_code == 200, r.text
    assert r.json()["trust_tier"] == "admin_approved"
