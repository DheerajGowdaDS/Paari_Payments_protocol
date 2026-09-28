"""Task 6: trust tiers, key rotation via fresh delegation, authz revoke."""
import uuid
from datetime import datetime, timedelta, timezone

from tests.conftest import make_intent


def _fresh_delegation(ctx, agent_public_pem, parent_private_pem, limit=500000):
    from app import crypto_utils
    now = datetime.now(timezone.utc)
    delegation = {
        "delegation_id": str(uuid.uuid4()),
        "parent_id": ctx.parent_id,
        "agent_public_key_fingerprint": crypto_utils.public_key_fingerprint(agent_public_pem),
        "granted_capabilities": ["make_payment"],
        "payment_limit_minor_units": limit,
        "currency": "INR",
        "issued_at": int(now.timestamp()),
        "expires_at": int((now + timedelta(days=30)).timestamp()),
    }
    sig = crypto_utils.sign_with_private_key(
        parent_private_pem, crypto_utils.canonical_json(delegation))
    return delegation, sig


def _authenticate(client, agent_id, agent_private, credential_jwt):
    r = client.post("/auth/challenge", json={"agent_id": agent_id})
    assert r.status_code == 200, r.text
    nonce = r.json()["nonce"]
    from app import crypto_utils
    sig = crypto_utils.sign_with_private_key(agent_private, nonce)
    r = client.post("/auth/verify", json={
        "agent_id": agent_id, "nonce": nonce,
        "signature_b64": sig, "credential_jwt": credential_jwt})
    assert r.status_code == 200, r.text
    return r.json()["session_token"]


def test_agent_key_rotation_needs_fresh_delegation(paari_client):
    from app import crypto_utils
    ctx = paari_client
    new_private, new_public = crypto_utils.generate_agent_keypair()
    r = ctx.client.post(f"/v1/agents/{ctx.agent_id}/rotate-key", json={
        "new_public_key_pem": new_public,
        "delegation": {},
        "delegation_signature_b64": "bogus",
    })
    assert r.status_code == 401, r.text


def test_rotation_with_parent_delegation_succeeds_and_sunsets_old(paari_client):
    import app.models as models
    from app import crypto_utils
    ctx = paari_client
    new_private, new_public = crypto_utils.generate_agent_keypair()
    delegation, sig = _fresh_delegation(ctx, new_public, ctx.parent_private)
    # Mint an authorization BEFORE rotation, while the old session is live.
    pre_body = make_intent(ctx, suffix="rot-pre")
    pre_auth_id = pre_body["authorization"]["authorization_id"]
    r = ctx.client.post(f"/v1/agents/{ctx.agent_id}/rotate-key", json={
        "new_public_key_pem": new_public,
        "delegation": delegation,
        "delegation_signature_b64": sig,
    })
    assert r.status_code == 200, r.text
    new_credential = r.json()["credential_jwt"]

    # Old credential revoked -> old session fails closed immediately.
    db = ctx.Session()
    agent = db.query(models.Agent).filter_by(agent_id=ctx.agent_id).first()
    assert agent.public_key_pem == new_public
    assert agent.old_public_key_pem is not None
    assert agent.key_sunset_at is not None
    live_creds = db.query(models.Credential).filter_by(agent_pk=agent.id, revoked=False).all()
    assert live_creds and all(c.signed_jwt == new_credential for c in live_creds)
    db.close()

    # Old credential revoked -> pre-rotation authorization fails closed.
    r = ctx.client.post(f"/payments/authorizations/{pre_auth_id}/consume",
                        json={"session_token": ctx.session_token})
    assert r.status_code == 401, r.text

    # New key authenticates and transacts.
    token = _authenticate(ctx.client, ctx.agent_id, new_private, new_credential)
    import uuid as _uuid
    rr = ctx.client.post("/payments/intent", json={
        "session_token": token, "transaction_id": "TXN-rot-new2",
        "idempotency_key": f"idem-rot-{_uuid.uuid4().hex[:6]}",
        "merchant": "TestMerchant", "amount_minor_units": 120000,
        "currency": "INR", "action": "make_payment", "purpose": "rotation test"})
    assert rr.status_code == 200, rr.text
    assert rr.json()["decision"] == "allow"

    # Old key authenticates during the 24h grace window...
    grace_token = _authenticate(ctx.client, ctx.agent_id, ctx.agent_private, new_credential)
    assert grace_token

    # ...and fails closed once the sunset has passed.
    db = ctx.Session()
    agent = db.query(models.Agent).filter_by(agent_id=ctx.agent_id).first()
    agent.key_sunset_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    db.close()
    r = ctx.client.post("/auth/challenge", json={"agent_id": ctx.agent_id})
    assert r.status_code == 200, r.text
    nonce = r.json()["nonce"]
    sig = crypto_utils.sign_with_private_key(ctx.agent_private, nonce)
    # NOTE: ctx.session_token's credential was revoked at rotation; fetch the
    # current live credential for this negative check.
    db = ctx.Session()
    live = db.query(models.Credential).filter_by(revoked=False).order_by(
        models.Credential.issued_at.desc()).first()
    live_jwt = live.signed_jwt
    db.close()
    r = ctx.client.post("/auth/verify", json={
        "agent_id": ctx.agent_id, "nonce": nonce,
        "signature_b64": sig, "credential_jwt": live_jwt})
    assert r.status_code == 401, r.text


def test_authz_revoke_burns_unconsumed(paari_client, monkeypatch):
    import app.routers.payments as payments_router
    ctx = paari_client

    class FakeProvider:
        def create_payment(self, **kwargs):
            return {"id": "order_revoke_1", "receipt": authorization_id, "amount": kwargs.get("amount_minor_units"), "currency": kwargs.get("currency"), "status": "created"}

    monkeypatch.setattr(payments_router, "get_provider", lambda: FakeProvider())
    body = make_intent(ctx, suffix="revoke-me")
    auth_id = body["authorization"]["authorization_id"]
    r = ctx.client.post(f"/v1/authorizations/{auth_id}/revoke",
                        json={"session_token": ctx.session_token})
    assert r.status_code == 200, r.text
    r = ctx.client.post(f"/payments/authorizations/{auth_id}/consume",
                        json={"session_token": ctx.session_token})
    assert r.status_code == 409, r.text


def test_trust_tier_approve_and_kyb(paari_client, monkeypatch):
    import app.security as security
    from app import crypto_utils
    monkeypatch.setattr(security, "_ADMIN_API_KEY", "test-admin")
    headers = {"X-Admin-Api-Key": "test-admin"}
    ctx = paari_client
    # Register a fresh parent through the real endpoint (starts self-asserted).
    _, parent_public = crypto_utils.generate_agent_keypair()
    r = ctx.client.post("/parents/register", json={
        "name": "Tier Parent", "parent_type": "developer",
        "contact": "tier@example.com", "public_key_pem": parent_public})
    assert r.status_code == 200, r.text
    parent_id = r.json()["parent_id"]
    r = ctx.client.post(f"/parents/{parent_id}/approve", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["trust_tier"] == "admin_approved"
    r = ctx.client.post(f"/v1/parents/{parent_id}/kyb", headers=headers,
                        json={"provider_ref": "kyb-vendor-ref-1"})
    assert r.status_code == 200, r.text
    assert r.json()["trust_tier"] == "kyb_verified"


def test_parent_key_rotation(paari_client, monkeypatch):
    import app.security as security
    from app import crypto_utils
    monkeypatch.setattr(security, "_ADMIN_API_KEY", "test-admin")
    headers = {"X-Admin-Api-Key": "test-admin"}
    ctx = paari_client
    new_private, new_public = crypto_utils.generate_agent_keypair()
    r = ctx.client.post(f"/v1/parents/{ctx.parent_id}/rotate-key", headers=headers,
                        json={"new_public_key_pem": new_public})
    assert r.status_code == 200, r.text
    # A delegation signed by the NEW parent key verifies for new registrations.
    agent_private, agent_public = crypto_utils.generate_agent_keypair()
    now = datetime.now(timezone.utc)
    delegation = {
        "delegation_id": str(uuid.uuid4()),
        "parent_id": ctx.parent_id,
        "agent_public_key_fingerprint": crypto_utils.public_key_fingerprint(agent_public),
        "granted_capabilities": ["make_payment"],
        "payment_limit_minor_units": 500000,
        "currency": "INR",
        "issued_at": int(now.timestamp()),
        "expires_at": int((now + timedelta(days=30)).timestamp()),
    }
    sig = crypto_utils.sign_with_private_key(
        new_private, crypto_utils.canonical_json(delegation))
    r = ctx.client.post("/agents/register", json={
        "name": "PostRotation", "agent_type": "shopping_assistant",
        "purpose": "parent rotation test", "public_key_pem": agent_public,
        "delegation": delegation, "delegation_signature_b64": sig})
    assert r.status_code == 200, r.text
