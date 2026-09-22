"""Phase 5 consume tests: provider execution + atomic single-use + revocation.

RED expectations (pre-fix):
- `app.routers.payments` has no `razorpay_provider` attribute -> monkeypatch errors.
- consume response has no provider state fields.
- consume after parent revocation still returns 200.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from tests.conftest import _migrate_fresh

TEST_DB_URL = "sqlite:///./.phase5_test.db"


@pytest.fixture()
def client_with_auth(monkeypatch):
    import app.models as models
    from app import crypto_utils
    from app.database import get_engine

    _migrate_fresh(TEST_DB_URL)
    test_engine = get_engine(TEST_DB_URL)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    from app.main import app as fastapi_app
    from app.database import get_db

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    fastapi_app.dependency_overrides[get_db] = override_get_db
    client = TestClient(fastapi_app)

    # Seed an ACTIVE parent directly (bypasses admin gate for test speed).
    parent_private, parent_public = crypto_utils.generate_agent_keypair()
    db = TestingSession()
    parent = models.ParentAuthority(
        name="Test Parent",
        parent_type="developer",
        contact="test@example.com",
        public_key_pem=parent_public,
        status=models.ParentStatus.ACTIVE,
    )
    db.add(parent)
    db.commit()
    db.refresh(parent)
    parent_id = parent.parent_id
    db.close()

    # Register agent through the real endpoint (exercises delegation verification).
    agent_private, agent_public = crypto_utils.generate_agent_keypair()
    now = datetime.now(timezone.utc)
    delegation = {
        "delegation_id": str(uuid.uuid4()),
        "parent_id": parent_id,
        "agent_public_key_fingerprint": crypto_utils.public_key_fingerprint(agent_public),
        "granted_capabilities": ["make_payment"],
        "payment_limit_minor_units": 500000,
        "currency": "INR",
        "issued_at": int(now.timestamp()),
        "expires_at": int((now + timedelta(days=30)).timestamp()),
    }
    sig = crypto_utils.sign_with_private_key(
        parent_private, crypto_utils.canonical_json(delegation)
    )
    r = client.post(
        "/agents/register",
        json={
            "name": "Test Agent",
            "agent_type": "shopping_assistant",
            "purpose": "phase5 test",
            "public_key_pem": agent_public,
            "delegation": delegation,
            "delegation_signature_b64": sig,
        },
    )
    assert r.status_code == 200, r.text
    agent_id = r.json()["agent_card"]["agent_id"]
    credential_jwt = r.json()["credential_jwt"]

    # Authenticate to a session token.
    r = client.post("/auth/challenge", json={"agent_id": agent_id})
    assert r.status_code == 200, r.text
    nonce = r.json()["nonce"]
    nonce_sig = crypto_utils.sign_with_private_key(agent_private, nonce)
    r = client.post(
        "/auth/verify",
        json={
            "agent_id": agent_id,
            "nonce": nonce,
            "signature_b64": nonce_sig,
            "credential_jwt": credential_jwt,
        },
    )
    assert r.status_code == 200, r.text
    session_token = r.json()["session_token"]

    # Mock the provider at the router seam (real API used in manual runs).
    import app.routers.payments as payments_router

    class FakeProvider:
        def create_payment(self, authorization_id, amount_minor_units, currency, notes):
            return {"id": "order_test_123", "receipt": authorization_id, "amount": amount_minor_units, "currency": currency, "status": "created"}

    monkeypatch.setattr(payments_router, "get_provider", lambda: FakeProvider())

    yield type(
        "Ctx",
        (),
        {
            "client": client,
            "session_token": session_token,
            "agent_id": agent_id,
            "parent_id": parent_id,
            "Session": TestingSession,
        },
    )
    fastapi_app.dependency_overrides.clear()
    test_engine.dispose()


def _new_allow_authorization(ctx, idem_suffix):
    r = ctx.client.post(
        "/payments/intent",
        json={
            "session_token": ctx.session_token,
            "transaction_id": f"TXN-{idem_suffix}",
            "idempotency_key": f"idem-{idem_suffix}-{uuid.uuid4().hex[:8]}",
            "merchant": "TestMerchant",
            "amount_minor_units": 120000,
            "currency": "INR",
            "action": "make_payment",
            "purpose": "phase5 test",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["decision"] == "allow", body
    return body["authorization"]["authorization_id"]


def test_consume_returns_provider_state(client_with_auth):
    ctx = client_with_auth
    auth_id = _new_allow_authorization(ctx, "provider-state")
    r = ctx.client.post(
        f"/payments/authorizations/{auth_id}/consume",
        json={"session_token": ctx.session_token},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["razorpay_order_id"] == "order_test_123"
    assert body["state"] in ("PROVIDER_SUBMITTED", "PAYMENT_PENDING")


def test_double_consume_second_rejected(client_with_auth):
    ctx = client_with_auth
    auth_id = _new_allow_authorization(ctx, "double")
    first = ctx.client.post(
        f"/payments/authorizations/{auth_id}/consume",
        json={"session_token": ctx.session_token},
    )
    assert first.status_code == 200, first.text
    second = ctx.client.post(
        f"/payments/authorizations/{auth_id}/consume",
        json={"session_token": ctx.session_token},
    )
    assert second.status_code == 409


def test_consume_blocked_after_parent_revoked(client_with_auth):
    import app.models as models

    ctx = client_with_auth
    auth_id = _new_allow_authorization(ctx, "revoked")
    db = ctx.Session()
    parent = db.query(models.ParentAuthority).filter_by(parent_id=ctx.parent_id).first()
    parent.status = models.ParentStatus.REVOKED
    db.commit()
    db.close()
    r = ctx.client.post(
        f"/payments/authorizations/{auth_id}/consume",
        json={"session_token": ctx.session_token},
    )
    assert r.status_code in (401, 403), r.text
