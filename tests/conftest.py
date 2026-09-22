"""Shared fixtures: isolated SQLite DB (built by Alembic) + real register/auth/intent flow."""
import pathlib
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

TEST_DB_URL = "sqlite:///./.phase5_test.db"
ALEMBIC_INI = str(pathlib.Path(__file__).resolve().parents[1] / "alembic.ini")


def _migrate_fresh(url: str):
    """Drop the file (if any) and rebuild schema purely via `alembic upgrade head`."""
    from alembic import command
    from alembic.config import Config

    path = url.removeprefix("sqlite:///")
    if pathlib.Path(path).exists():
        pathlib.Path(path).unlink()
    cfg = Config(ALEMBIC_INI)
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")


def _register_and_auth(client, parent_id, parent_private, name_suffix=""):
    from app import crypto_utils

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
            "name": f"Test Agent{name_suffix}",
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
    return agent_id, r.json()["session_token"], agent_private, credential_jwt


@pytest.fixture()
def paari_client():
    import app.models as models  # noqa: F401  (register all tables for the ORM)
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

    agent_id, session_token, agent_private, _cred = _register_and_auth(client, parent_id, parent_private)

    ctx = type(
        "Ctx",
        (),
        {
            "client": client,
            "session_token": session_token,
            "agent_id": agent_id,
            "agent_private": agent_private,
            "parent_id": parent_id,
            "parent_private": parent_private,
            "Session": TestingSession,
            "register_extra_agent": lambda suffix="2": _register_and_auth(
                client, parent_id, parent_private, suffix
            ),
        },
    )
    yield ctx
    fastapi_app.dependency_overrides.clear()
    test_engine.dispose()


def make_intent(ctx, amount=120000, suffix=None):
    suffix = suffix or uuid.uuid4().hex[:8]
    r = ctx.client.post(
        "/payments/intent",
        json={
            "session_token": ctx.session_token,
            "transaction_id": f"TXN-{suffix}",
            "idempotency_key": f"idem-{suffix}",
            "merchant": "TestMerchant",
            "amount_minor_units": amount,
            "currency": "INR",
            "action": "make_payment",
            "purpose": "phase5 test",
        },
    )
    assert r.status_code == 200, r.text
    return r.json()
