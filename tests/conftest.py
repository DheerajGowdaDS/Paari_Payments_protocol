"""Shared fixtures: isolated SQLite DB (built by Alembic) + real register/auth/intent flow.

Where the pytest database comes from
-----------------------------------
`TEST_DATABASE_URL` - and nothing else - is the database this suite is allowed
to destroy and rebuild. It used to read `DATABASE_URL`, which is the
*deployment's* database variable: an operator who followed the documented
setup (export `DATABASE_URL` and `ALEMBIC_URL` at the sandbox) and then ran
`pytest -q` had `DROP SCHEMA public CASCADE` executed against that live
sandbox before the first test collected. A test harness must never inherit the
name that points at real data, so `DATABASE_URL` is not consulted here at all.

Unset, the suite stays on a throwaway SQLite file exactly as before. Set it to
Postgres and the whole suite runs against Postgres - which is the only way the
referential-integrity work in migration e4f5a6b7c8d9 ever gets executed rather
than asserted. `app.database.assert_disposable_database_url` still gates the
reset, so a `TEST_DATABASE_URL` that names a non-disposable database aborts the
session instead of wiping it.
"""
import os
import pathlib
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker


def _read_env_test() -> dict:
    """Parse `.env.test` into the suite's baseline configuration.

    A file nobody reads is not isolation, and the Blueprint's point was that the
    suite should DECIDE its posture rather than inherit one. So this is loaded
    here, and the fixture below applies it. `.env.test` deliberately omits
    `DATABASE_URL` - that name belongs to the deployment.
    """
    path = pathlib.Path(__file__).resolve().parents[1] / ".env.test"
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


TEST_BASELINE = _read_env_test()

# An explicit TEST_DATABASE_URL / PAARI_DATABASE_URL from the caller wins over
# the checked-in default, so CI can run the whole suite against Postgres without
# editing anything. Nothing here falls back to `DATABASE_URL`.
TEST_DATABASE_URL = (
    os.environ.get("TEST_DATABASE_URL")
    or os.environ.get("PAARI_DATABASE_URL")
    or TEST_BASELINE.get("PAARI_DATABASE_URL")
    or "sqlite:///./.phase5_test.db"
)
ALEMBIC_INI = str(pathlib.Path(__file__).resolve().parents[1] / "alembic.ini")

# ORDER-CRITICAL. `app.database` freezes its global engine at import, so the test
# target must be in the environment BEFORE anything imports it. Importing the
# classifier first would resolve the engine against the operator's ambient
# `DATABASE_URL` - a deployment database - and no later fixture could undo that.
os.environ["PAARI_DATABASE_URL"] = TEST_DATABASE_URL
# A leaked PAARI_LIVE makes `app.security` demand a signing-key path during
# *collection*, failing the whole suite for a reason no fixture can undo.
os.environ.pop("PAARI_LIVE", None)

from app.database import assert_disposable_database_url  # noqa: E402

# Fail at import, before any fixture can run: pytest exit means the operator
# sees one clear reason instead of a hundred errors.
try:
    assert_disposable_database_url(TEST_DATABASE_URL, "reset the pytest database")
except RuntimeError as exc:  # pragma: no cover - guard trip
    pytest.exit(str(exc), returncode=2)


def _reset_database(url: str) -> None:
    """Give each test a genuinely empty schema, on SQLite and on Postgres.

    The old code only unlinked a *file*:
        url.removeprefix("sqlite:///")
    For any non-SQLite URL that expression returns the whole DSN, Path(...)
    never exists, and the reset silently became a NO-OP. Every test then
    shared one accumulating database, so a Postgres run failed with
    `duplicate key ... organizations_org_id_key` / UniqueViolation errors
    that had nothing to do with the code under test. The suite was therefore
    structurally SQLite-only and had never actually been validated against
    Postgres, even though CI provisions a Postgres service.
    """
    from sqlalchemy import create_engine, text

    # Belt and braces: the caller has already checked, but this is the function
    # that drops schemas and it must not depend on its callers remembering.
    assert_disposable_database_url(url, "reset the pytest database")

    if url.startswith("sqlite"):
        path = url.removeprefix("sqlite:///")
        # The app's module-level engine is pooled and lives for the whole
        # session. Now that it is correctly pinned to the same disposable file
        # as the per-test engine, its open connection is what holds the file
        # locked on Windows - so it has to be released before the unlink.
        from app import database as app_database
        if str(app_database.DATABASE_URL).removeprefix("sqlite:///") == path:
            app_database.engine.dispose()
        if pathlib.Path(path).exists():
            pathlib.Path(path).unlink()
        return

    # Postgres (and anything else server-side): drop and recreate the public
    # schema. Only reachable for a database named as disposable.
    engine = create_engine(url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as conn:
            conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
    finally:
        engine.dispose()


def _migrate_fresh(url: str):
    """Reset the schema and rebuild it purely via `alembic upgrade head`."""
    from alembic import command
    from alembic.config import Config

    _reset_database(url)
    cfg = Config(ALEMBIC_INI)
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")

@pytest.fixture(autouse=True)
def isolate_test_environment(monkeypatch):
    """Apply `.env.test` as the baseline every test starts from.

    The point is determinism from an explicit decision rather than inheritance:
    an operator shell exporting `PAARI_REQUIRE_USER_MANDATE=1` used to silently
    move the whole suite into autonomous posture, where a payment with no mandate
    is denied and standard-mode assertions fail for a reason that has nothing to
    do with the code under test. Tests that want the autonomous posture say so
    themselves with monkeypatch.
    """
    # Posture and environment come from the versioned baseline; anything the
    # baseline does not name is removed rather than inherited, so a new ambient
    # variable cannot change protocol behaviour by accident.
    for name in ("PAARI_ENV", "PAARI_MODE", "PAARI_REQUIRE_USER_MANDATE",
                 "PAARI_REQUIRE_SIGNED_MANDATE"):
        if name in TEST_BASELINE:
            monkeypatch.setenv(name, TEST_BASELINE[name])
        else:
            monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("PAARI_LIVE", raising=False)
    # `app.security` freezes the admin key and the signing-key path at import,
    # and the payment provider reads Razorpay credentials per call, so an
    # operator shell with real test keys would let a "unit" test talk to the
    # live API. The suite drives a local stub or no provider at all.
    for name in (
        "PAARI_ADMIN_API_KEY",
        "PAARI_ADMIN_ORG",
        "PAARI_SIGNING_KEY_PATH",
        "PAARI_REQUIRE_REQUEST_PROOF",
        "PAARI_AGENTIC_PROVIDER",
        "RAZORPAY_KEY_ID",
        "RAZORPAY_KEY_SECRET",
        "RAZORPAY_WEBHOOK_SECRET",
        "RAZORPAY_API_BASE",
    ):
        monkeypatch.delenv(name, raising=False)
    # The deployment URL must never reach the app under test either.
    monkeypatch.setenv("PAARI_DATABASE_URL", TEST_DATABASE_URL)
    monkeypatch.delenv("ALEMBIC_URL", raising=False)
    assert os.environ.get("RAZORPAY_KEY_ID") is None, \
        "provider credentials leaked into the test environment"
    assert os.environ.get("PAARI_LIVE") is None, \
        "PAARI_LIVE leaked into the test environment"
    # The strongest form of the guarantee: not "we set the variable" but "the
    # module that froze its engine at import is pointing where we think it is".
    from app import database as app_database
    assert_disposable_database_url(app_database.DATABASE_URL, "back the app under test")
    assert app_database.DATABASE_URL == TEST_DATABASE_URL, (
        f"app.database resolved to {app_database.DATABASE_URL!r}, not the "
        f"disposable {TEST_DATABASE_URL!r}")





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

    _migrate_fresh(TEST_DATABASE_URL)
    test_engine = get_engine(TEST_DATABASE_URL)
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


def make_intent(ctx, amount=120000, suffix=None, mandate_id=None):
    suffix = suffix or uuid.uuid4().hex[:8]
    payload = {
        "session_token": ctx.session_token,
        "transaction_id": f"TXN-{suffix}",
        "idempotency_key": f"idem-{suffix}",
        "merchant": "TestMerchant",
        "amount_minor_units": amount,
        "currency": "INR",
        "action": "make_payment",
        "purpose": "phase5 test",
    }
    # Optional so a test can assert the server ignores a client-named mandate.
    # The request field is never authoritative; only the parent/user-signed
    # delegation and mandate values apply.
    if mandate_id is not None:
        payload["mandate_id"] = mandate_id
    r = ctx.client.post("/payments/intent", json=payload)
    assert r.status_code == 200, r.text
    return r.json()
