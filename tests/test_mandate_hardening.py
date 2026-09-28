"""Regression tests for the three P0 money-path defects plus posture hardening.

Each test failed against the pre-remediation code:

- P0-1  A lapsed (expired or revoked) mandate resolved to the same value as
        "no mandate ever existed", so in standard mode an expired spending cap
        silently became NO cap: the payment was ALLOWed with
        reasons=["all checks passed"] and mandate_id=None.
- P0-2  The Ed25519 mandate signature was verified only at creation and for
        display, so a direct DB edit could raise a signed mandate's limits.
- P0-3  active_mandate() ordered by expires_at DESC, so the longest-lived
        mandate won regardless of its limits.
- P1-5  A typo in PAARI_MODE silently degraded to `standard`, i.e. made the
        mandate optional - the fail-open direction.

The blueprint's expiry matrix lives here too: expired (+/- valid signature,
+/- revoked, +/- valid delegation) must always DENY. The governing property is
that a valid signature does NOT make an expired mandate valid.
"""
from datetime import datetime, timedelta, timezone

from tests.conftest import make_intent
from tests.test_user_mandates import create_mandate, _admin_key
from tests.test_v2_governance import _user_keypair, _signed_mandate_post


def _frozen(shift: timedelta) -> datetime:
    """A 'now' shifted from real time, kept inside the 15-minute session TTL."""
    return datetime.now(timezone.utc) + shift


def _short_lived_mandate(ctx, **overrides) -> dict:
    """A mandate expiring in 60s, so a +2min freeze is past its expiry but
    still inside the session TTL."""
    now = datetime.now(timezone.utc)
    payload = {
        "max_per_transaction": 1000,
        "max_daily_amount": 2000,
        "valid_from": now.isoformat(),
        "expires_at": (now + timedelta(seconds=60)).isoformat(),
    }
    payload.update(overrides)
    return create_mandate(ctx, **payload)


# --------------------------- P0-1 lapsed mandate ---------------------------

def test_lapsed_mandate_denies_in_standard_mode(paari_client):
    """An EXPIRED mandate is a revoked grant of user authority, not an absent
    one. Pre-fix this ALLOWed with 'all checks passed' and mandate_id=None,
    turning a 1,000/2,000 cap into no cap at all."""
    from app.routers import payments as payments_mod

    ctx = paari_client
    _short_lived_mandate(ctx)
    real_now = payments_mod._now
    payments_mod._now = lambda: _frozen(timedelta(minutes=2))
    try:
        body = make_intent(ctx, amount=100_000, suffix="lapsed-standard")
    finally:
        payments_mod._now = real_now

    assert body["decision"] == "deny", body
    assert body["mandate_id"] is None
    assert any("no active user payment mandate" in r for r in body["reasons"]), body["reasons"]
    assert "all checks passed" not in body["reasons"]


def test_lapsed_mandate_denies_even_with_valid_signature(paari_client):
    """Blueprint: a valid signature does NOT make an expired mandate valid."""
    from app.routers import payments as payments_mod
    from app.mandate_signing import verify_mandate_signature
    from app.models import UserPaymentMandate

    ctx = paari_client
    user_private, user_public = _user_keypair()
    now = datetime.now(timezone.utc)
    _signed_mandate_post(
        ctx, user_private, user_public,
        max_per_transaction=1000, max_daily_amount=2000,
        valid_from=now.isoformat(),
        expires_at=(now + timedelta(seconds=60)).isoformat(),
    )
    db = ctx.Session()
    try:
        # The signature itself is genuinely valid - only liveness has lapsed.
        assert verify_mandate_signature(db.query(UserPaymentMandate).first()).signature_valid
    finally:
        db.close()

    real_now = payments_mod._now
    payments_mod._now = lambda: now + timedelta(minutes=2)
    try:
        body = make_intent(ctx, amount=100_000, suffix="lapsed-signed")
    finally:
        payments_mod._now = real_now

    assert body["decision"] == "deny", body


def test_expired_and_revoked_mandate_denies(paari_client):
    """Blueprint: expired + revoked is a hard deny."""
    ctx = paari_client
    now = datetime.now(timezone.utc)
    mandate = create_mandate(
        ctx, max_per_transaction=5000, max_daily_amount=10000,
        valid_from=(now - timedelta(days=2)).isoformat(),
        expires_at=(now - timedelta(days=1)).isoformat(),
    )
    revoke = ctx.client.post(
        f"/v1/mandates/{mandate['mandate_id']}/revoke",
        json={"reason": "audit: expired and revoked"},
        headers={"X-Admin-Api-Key": _admin_key()},
    )
    assert revoke.status_code == 200, revoke.text

    body = make_intent(ctx, amount=1000, suffix="expired-revoked")
    assert body["decision"] == "deny", body
    assert any("user payment mandate" in r for r in body["reasons"]), body["reasons"]


def test_expired_mandate_with_valid_delegation_denies(paari_client):
    """Blueprint: expired + valid delegation still denies.

    Parent delegation and user payment authority are two separate grants; a
    healthy agent delegation must not substitute for lapsed user consent.
    """
    ctx = paari_client
    now = datetime.now(timezone.utc)
    create_mandate(
        ctx, max_per_transaction=5000, max_daily_amount=10000,
        valid_from=(now - timedelta(days=2)).isoformat(),
        expires_at=(now - timedelta(days=1)).isoformat(),
    )
    # conftest registers the agent with a 30-day delegation, still valid.
    body = make_intent(ctx, amount=1000, suffix="expired-valid-delegation")
    assert body["decision"] == "deny", body


# ------------------------ P0-2 signature enforcement -----------------------

def test_tampered_signed_mandate_cannot_raise_limits(paari_client, monkeypatch):
    """The signature was verified only at creation and for display, so a direct
    DB edit could freely raise a *signed* mandate's limits."""
    from app.models import UserPaymentMandate

    monkeypatch.setenv("PAARI_MODE", "autonomous")
    ctx = paari_client
    user_private, user_public = _user_keypair()
    _signed_mandate_post(ctx, user_private, user_public,
                         max_per_transaction=1000, max_daily_amount=2000)

    db = ctx.Session()
    try:
        row = db.query(UserPaymentMandate).first()
        row.max_per_transaction = 10_000_000
        row.max_daily_amount = 20_000_000
        db.commit()
    finally:
        db.close()

    body = make_intent(ctx, amount=5000, suffix="tampered-signed")
    assert body["decision"] == "deny", body
    assert any("signature" in r for r in body["reasons"]), body["reasons"]


def test_tampered_signed_mandate_blocks_consume(paari_client, monkeypatch):
    """Execution half: a mandate altered AFTER minting must not be spendable."""
    import app.routers.payments as payments_router
    from app.models import UserPaymentMandate

    class FakeProvider:
        def create_payment(self, authorization_id, amount_minor_units, currency, notes):
            return {"id": "order_tamper", "receipt": authorization_id,
                    "amount": amount_minor_units, "currency": currency, "status": "created"}

    monkeypatch.setattr(payments_router, "get_provider", lambda: FakeProvider())
    ctx = paari_client
    user_private, user_public = _user_keypair()
    _signed_mandate_post(ctx, user_private, user_public,
                         max_per_transaction=5000, max_daily_amount=5000)
    ok = make_intent(ctx, amount=1000, suffix="tamper-consume-allow")
    assert ok["decision"] == "allow", ok
    auth_id = ok["authorization"]["authorization_id"]

    db = ctx.Session()
    try:
        row = db.query(UserPaymentMandate).first()
        row.allowed_merchants = ["SomeoneElseEntirely"]
        db.commit()
    finally:
        db.close()

    r = ctx.client.post(f"/payments/authorizations/{auth_id}/consume",
                        json={"session_token": ctx.session_token})
    assert r.status_code == 403, r.text
    detail = r.json()["detail"]
    assert "signature" in detail or "merchant" in detail


def test_require_signed_mandate_mode_rejects_unsigned(paari_client, monkeypatch):
    """PAARI_REQUIRE_SIGNED_MANDATE=1 makes an unsigned mandate unacceptable."""
    monkeypatch.setenv("PAARI_MODE", "autonomous")
    monkeypatch.setenv("PAARI_REQUIRE_SIGNED_MANDATE", "1")
    ctx = paari_client
    create_mandate(ctx, max_per_transaction=5000, max_daily_amount=10000)
    body = make_intent(ctx, amount=1000, suffix="unsigned-rejected")
    assert body["decision"] == "deny", body
    assert any("unsigned" in r for r in body["reasons"]), body["reasons"]


# --------------------- P0-3 tightest mandate governs -----------------------

def test_tightest_active_mandate_governs(paari_client):
    """Two ACTIVE mandates must intersect. Ordering by expires_at DESC let a
    broad 90-day mandate silently override a narrow 1-day one."""
    ctx = paari_client
    now = datetime.now(timezone.utc)
    create_mandate(ctx, max_per_transaction=1000, max_daily_amount=2000,
                   expires_at=(now + timedelta(days=1)).isoformat())
    create_mandate(ctx, max_per_transaction=900_000, max_daily_amount=900_000,
                   expires_at=(now + timedelta(days=90)).isoformat())

    body = make_intent(ctx, amount=50_000, suffix="two-mandates")
    assert body["decision"] == "deny", body
    assert any("per-transaction" in r for r in body["reasons"]), body["reasons"]


def test_all_active_mandates_are_reported_as_evaluated(paari_client):
    """The decision must record which mandates were considered."""
    from app import mandates as mandates_mod
    from app.models import Agent

    ctx = paari_client
    now = datetime.now(timezone.utc)
    create_mandate(ctx, max_per_transaction=1000, max_daily_amount=2000,
                   expires_at=(now + timedelta(days=1)).isoformat())
    create_mandate(ctx, max_per_transaction=900_000, max_daily_amount=900_000,
                   expires_at=(now + timedelta(days=90)).isoformat())
    db = ctx.Session()
    try:
        agent = db.query(Agent).filter_by(agent_id=ctx.agent_id).one()
        decision = mandates_mod.evaluate_mandate(
            db, agent=agent, merchant="TestMerchant", amount_minor_units=1,
            currency="INR")
        assert len(decision.evaluated) == 2, decision.evaluated
        assert decision.mandate.max_per_transaction == 1000
    finally:
        db.close()


# ------------------------- P1-5 posture fail-closed ------------------------

def test_invalid_paari_mode_is_rejected_not_downgraded(paari_client, monkeypatch):
    """A typo in PAARI_MODE used to silently degrade to `standard`, i.e. make
    the mandate optional - the fail-open direction."""
    monkeypatch.setenv("PAARI_MODE", "autonom")
    ctx = paari_client
    r = ctx.client.post("/payments/intent", json={
        "session_token": ctx.session_token, "transaction_id": "TXN-badmode",
        "idempotency_key": "idem-badmode", "merchant": "TestMerchant",
        "amount_minor_units": 100, "currency": "INR", "action": "make_payment",
    })
    assert r.status_code == 500, r.text
    assert "PAARI_MODE" in r.json()["detail"]


def test_legacy_require_user_mandate_alias_still_works(paari_client, monkeypatch):
    """PAARI_REQUIRE_USER_MANDATE=1 must keep strengthening enforcement."""
    monkeypatch.setenv("PAARI_REQUIRE_USER_MANDATE", "1")
    ctx = paari_client
    assert make_intent(ctx, amount=100, suffix="legacy-alias")["decision"] == "deny"
