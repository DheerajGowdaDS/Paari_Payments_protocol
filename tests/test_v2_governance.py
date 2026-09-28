"""Paari v2 Sprint 5-7 tests: signed mandates, spending aggregation, LLM causal audit,
autonomous mode, and the honest NOT_CONFIGURED agentic provider boundary.
"""
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import make_intent
from tests.test_user_mandates import create_mandate, _admin_key


def _user_keypair():
    from app import crypto_utils
    return crypto_utils.generate_agent_keypair()


def _proof(ctx, method, path):
    from sdk.paari_agent.crypto import build_request_proof
    return build_request_proof(
        ctx.agent_private, agent_id=ctx.agent_id, access_token=ctx.session_token,
        method=method, path=path,
    )


def _mandate_payload_for_post(body: dict) -> dict:
    """Canonical mandate fields exactly as the server stores them, so the
    user key can sign BEFORE submission (mirrors the server-side payload)."""
    from app import crypto_utils

    def _iso(dt: str) -> int:
        return int(datetime.fromisoformat(dt.replace("Z", "+00:00")).timestamp())

    payload = {
        "purpose": "paari_user_payment_mandate",
        "mandate_version": 1,
        "mandate_id": body["mandate_id"],
        "user_id": body["user_id"],
        "agent_id": body["agent_id"],
        "org_id": "default",
        "constraints": {
            "currency": body["currency"],
            "max_per_transaction": int(body["max_per_transaction"]),
            "max_daily_amount": int(body["max_daily_amount"]),
            "max_per_hour": body.get("max_per_hour"),
            "max_per_merchant_per_day": body.get("max_per_merchant_per_day"),
            "max_category_per_day": body.get("max_category_per_day"),
            "allowed_merchants": sorted(str(m) for m in (body.get("allowed_merchants") or [])),
            "allowed_categories": sorted(str(c) for c in (body.get("allowed_categories") or [])),
            "require_review_above": body.get("require_review_above"),
        },
        "issued_at": _iso(body["valid_from"]),
        "expires_at": _iso(body["expires_at"]),
    }
    return crypto_utils.canonical_json(payload)


def _signed_mandate_post(ctx, user_private, user_public, **overrides) -> dict:
    """Full API-path signed-mandate creation: the client picks the mandate_id,
    computes the canonical payload, signs it with the user key, and posts it."""
    from app import crypto_utils

    now = datetime.now(timezone.utc)
    mandate_id = overrides.pop("mandate_id", f"UM-TEST-{crypto_utils.public_key_fingerprint(user_public)[:12]}")
    valid_from = overrides.pop("valid_from", now.isoformat())
    payload_fields = {
        "user_id": "user-42",
        "agent_id": ctx.agent_id,
        "max_per_transaction": 200000,
        "max_daily_amount": 500000,
        "currency": "INR",
        "expires_at": (now + timedelta(days=30)).isoformat(),
        "approval_reference": "test-user-consent-42",
        **overrides,
        "mandate_id": mandate_id,
        "valid_from": valid_from,
    }
    canonical = _mandate_payload_for_post({**payload_fields, "org_id": "default"})
    signature = crypto_utils.sign_with_private_key(user_private, canonical)
    r = ctx.client.post(
        "/v1/mandates",
        json={**payload_fields, "user_public_key_pem": user_public,
              "mandate_signature_b64": signature, "signing_key_id": "user-test-key"},
        headers={"X-Admin-Api-Key": _admin_key()},
    )
    assert r.status_code == 200, r.text
    return r.json()


def test_mandate_signature_roundtrip(paari_client):
    from app.mandate_signing import verify_mandate_signature
    from app.models import UserPaymentMandate

    ctx = paari_client
    user_private, user_public = _user_keypair()
    body = _signed_mandate_post(ctx, user_private, user_public)

    db = ctx.Session()
    try:
        row = db.query(UserPaymentMandate).filter_by(mandate_id=body["mandate_id"]).first()
        result = verify_mandate_signature(row)
        assert result.signature_valid, result.reasons

        # Tamper with a constraint -> verification must fail.
        original = row.max_per_transaction
        row.max_per_transaction = original + 1
        tampered = verify_mandate_signature(row)
        assert not tampered.signature_valid
        row.max_per_transaction = original
    finally:
        db.close()

    # Agent-facing view reports signature evidence.
    r = ctx.client.get(
        f"/v1/mandates/active/{ctx.agent_id}",
        headers={"Authorization": f"Bearer {ctx.session_token}",
                 "X-Paari-Proof": _proof(ctx, "GET", f"/v1/mandates/active/{ctx.agent_id}")},
    )
    assert r.status_code == 200
    assert r.json()["signature_valid"] is True
    assert r.json()["signing_key_id"] == "user-test-key"


def test_mandate_rejects_bad_signature(paari_client):
    from app import crypto_utils

    ctx = paari_client
    user_private, user_public = _user_keypair()
    now = datetime.now(timezone.utc)
    mandate_id = "UM-BADSIG-1"
    fields = {
        "user_id": "user-42", "agent_id": ctx.agent_id,
        "max_per_transaction": 200000, "max_daily_amount": 500000,
        "currency": "INR", "expires_at": (now + timedelta(days=30)).isoformat(),
        "mandate_id": mandate_id, "valid_from": now.isoformat(),
    }
    canonical = _mandate_payload_for_post({**fields, "org_id": "default"})
    # Sign DIFFERENT bytes than what will be verified -> must be rejected.
    forged = crypto_utils.sign_with_private_key(user_private, canonical.replace("200000", "999999"))
    r = ctx.client.post(
        "/v1/mandates",
        json={**fields, "user_public_key_pem": user_public, "mandate_signature_b64": forged},
        headers={"X-Admin-Api-Key": _admin_key()},
    )
    assert r.status_code == 400
    assert "signature" in r.json()["detail"]


def test_unsigned_mandate_reports_signature_none(paari_client):
    ctx = paari_client
    create_mandate(ctx)
    r = ctx.client.get(
        f"/v1/mandates/active/{ctx.agent_id}",
        headers={"Authorization": f"Bearer {ctx.session_token}",
                 "X-Paari-Proof": _proof(ctx, "GET", f"/v1/mandates/active/{ctx.agent_id}")},
    )
    assert r.status_code == 200
    assert r.json()["signature_valid"] is None
    assert r.json()["signature_b64"] is None


def test_expired_mandate_denies_even_with_valid_signature(paari_client, monkeypatch):
    """The key property: a valid signature does NOT make an expired mandate valid."""
    from app.mandate_signing import verify_mandate_signature
    from app.models import UserPaymentMandate

    monkeypatch.setenv("PAARI_MODE", "autonomous")
    ctx = paari_client
    user_private, user_public = _user_keypair()
    now = datetime.now(timezone.utc)
    body = _signed_mandate_post(
        ctx, user_private, user_public,
        valid_from=(now - timedelta(days=2)).isoformat(),
        expires_at=(now - timedelta(days=1)).isoformat(),
    )
    assert body["status"] == "active"

    db = ctx.Session()
    try:
        row = db.query(UserPaymentMandate).filter_by(mandate_id=body["mandate_id"]).first()
        # The signature itself is genuinely valid...
        assert verify_mandate_signature(row).signature_valid
    finally:
        db.close()

    # ...but governance still denies because the mandate is expired.
    body_intent = make_intent(ctx, amount=1000, suffix="expired-signed")
    assert body_intent["decision"] == "deny"
    assert any("mandate" in reason for reason in body_intent["reasons"])


def test_hourly_limit_blocks_next_payment(paari_client):
    ctx = paari_client
    create_mandate(ctx, max_per_transaction=3000, max_daily_amount=100000, max_per_hour=4000)
    one = make_intent(ctx, amount=3000, suffix="hour-1")
    assert one["decision"] == "allow"
    two = make_intent(ctx, amount=2000, suffix="hour-2")
    assert two["decision"] == "deny"
    assert any("hourly" in r for r in two["reasons"])


def _frozen_future(hours: int = 1) -> datetime:
    """A frozen 'now' safely INSIDE the mandate validity window.

    The old version of this test hardcoded datetime(2026, 9, 26, 10, 0), which
    was in the PAST relative to whenever the suite actually ran. That made
    active_mandate() filter the freshly created mandate out (valid_from <= now),
    so mandate_id resolved to None, standard mode applied no mandate at all,
    and BOTH concurrent requests were allowed - a false negative that also
    masked the lapsed-mandate and most-permissive-mandate defects. Deriving
    the instant from the real clock keeps the mandate in-window forever.
    """
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).replace(
        minute=0, second=0, microsecond=0)


def test_concurrent_spend_under_hourly_limit_serialized(paari_client):
    """Two concurrent intents that both fit individually but exceed the hourly
    budget together: the serialization gate must ensure exactly one ALLOWs."""
    from app.routers import payments as payments_mod

    ctx = paari_client
    create_mandate(ctx, max_per_transaction=3000, max_daily_amount=100000, max_per_hour=4000)

    # Freeze payments._now so the request timestamp (now captured at handler
    # entry) and the intent's created_at both use the frozen time, and so both
    # requests land in the same rolling hour. evaluate_mandate already passes
    # `now` through to hourly_spend / daily_spend.
    real_payments_now = payments_mod._now
    payments_mod._now = lambda: _frozen_future()

    barrier = threading.Barrier(2)
    results: dict[int, dict] = {}
    errors: dict[int, Exception] = {}

    def fire(tag: int, idem_suffix: str):
        try:
            barrier.wait(timeout=10)
            r = ctx.client.post(
                "/payments/intent",
                json={
                    "session_token": ctx.session_token,
                    "transaction_id": f"TXN-concurrent-{tag}",
                    "idempotency_key": f"idem-concurrent-{idem_suffix}",
                    "merchant": "TestMerchant",
                    "amount_minor_units": 3000,
                    "currency": "INR",
                    "action": "make_payment",
                    "purpose": "concurrency test",
                },
            )
            results[tag] = r.status_code, r.json() if r.status_code == 200 else {}
        except Exception as exc:
            errors[tag] = exc

    try:
        t1 = threading.Thread(target=fire, args=(1, "a"))
        t2 = threading.Thread(target=fire, args=(2, "b"))
        t1.start(); t2.start()
        t1.join(timeout=30); t2.join(timeout=30)
    finally:
        payments_mod._now = real_payments_now

    assert not errors, f"Thread errors: {errors}"
    assert len(results) == 2

    allows = [r for r in results.values() if r[1].get("decision") == "allow"]
    denies  = [r for r in results.values() if r[1].get("decision") == "deny"]
    assert len(allows) == 1, f"expected exactly 1 allow, got {len(allows)}: {results}"
    assert len(denies)  == 1, f"expected exactly 1 deny, got {len(denies)}: {results}"
    assert any("hourly" in r for r in denies[0][1].get("reasons", []))


def test_per_merchant_daily_limit(paari_client):
    ctx = paari_client
    create_mandate(ctx, max_per_transaction=5000, max_daily_amount=100000,
                   max_per_merchant_per_day=4000)
    one = make_intent(ctx, amount=3000, suffix="pm-1")
    assert one["decision"] == "allow"

    r = ctx.client.post(
        "/payments/intent",
        json={
            "session_token": ctx.session_token,
            "transaction_id": "TXN-pm-2",
            "idempotency_key": "idem-pm-2",
            "merchant": "TestMerchant",
            "amount_minor_units": 2000,
            "currency": "INR",
            "action": "make_payment",
            "purpose": "phase5 test",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "deny"
    assert any("merchant" in reason for reason in body["reasons"])


def test_per_category_daily_limit(paari_client):
    ctx = paari_client
    create_mandate(ctx, max_per_transaction=5000, max_daily_amount=100000,
                   max_category_per_day=3000)

    def cat_intent(suffix, amount):
        return ctx.client.post(
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
                "merchant_category": "grocery",
            },
        ).json()

    one = cat_intent("cat-1", 2000)
    assert one["decision"] == "allow", one["reasons"]
    two = cat_intent("cat-2", 2000)
    assert two["decision"] == "deny"
    assert any("category" in reason for reason in two["reasons"])


def test_category_budget_fails_closed_without_category(paari_client):
    ctx = paari_client
    create_mandate(ctx, max_per_transaction=5000, max_daily_amount=100000,
                   max_category_per_day=3000)
    body = make_intent(ctx, amount=1000, suffix="cat-nocat")
    assert body["decision"] == "deny"
    assert any("category" in reason for reason in body["reasons"])


def test_llm_causal_identifiers_flow_to_intent_and_audit(paari_client):
    ctx = paari_client
    create_mandate(ctx)
    r = ctx.client.post(
        "/payments/intent",
        json={
            "session_token": ctx.session_token,
            "transaction_id": "TXN-llm-audit-1",
            "idempotency_key": "idem-llm-audit-1",
            "merchant": "TestMerchant",
            "amount_minor_units": 1000,
            "currency": "INR",
            "action": "make_payment",
            "purpose": "causal audit test",
            "llm_run_id": "RUN-123",
            "llm_model": "test-model",
            "llm_tool_call_id": "call_456",
            "llm_tool_name": "propose_payment",
        },
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "allow"

    from app.models import PaymentIntent, AuditEvent
    db = ctx.Session()
    try:
        intent = db.query(PaymentIntent).filter_by(transaction_id="TXN-llm-audit-1").first()
        assert intent.llm_run_id == "RUN-123"
        assert intent.llm_model == "test-model"
        assert intent.llm_tool_call_id == "call_456"

        events = (
            db.query(AuditEvent)
            .filter_by(transaction_id="TXN-llm-audit-1")
            .order_by(AuditEvent.id.asc())
            .all()
        )
        kinds = [e.kind for e in events]
        assert "llm_tool_call" in kinds
        tool_event = next(e for e in events if e.kind == "llm_tool_call")
        assert tool_event.detail["llm_run_id"] == "RUN-123"
        assert tool_event.detail["llm_tool_call_id"] == "call_456"
        minted = next(e for e in events if e.kind == "authorization_minted")
        assert minted.detail["llm_model"] == "test-model"

        from app.audit import verify_chain
        assert verify_chain(db, "TXN-llm-audit-1")
    finally:
        db.close()


def test_autonomous_mode_requires_mandate(paari_client, monkeypatch):
    monkeypatch.setenv("PAARI_MODE", "autonomous")
    ctx = paari_client
    body = make_intent(ctx, amount=1000, suffix="auto-nomandate")
    assert body["decision"] == "deny"
    assert any("user payment mandate" in reason for reason in body["reasons"])


def test_autonomous_mode_allows_with_mandate(paari_client, monkeypatch):
    monkeypatch.setenv("PAARI_MODE", "autonomous")
    ctx = paari_client
    create_mandate(ctx, max_per_transaction=5000, max_daily_amount=10000)
    body = make_intent(ctx, amount=1000, suffix="auto-with-mandate")
    assert body["decision"] == "allow"
    assert body["mandate_id"]


def test_agentic_provider_is_not_configured():
    from app.providers.agentic import NotConfiguredAgenticProvider, AdapterStatus

    adapter = NotConfiguredAgenticProvider()
    assert adapter.status() is AdapterStatus.NOT_CONFIGURED
    assert adapter.supports_autonomous_settlement() is False
    with pytest.raises(NotImplementedError):
        adapter.authorize_payment(
            authorization_id="AUTH-1", provider_mandate_ref="m-1",
            amount_minor_units=100, currency="INR",
            merchant_reference="shop", idempotency_key="AUTH-1",
        )
    with pytest.raises(NotImplementedError):
        adapter.capture_payment(
            provider_payment_ref="pay_1", amount_minor_units=100,
            currency="INR", idempotency_key="x",
        )


def test_cannot_bind_provider_mandate_to_expired_mandate(paari_client):
    ctx = paari_client
    now = datetime.now(timezone.utc)
    body = create_mandate(
        ctx,
        valid_from=(now - timedelta(days=2)).isoformat(),
        expires_at=(now - timedelta(days=1)).isoformat(),
    )
    r = ctx.client.post(
        f"/v1/mandates/{body['mandate_id']}/provider-binding",
        json={"provider": "razorpay", "provider_mandate_ref": "mandate_x",
              "currency": "INR", "max_amount_minor_units": 1000},
        headers={"X-Admin-Api-Key": _admin_key()},
    )
    assert r.status_code == 409  # mandate is outside its validity window
