"""Paari v2 user-mandate governance tests.

The governance tests exercise both the mandate layer and the provider-native
autonomous adapter boundary. The reference provider used by the autonomous E2E
is protocol-only and never masquerades as a real payment network.
"""
from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import make_intent


def _proof(ctx, method: str, path: str) -> str:
    from sdk.paari_agent.crypto import build_request_proof
    return build_request_proof(
        ctx.agent_private, agent_id=ctx.agent_id, access_token=ctx.session_token,
        method=method, path=path,
    )


def _admin_key():
    from app.security import _ADMIN_API_KEY
    return _ADMIN_API_KEY


def create_mandate(ctx, **overrides):
    now = datetime.now(timezone.utc)
    payload = {
        "user_id": "user-42",
        "agent_id": ctx.agent_id,
        "max_per_transaction": 200000,
        "max_daily_amount": 500000,
        "currency": "INR",
        "expires_at": (now + timedelta(days=30)).isoformat(),
        "approval_reference": "test-user-consent-42",
    }
    payload.update(overrides)
    r = ctx.client.post("/v1/mandates", json=payload, headers={"X-Admin-Api-Key": _admin_key()})
    assert r.status_code == 200, r.text
    return r.json()


def test_mandate_can_be_created_and_read_by_agent(paari_client):
    ctx = paari_client
    body = create_mandate(ctx)
    assert body["agent_id"] == ctx.agent_id
    assert body["status"] == "active"
    assert body["daily_remaining"] == 500000

    from sdk.paari_agent.crypto import build_request_proof
    path = f"/v1/mandates/active/{ctx.agent_id}"
    proof = build_request_proof(
        ctx.agent_private, agent_id=ctx.agent_id, access_token=ctx.session_token,
        method="GET", path=path,
    )
    r = ctx.client.get(path, headers={
        "Authorization": f"Bearer {ctx.session_token}",
        "X-Paari-Proof": proof,
    })
    assert r.status_code == 200, r.text
    assert r.json()["mandate_id"] == body["mandate_id"]


def test_required_user_mandate_denies_without_one(paari_client, monkeypatch):
    monkeypatch.setenv("PAARI_REQUIRE_USER_MANDATE", "1")
    ctx = paari_client
    body = make_intent(ctx, amount=1000, suffix="mandate-required-no-mandate")
    assert body["decision"] == "deny"
    assert any("user payment mandate" in reason for reason in body["reasons"])


def test_mandate_limit_is_enforced_before_bounded_authorization(paari_client, monkeypatch):
    monkeypatch.setenv("PAARI_REQUIRE_USER_MANDATE", "1")
    ctx = paari_client
    create_mandate(ctx, max_per_transaction=1000, max_daily_amount=5000)
    body = make_intent(ctx, amount=1001, suffix="mandate-per-tx")
    assert body["decision"] == "deny"
    assert any("user mandate per-transaction limit" in reason for reason in body["reasons"])
    assert body["authorization"] is None


def test_mandate_review_threshold_routes_to_review(paari_client, monkeypatch):
    monkeypatch.setenv("PAARI_REQUIRE_USER_MANDATE", "1")
    ctx = paari_client
    create_mandate(ctx, max_per_transaction=5000, max_daily_amount=10000, require_review_above=3000)
    body = make_intent(ctx, amount=3001, suffix="mandate-review")
    assert body["decision"] == "review"
    assert body["mandate_id"]
    assert body["authorization"] is None


def test_mandate_replays_are_bounded_by_daily_budget(paari_client, monkeypatch):
    monkeypatch.setenv("PAARI_REQUIRE_USER_MANDATE", "1")
    ctx = paari_client
    create_mandate(ctx, max_per_transaction=3000, max_daily_amount=5000)
    one = make_intent(ctx, amount=3000, suffix="daily-1")
    assert one["decision"] == "allow"
    two = make_intent(ctx, amount=2000, suffix="daily-2")
    assert two["decision"] == "allow"
    three = make_intent(ctx, amount=1, suffix="daily-3")
    assert three["decision"] == "deny"
    assert any("remaining daily mandate budget" in reason for reason in three["reasons"])


def test_revoked_mandate_blocks_future_intent(paari_client, monkeypatch):
    monkeypatch.setenv("PAARI_REQUIRE_USER_MANDATE", "1")
    ctx = paari_client
    mandate = create_mandate(ctx, max_per_transaction=5000, max_daily_amount=10000)
    revoke = ctx.client.post(
        f"/v1/mandates/{mandate['mandate_id']}/revoke",
        json={"reason": "user stopped autonomous payments"},
        headers={"X-Admin-Api-Key": _admin_key()},
    )
    assert revoke.status_code == 200, revoke.text
    assert revoke.json()["status"] == "revoked"
    body = make_intent(ctx, amount=1000, suffix="mandate-revoked")
    assert body["decision"] == "deny"


def test_active_mandate_is_carried_into_bounded_authorization(paari_client):
    ctx = paari_client
    mandate = create_mandate(ctx, max_per_transaction=5000, max_daily_amount=10000)
    body = make_intent(ctx, amount=1000, suffix="mandate-carried")
    assert body["decision"] == "allow"
    assert body["mandate_id"] == mandate["mandate_id"]
    assert body["authorization"]["mandate_id"] == mandate["mandate_id"]


def test_provider_binding_never_accepts_raw_card_data(paari_client):
    ctx = paari_client
    mandate = create_mandate(ctx)
    r = ctx.client.post(
        f"/v1/mandates/{mandate['mandate_id']}/provider-binding",
        json={
            "provider": "razorpay",
            "provider_mandate_ref": "mandate_test_123",
            "currency": "INR",
            "max_amount_minor_units": 100000,
        },
        headers={"X-Admin-Api-Key": _admin_key()},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "card_number" not in body
    assert "cvv" not in body
    assert body["provider_mandate_ref"] == "mandate_test_123"


def test_provider_binding_readable_via_get(paari_client):
    ctx = paari_client
    mandate = create_mandate(ctx)
    create_r = ctx.client.post(
        f"/v1/mandates/{mandate['mandate_id']}/provider-binding",
        json={
            "provider": "razorpay",
            "provider_mandate_ref": "mandate_test_456",
            "currency": "INR",
            "max_amount_minor_units": 100000,
        },
        headers={"X-Admin-Api-Key": _admin_key()},
    )
    assert create_r.status_code == 200, create_r.text
    binding_id = create_r.json()["binding_id"]
    session_token = ctx.session_token
    proof = _proof(ctx, "GET", f"/v1/mandates/{mandate['mandate_id']}/provider-binding")
    r = ctx.client.get(
        f"/v1/mandates/{mandate['mandate_id']}/provider-binding",
        headers={"Authorization": f"Bearer {session_token}", "X-Paari-Proof": proof},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["binding_id"] == binding_id
    assert body["provider_mandate_ref"] == "mandate_test_456"
    assert body["status"] == "active"


def test_provider_binding_get_returns_404_when_missing(paari_client):
    ctx = paari_client
    mandate = create_mandate(ctx)
    session_token = ctx.session_token
    proof = _proof(ctx, "GET", f"/v1/mandates/{mandate['mandate_id']}/provider-binding")
    r = ctx.client.get(
        f"/v1/mandates/{mandate['mandate_id']}/provider-binding",
        headers={"Authorization": f"Bearer {session_token}", "X-Paari-Proof": proof},
    )
    assert r.status_code == 404
