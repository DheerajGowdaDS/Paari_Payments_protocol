"""Phase 8 adversarial tests: prove the protocol fails closed under abuse."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import make_intent


def _request_proof(ctx, method: str, path: str, token: str | None = None):
    from app.security import encode_request_proof
    token = token or ctx.session_token
    return encode_request_proof(ctx.agent_private, method=method, path=path,
                                access_token=token, agent_id=ctx.agent_id, jti=str(uuid.uuid4()))


def test_over_limit_is_denied_before_authorization(paari_client):
    ctx = paari_client
    body = make_intent(ctx, amount=500001, suffix="over-limit")
    assert body["decision"] == "deny"
    assert "exceeds delegated limit" in " ".join(body["reasons"])


def test_wrong_currency_is_denied(paari_client, monkeypatch):
    monkeypatch.setenv("PAARI_REQUIRE_REQUEST_PROOF", "1")
    ctx = paari_client
    r = ctx.client.post("/v1/payments/intent", json={
        "agent_id": ctx.agent_id,
        "transaction_id": "TX-wrong-currency",
        "idempotency_key": "idem-wrong-currency",
        "merchant": "TestMerchant",
        "amount_minor_units": 100,
        "currency": "USD",
        "action": "make_payment",
        "purpose": "attack",
    }, headers={
        "Authorization": f"Bearer {ctx.session_token}",
        "X-Paari-Proof": _request_proof(ctx, "POST", "/v1/payments/intent"),
    })
    assert r.status_code == 200
    assert r.json()["decision"] == "deny"


def test_replayed_request_proof_is_rejected(paari_client, monkeypatch):
    monkeypatch.setenv("PAARI_REQUIRE_REQUEST_PROOF", "1")
    ctx = paari_client
    proof = _request_proof(ctx, "POST", "/v1/payments/intent")
    headers = {"Authorization": f"Bearer {ctx.session_token}", "X-Paari-Proof": proof}
    first = ctx.client.post("/v1/payments/intent", json={
        "agent_id": ctx.agent_id,
        "transaction_id": "TX-proof-a", "idempotency_key": "idem-proof-a",
        "merchant": "TestMerchant", "amount_minor_units": 100, "currency": "INR",
        "action": "make_payment", "purpose": "proof"}, headers=headers)
    assert first.status_code == 200
    second = ctx.client.post("/v1/payments/intent", json={
        "agent_id": ctx.agent_id,
        "transaction_id": "TX-proof-b", "idempotency_key": "idem-proof-b",
        "merchant": "TestMerchant", "amount_minor_units": 100, "currency": "INR",
        "action": "make_payment", "purpose": "replay"}, headers=headers)
    assert second.status_code == 401

def test_agent_id_mismatch_is_denied(paari_client, monkeypatch):
    monkeypatch.setenv("PAARI_REQUIRE_REQUEST_PROOF", "1")
    ctx = paari_client
    r = ctx.client.post("/v1/payments/intent", json={
        "agent_id": "not-this-agent", "transaction_id": "TX-agent-mismatch",
        "idempotency_key": "idem-agent-mismatch", "merchant": "TestMerchant",
        "amount_minor_units": 100, "currency": "INR", "action": "make_payment"},
        headers={"Authorization": f"Bearer {ctx.session_token}",
                 "X-Paari-Proof": _request_proof(ctx, "POST", "/v1/payments/intent")})
    assert r.status_code == 403


def test_request_proof_htm_binding_rejects_wrong_method(paari_client, monkeypatch):
    """A proof minted for GET must not be accepted on POST."""
    monkeypatch.setenv("PAARI_REQUIRE_REQUEST_PROOF", "1")
    ctx = paari_client
    proof = _request_proof(ctx, "GET", "/v1/payments/intent")
    r = ctx.client.post("/v1/payments/intent", json={
        "agent_id": ctx.agent_id,
        "transaction_id": "TX-htm-mismatch", "idempotency_key": "idem-htm-mismatch",
        "merchant": "TestMerchant", "amount_minor_units": 100, "currency": "INR",
        "action": "make_payment", "purpose": "htm-binding-test",
    }, headers={
        "Authorization": f"Bearer {ctx.session_token}",
        "X-Paari-Proof": proof,
    })
    assert r.status_code == 401


def test_request_proof_htu_binding_rejects_wrong_path(paari_client, monkeypatch):
    """A proof minted for one path must not be accepted on another."""
    monkeypatch.setenv("PAARI_REQUIRE_REQUEST_PROOF", "1")
    ctx = paari_client
    proof = _request_proof(ctx, "POST", "/v1/payments/mfa/challenge")
    r = ctx.client.post("/v1/payments/intent", json={
        "agent_id": ctx.agent_id,
        "transaction_id": "TX-htu-mismatch", "idempotency_key": "idem-htu-mismatch",
        "merchant": "TestMerchant", "amount_minor_units": 100, "currency": "INR",
        "action": "make_payment", "purpose": "htu-binding-test",
    }, headers={
        "Authorization": f"Bearer {ctx.session_token}",
        "X-Paari-Proof": proof,
    })
    assert r.status_code == 401


def test_payment_schema_has_identity_and_limits():
    schema = json.loads(open("schemas/paari-payment-intent.v1.schema.json", encoding="utf-8").read())
    assert schema["properties"]["amount_minor_units"]["minimum"] == 1
    assert schema["properties"]["currency"]["pattern"] == "^[A-Z]{3}$"
    assert "agent_id" in schema["properties"]


def test_v1_audit_is_readable_with_a_signed_proof(paari_client, monkeypatch):
    """The settlement proof polls `/v1/audit`, so that call must work.

    Tightening this route to require a sender-constrained proof (the
    cross-tenant audit fix) was correct, but the same requirement was applied to
    `/v1/reconcile` in the proof script and *not* to its two audit calls. Every
    poll then returned 401 while the loop reduced the response to
    `.json().get("events", [])` - so "I am not allowed to look" was reported as
    "the provider never settled", about a payment that had settled within
    seconds. A partial security fix plus a poller that cannot tell absence from
    ignorance produces a confident false negative.
    """
    import app.routers.payments as payments_router

    ctx = paari_client

    class Provider:
        key_id = "rzp_key_audit"

        def create_payment(self, authorization_id, amount_minor_units, currency, notes):
            return {"id": "order_audit_read", "receipt": authorization_id,
                    "amount": amount_minor_units, "currency": currency, "status": "created"}

    monkeypatch.setattr(payments_router, "get_provider", lambda: Provider())
    body = make_intent(ctx, suffix="audit-read")
    tx = body["transaction_id"]
    auth_id = body["authorization"]["authorization_id"]
    r = ctx.client.post(f"/payments/authorizations/{auth_id}/consume",
                        json={"session_token": ctx.session_token})
    assert r.status_code == 200, r.text

    path = f"/v1/audit/{tx}"
    # Proof enforcement is conditional on registration surface: an agent onboarded
    # through /v1/agents/register carries protocol_version "1.0" and always needs a
    # proof, while a legacy /agents/register agent does not unless
    # PAARI_REQUIRE_REQUEST_PROOF is set. The proof script uses /v1, which is why it
    # was rejected. Assert under the explicitly enforced regime so this test says
    # something regardless of which surface the fixture used.
    monkeypatch.setenv("PAARI_REQUIRE_REQUEST_PROOF", "1")
    with_proof = ctx.client.get(path, headers={
        "Authorization": f"Bearer {ctx.session_token}",
        "X-Paari-Proof": _request_proof(ctx, "GET", path)})
    assert with_proof.status_code == 200, (
        f"a correctly signed audit read was refused: {with_proof.status_code} "
        f"{with_proof.text[:200]}")
    kinds = [e["kind"] for e in with_proof.json()["events"]]
    assert "order_submitted" in kinds, kinds

    without = ctx.client.get(path, headers={"Authorization": f"Bearer {ctx.session_token}"})
    assert without.status_code == 401, (
        "audit trail readable without a proof - the proof requirement is not enforced")
