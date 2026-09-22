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


def test_payment_schema_has_identity_and_limits():
    schema = json.loads(open("schemas/paari-payment-intent.v1.schema.json", encoding="utf-8").read())
    assert schema["properties"]["amount_minor_units"]["minimum"] == 1
    assert schema["properties"]["currency"]["pattern"] == "^[A-Z]{3}$"
    assert "agent_id" in schema["properties"]
