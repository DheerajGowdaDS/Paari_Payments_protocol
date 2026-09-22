"""Phase 8: external-agent SDK conformance tests."""
from __future__ import annotations

import sys
from pathlib import Path
import uuid
from datetime import datetime, timedelta, timezone

import pytest

SDK_ROOT = Path(__file__).resolve().parents[1] / "sdk"
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

from paari_agent import PaariAgentClient, generate_keypair, fingerprint, sign_delegation
from paari_agent.crypto import verify_paari_card


def test_sdk_has_no_server_app_dependency():
    for py_file in (SDK_ROOT / "paari_agent").glob("*.py"):
        source = py_file.read_text(encoding="utf-8")
        assert "from app" not in source and "import app" not in source


def test_sdk_foreign_agent_registration_and_auth(paari_client):
    ctx = paari_client
    private, public = generate_keypair()
    now = datetime.now(timezone.utc)
    delegation = {
        "delegation_id": str(uuid.uuid4()),
        "parent_id": ctx.parent_id,
        "agent_public_key_fingerprint": fingerprint(public),
        "granted_capabilities": ["make_payment"],
        "payment_limit_minor_units": 500000,
        "currency": "INR",
        "issued_at": int(now.timestamp()),
        "expires_at": int((now + timedelta(days=7)).timestamp()),
    }
    sig = sign_delegation(ctx.parent_private, delegation)
    client = PaariAgentClient("http://test", private, public, http=ctx.client)
    discovered = client.discover()
    assert discovered["protocol_version"] == "1.0"
    result = client.register(name="SDK Foreign Agent", agent_type="assistant", purpose="conformance",
                             delegation=delegation, delegation_signature_b64=sig)
    assert verify_paari_card(result["agent_card"])
    client.authenticate()
    body = client.payment_intent(transaction_id="TX-sdk-conformance", idempotency_key="idem-sdk-conformance",
                                 merchant="TestMerchant", amount_minor_units=100, currency="INR")
    assert body["decision"] == "allow"


def test_sdk_card_tamper_is_detected(paari_client):
    ctx = paari_client
    private, public = generate_keypair()
    now = datetime.now(timezone.utc)
    delegation = {
        "delegation_id": str(uuid.uuid4()), "parent_id": ctx.parent_id,
        "agent_public_key_fingerprint": fingerprint(public), "granted_capabilities": ["make_payment"],
        "payment_limit_minor_units": 500000, "currency": "INR", "issued_at": int(now.timestamp()),
        "expires_at": int((now + timedelta(days=7)).timestamp())}
    client = PaariAgentClient("http://test", private, public, http=ctx.client)
    result = client.register(name="SDK Card Agent", agent_type="assistant", purpose="card",
                             delegation=delegation, delegation_signature_b64=sign_delegation(ctx.parent_private, delegation))
    card = dict(result["agent_card"])
    card["limits"] = {"max_amount": 1, "currency": "INR"}
    assert not verify_paari_card(card)


def test_sdk_v1_session_must_send_proof_for_proof_bundle(paari_client):
    """A v1-onboarded agent gets the bundle with a proof and is refused without one."""
    ctx = paari_client
    private, public = generate_keypair()
    now = datetime.now(timezone.utc)
    delegation = {
        "delegation_id": str(uuid.uuid4()), "parent_id": ctx.parent_id,
        "agent_public_key_fingerprint": fingerprint(public),
        "granted_capabilities": ["make_payment"],
        "payment_limit_minor_units": 500000, "currency": "INR",
        "issued_at": int(now.timestamp()),
        "expires_at": int((now + timedelta(days=7)).timestamp())}
    client = PaariAgentClient("http://test", private, public, http=ctx.client)
    client.register(name="SDK Proof Agent", agent_type="assistant", purpose="bundle",
                    delegation=delegation,
                    delegation_signature_b64=sign_delegation(ctx.parent_private, delegation))
    client.authenticate()
    tx = "TX-sdk-proof-bundle"
    body = client.payment_intent(transaction_id=tx, idempotency_key="idem-" + tx,
                                 merchant="TestMerchant", amount_minor_units=100,
                                 currency="INR")
    assert body["decision"] == "allow"

    bundle = client.proof_bundle(tx)
    assert bundle["transaction_id"] == tx
    assert bundle["artifacts"]["governance_decision"]["merchant"] == "TestMerchant"

    # Same session, no X-Paari-Proof: must be refused for a protocol-v1 session.
    raw = ctx.client.get(f"/v1/proof/{tx}",
                         headers={"Authorization": f"Bearer {client.session_token}"})
    assert raw.status_code == 401, raw.text
    assert raw.json()["code"] == "PROOF_REPLAYED"
