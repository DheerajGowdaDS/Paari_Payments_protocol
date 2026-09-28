"""Task 5: protocol envelope + v1 onboarding + Agent Card."""
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest


def _delegation_for(client_ctx, agent_public_pem, parent_private_pem, limit=500000):
    from app import crypto_utils
    now = datetime.now(timezone.utc)
    delegation = {
        "delegation_id": str(uuid.uuid4()),
        "parent_id": client_ctx.parent_id,
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


def test_v1_register_ignores_requested_permissions(paari_client):
    from app import crypto_utils
    from app.protocol.envelope import sign_envelope
    ctx = paari_client
    agent_private, agent_public = crypto_utils.generate_agent_keypair()
    delegation, sig = _delegation_for(ctx, agent_public, ctx.parent_private)
    payload = {
        "name": "V1 Agent",
        "agent_type": "shopping_assistant",
        "purpose": "v1 test",
        "public_key_pem": agent_public,
        "delegation": delegation,
        "delegation_signature_b64": sig,
        # Attacker asks for more than the delegation grants - must be ignored.
        "requested_permissions": {"payment_limit_minor_units": 99999999,
                                  "capabilities": ["make_payment", "print_money"]},
    }
    envelope = sign_envelope(agent_private, "agent.register", {"sender": crypto_utils.public_key_fingerprint(agent_public), "receiver": "paari"}, payload, ttl_seconds=300)
    r = ctx.client.post("/v1/agents/register", json={"envelope": envelope})
    assert r.status_code == 200, r.text
    card = r.json()["agent_card"]
    assert card["limits"]["max_amount"] == 500000
    assert card["capabilities"] == ["payment.create"]
    assert card["protocol_version"] == "1.0"
    assert "credential_jwt" in r.json()


def test_envelope_rejects_wrong_key():
    from app import crypto_utils
    from app.protocol.envelope import sign_envelope, verify_envelope
    good_private, _ = crypto_utils.generate_agent_keypair()
    _, wrong_public = crypto_utils.generate_agent_keypair()
    envelope = sign_envelope(good_private, "payment.intent", {}, {"amount": 1}, ttl_seconds=300)
    assert verify_envelope(wrong_public, envelope) is False


def test_envelope_rejects_expired():
    from app import crypto_utils
    from app.protocol.envelope import sign_envelope, verify_envelope
    private, public = crypto_utils.generate_agent_keypair()
    envelope = sign_envelope(private, "payment.intent", {}, {"amount": 1}, ttl_seconds=-1)
    assert verify_envelope(public, envelope) is False


def test_v1_card_is_discovery_only(paari_client):
    from app import crypto_utils
    from app.protocol.envelope import sign_envelope
    ctx = paari_client
    agent_private, agent_public = crypto_utils.generate_agent_keypair()
    delegation, sig = _delegation_for(ctx, agent_public, ctx.parent_private)
    payload = {"name": "V1 Card Agent", "agent_type": "shopping_assistant",
               "purpose": "v1 card test", "public_key_pem": agent_public,
               "delegation": delegation, "delegation_signature_b64": sig}
    envelope = sign_envelope(agent_private, "agent.register", {"sender": crypto_utils.public_key_fingerprint(agent_public), "receiver": "paari"}, payload, ttl_seconds=300)
    agent_id = ctx.client.post("/v1/agents/register", json={"envelope": envelope}).json()["agent_card"]["agent_id"]
    r = ctx.client.get(f"/v1/agents/{agent_id}/card")
    assert r.status_code == 200, r.text
    card = r.json()
    assert card["issuer"] == "paari"
    assert card["agent_id"] == agent_id
    assert "credential_jwt" not in card and card["card_signature_b64"]
    from app import security
    signed_fields = {k: card[k] for k in ["protocol", "protocol_version", "issuer", "agent_id", "name", "agent_type", "parent_id", "status", "public_key", "capabilities", "limits", "credential_id", "expires_at", "endpoints"]}
    assert security.verify_agent_card(signed_fields, card["card_signature_b64"])


def test_well_known_discovery_and_v1_surface(paari_client):
    r = paari_client.client.get("/.well-known/paari")
    assert r.status_code == 200, r.text
    doc = r.json()
    assert doc["protocol"] == "paari"
    assert doc["protocol_version"] == "1.0"
    assert doc["payment"]["intent"].endswith("/v1/payments/intent")
    assert doc["payment"]["mfa_challenge"].endswith("/v1/payments/mfa/challenge")
    assert doc["payment"]["mfa_verify"].endswith("/v1/payments/mfa/verify")
    assert doc["payment"]["consume"].endswith("/v1/payments/authorizations/{authorization_id}/consume")


def test_v1_payment_schema_exposes_legacy_body_token_only_for_compatibility():
    import json
    from pathlib import Path
    schema = json.loads(Path("schemas/paari-payment-intent.v1.schema.json").read_text())
    assert "session_token" in schema["properties"]
    assert "session_token" not in schema["required"]

