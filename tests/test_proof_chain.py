from tests.conftest import make_intent
from app.proof_bundle import collect_proof_bundle


def test_each_stage_output_links_to_previous_stage(paari_client):
    from app import crypto_utils, security
    ctx = paari_client
    intent = make_intent(ctx, amount=100)
    db = ctx.Session()
    try:
        bundle = collect_proof_bundle(db, intent["transaction_id"])
    finally:
        db.close()
    a = bundle["artifacts"]

    # --- Crypto-verified links (fail if collector mis-copies) ---

    # 1. Agent-card signature must verify against Paari's public key (stage 6 verifies stage 5)
    card = a["agent_card"]
    card_fields = {k: v for k, v in card.items() if k not in ("card_signature_b64", "paari_public_key_pem")}
    assert security.verify_agent_card(card_fields, card["card_signature_b64"]) is True
    # Independent fingerprint check: delegation was bound to the agent's real key
    fp_from_pem = crypto_utils.public_key_fingerprint(a["agent_identity"]["public_key_pem"])
    assert a["delegation"]["agent_public_key_fingerprint"] == fp_from_pem
    assert card["public_key"] == a["agent_identity"]["public_key_pem"]

    # 2. Credential was issued for this agent (stage 7 verifies stage 5) — decode JWT
    import jwt

    cred_jwt = db_cred_jwt = None
    # Re-fetch the raw JWT from DB to prove bundle's credential_id matches real JWT claims
    from sqlalchemy.orm import sessionmaker as _SM  # local import to avoid fixture coupling

    # Use the same session pattern as the bundle collector: join via agent_pk
    db2 = ctx.Session()
    try:
        import app.models as models

        agent_row = db2.query(models.Agent).filter_by(agent_id=a["agent_identity"]["agent_id"]).one()
        cred_row = (
            db2.query(models.Credential)
            .filter_by(agent_pk=agent_row.id)
            .order_by(models.Credential.issued_at.desc())
            .first()
        )
        assert cred_row is not None
        assert cred_row.credential_id == a["credential"]["credential_id"]
        assert cred_row.credential_id == card["credential_id"]
        # JWT typ must be credential, not fabricated
        claims = jwt.decode(
            cred_row.signed_jwt,
            security.paari_public_key_pem(),
            algorithms=["EdDSA"],
            options={"verify_signature": True, "verify_aud": False, "verify_iss": False},
        )
        assert claims["typ"] == "paari_credential"
        assert claims["sub"] == a["agent_identity"]["agent_id"]
    finally:
        db2.close()

    # 3. Governance decision carries the merchant that was actually authorized (WHAT + WHICH merchant)
    assert a["governance_decision"]["merchant"] == "TestMerchant"
    assert a["governance_decision"]["merchant"] == a["bounded_authorization"]["merchant"]
    assert a["governance_decision"]["intent_id"] == a["payment_intent"]["intent_id"]
    assert a["bounded_authorization"]["transaction_id"] == intent["transaction_id"]

    # 4. Audit hash chain + event linkage (stage 14 verifies all prior stages)
    events = a["audit_record"]["events"]
    assert events[0]["event_type"] == "intent_decided"
    for prev, cur in zip(events, events[1:]):
        assert cur["prev_hash"] == prev["event_hash"]

    # 5. Authentication is not hardcoded — bundle must report a real nonce evidence
    auth = a["authentication"]
    assert auth["authenticated"] is True
    assert auth["nonce_id"] is not None
    assert auth["credential_id"] == a["credential"]["credential_id"]


def test_tampered_delegation_fails_registration(paari_client):
    import uuid
    from datetime import datetime, timedelta, timezone
    from app import crypto_utils
    from app.protocol.envelope import sign_envelope
    ctx = paari_client
    agent_private, agent_public = crypto_utils.generate_agent_keypair()
    now = datetime.now(timezone.utc)
    delegation = {
        "delegation_id": str(uuid.uuid4()),
        "parent_id": ctx.parent_id,
        "agent_public_key_fingerprint": crypto_utils.public_key_fingerprint(agent_public),
        "granted_capabilities": ["make_payment"],
        "payment_limit_minor_units": 500000,
        "currency": "INR",
        "issued_at": int(now.timestamp()),
        "expires_at": int((now + timedelta(days=30)).timestamp()),
    }
    sig = crypto_utils.sign_with_private_key(
        ctx.parent_private, crypto_utils.canonical_json(delegation))
    delegation["payment_limit_minor_units"] = 999999999
    payload = {"name": "Tampered Agent", "agent_type": "shopping_assistant",
               "purpose": "chain test", "public_key_pem": agent_public,
               "delegation": delegation, "delegation_signature_b64": sig}
    envelope = sign_envelope(agent_private, "agent.register",
                             {"sender": crypto_utils.public_key_fingerprint(agent_public),
                              "receiver": "paari"}, payload, ttl_seconds=300)
    r = ctx.client.post("/v1/agents/register", json={"envelope": envelope})
    assert r.status_code == 401, r.text
    assert r.json()["detail"] == "Delegation signature verification failed"
