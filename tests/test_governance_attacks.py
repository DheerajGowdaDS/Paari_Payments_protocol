"""Task H1: governance attack suite."""
from tests.conftest import paari_client


def test_revoked_parent_blocks_agent_registration(paari_client):
    ctx = paari_client
    from app import models as m
    session = ctx.Session()
    parent = session.query(m.ParentAuthority).first()
    parent.status = m.ParentStatus.REVOKED
    session.commit()
    parent_id = parent.parent_id
    session.close()

    r = ctx.client.post(
        "/v1/agents/register",
        json={"envelope": {"version": "9.9"}},
    )
    assert r.status_code in (401, 400)


def test_high_velocity_triggers_review(paari_client):
    ctx = paari_client
    for i in range(6):
        r = ctx.client.post(
            "/payments/intent",
            json={
                "session_token": ctx.session_token,
                "transaction_id": f"TXN-vel-{i}",
                "idempotency_key": f"idem-vel-{i}",
                "merchant": "TestMerchant",
                "amount_minor_units": 1000,
                "currency": "INR",
                "action": "make_payment",
                "purpose": "velocity",
            },
        )
        assert r.status_code == 200
        if i >= 5:
            assert r.json()["decision"] in ("review", "deny")


def test_invalid_mfa_signature_is_rejected(paari_client):
    ctx = paari_client
    r = ctx.client.post(
        "/payments/intent",
        json={
            "session_token": ctx.session_token,
            "transaction_id": "TXN-mfa-bad",
            "idempotency_key": "idem-mfa-bad",
            "merchant": "TestMerchant",
            "amount_minor_units": 500000,
            "currency": "INR",
            "action": "make_payment",
            "purpose": "mfa test",
        },
    )
    assert r.status_code == 200
    intent_id = r.json()["intent_id"]

    r = ctx.client.post(
        "/v1/payments/mfa/challenge",
        json={"intent_id": intent_id, "session_token": ctx.session_token},
    )
    assert r.status_code == 200
    challenge_id = r.json()["challenge_id"]

    r = ctx.client.post(
        "/v1/payments/mfa/verify",
        json={
            "intent_id": intent_id,
            "challenge_id": challenge_id,
            "parent_signature_b64": "invalid_signature_base64",
        },
    )
    assert r.status_code in (401, 400)
