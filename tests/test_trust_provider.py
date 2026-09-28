"""Task C1: trust provider wiring — SUSPENDED state and provider enforcement."""
from tests.conftest import paari_client


def test_suspended_parent_rejected_via_trust_provider(paari_client):
    ctx = paari_client
    from app import models as m
    session = ctx.Session()
    parent = session.query(m.ParentAuthority).first()
    assert parent is not None
    parent.status = m.ParentStatus.SUSPENDED
    session.commit()
    session.close()

    r = ctx.client.post(
        "/payments/intent",
        json={
            "session_token": ctx.session_token,
            "transaction_id": "TXN-trust-suspend",
            "idempotency_key": "idem-trust-suspend",
            "merchant": "TestMerchant",
            "amount_minor_units": 1000,
            "currency": "INR",
            "action": "make_payment",
            "purpose": "trust suspend",
        },
    )
    assert r.status_code == 401
    body = r.json()
    assert "code" in body
    assert body["code"] == "PARENT_REVOKED"
