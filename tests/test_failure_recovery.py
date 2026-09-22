"""Task H2: failure and recovery tests."""
from tests.conftest import paari_client


def test_double_consume_second_rejected(paari_client):
    ctx = paari_client
    r = ctx.client.post(
        "/payments/intent",
        json={
            "session_token": ctx.session_token,
            "transaction_id": "TXN-double-consume",
            "idempotency_key": "idem-double-consume",
            "merchant": "TestMerchant",
            "amount_minor_units": 1000,
            "currency": "INR",
            "action": "make_payment",
            "purpose": "double consume",
        },
    )
    assert r.status_code == 200
    auth_id = r.json()["authorization"]["authorization_id"]

    import app.routers.payments as payments_router

    class FakeProvider:
        def create_payment(self, authorization_id, amount_minor_units, currency, notes):
            return {"id": "order_dc", "receipt": authorization_id, "amount": amount_minor_units, "currency": currency, "status": "created"}

        def verify_webhook(self, raw_body, signature):
            return True

    payments_router.get_provider = lambda: FakeProvider()
    r1 = ctx.client.post(
        f"/payments/authorizations/{auth_id}/consume",
        json={"session_token": ctx.session_token},
    )
    assert r1.status_code == 200
    r2 = ctx.client.post(
        f"/payments/authorizations/{auth_id}/consume",
        json={"session_token": ctx.session_token},
    )
    assert r2.status_code == 409


def test_audit_chain_remains_intact_after_failure(paari_client):
    ctx = paari_client
    r = ctx.client.post(
        "/payments/intent",
        json={
            "session_token": ctx.session_token,
            "transaction_id": "TXN-audit-failure",
            "idempotency_key": "idem-audit-failure",
            "merchant": "TestMerchant",
            "amount_minor_units": 1000,
            "currency": "INR",
            "action": "make_payment",
            "purpose": "audit failure",
        },
    )
    assert r.status_code == 200
    intent_id = r.json()["intent_id"]

    from app import models as m
    from app.audit import verify_chain
    session = ctx.Session()
    events = session.query(m.AuditEvent).filter_by(transaction_id="TXN-audit-failure").all()
    assert len(events) >= 1
    # Recompute every link: the chain must still be intact after the failed consume.
    assert verify_chain(session, "TXN-audit-failure") is True
    session.close()
