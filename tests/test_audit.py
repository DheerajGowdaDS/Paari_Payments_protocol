"""Task 4: append-only audit chain + v1 query surface.

RED expectations (pre-fix): no app.audit module, no AuditEvent table,
no GET /v1/audit/{transaction_id}.
"""
import hashlib
import hmac
import json

from tests.conftest import make_intent

WEBHOOK_SECRET = "test_webhook_secret"  # noqa: S105 (test-only fiction)


def _signed(secret, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_audit_chain_answers_eleven_questions(paari_client, monkeypatch):
    import app.routers.payments as payments_router

    class FakeProvider:
        def create_payment(self, authorization_id, amount_minor_units, currency, notes):
            return {"id": "order_audit_1", "receipt": authorization_id, "amount": amount_minor_units, "currency": currency, "status": "created"}

        def verify_webhook(self, raw_body, signature):
            import os
            from app.providers.razorpay import verify_webhook_signature
            return verify_webhook_signature(
                raw_body, signature, os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")
            )

    monkeypatch.setattr(payments_router, "get_provider", lambda: FakeProvider())
    monkeypatch.setenv("RAZORPAY_WEBHOOK_SECRET", WEBHOOK_SECRET)

    ctx = paari_client
    body = make_intent(ctx, suffix="audit-chain")
    assert body["decision"] == "allow", body
    tx_id = f"TXN-audit-chain"
    auth_id = body["authorization"]["authorization_id"]

    r = ctx.client.post(
        f"/payments/authorizations/{auth_id}/consume",
        json={"session_token": ctx.session_token},
    )
    assert r.status_code == 200, r.text

    raw = json.dumps({
        "id": "evt_audit_1",
        "event": "payment.captured",
        "payload": {"payment": {"entity": {
            "id": "pay_audit_1", "order_id": "order_audit_1",
            "amount": 120000, "currency": "INR",
        }}},
    }).encode()
    r = ctx.client.post(
        "/payments/webhooks/razorpay",
        content=raw,
        headers={"X-Razorpay-Signature": _signed(WEBHOOK_SECRET, raw),
                 "Content-Type": "application/json"},
    )
    assert r.status_code == 200, r.text

    r = ctx.client.get(
        f"/v1/audit/{tx_id}", headers={"Authorization": f"Bearer {ctx.session_token}"}
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["transaction_id"] == tx_id
    kinds = [e["kind"] for e in data["events"]]
    assert kinds == ["intent_decided", "authorization_minted",
                     "authorization_consumed", "order_submitted",
                     "webhook_applied"]
    assert data["events"][-1]["detail"]["to_state"] == "PAID"


def test_audit_chain_tamper_evident(paari_client):
    from app.audit import record_audit
    import app.models as models

    ctx = paari_client
    db = ctx.Session()
    e1 = record_audit(db, transaction_id="TXN-tamper", agent_id=ctx.agent_id,
                      parent_id=ctx.parent_id, kind="intent_decided",
                      detail={"decision": "allow"})
    e2 = record_audit(db, transaction_id="TXN-tamper", agent_id=ctx.agent_id,
                      parent_id=ctx.parent_id, kind="order_submitted",
                      detail={"order": "order_x"})
    db.commit()
    assert e2.prev_hash == e1.event_hash
    assert e1.prev_hash == "GENESIS"
    # Tampering with a stored detail breaks the chain link.
    e1.detail = {"decision": "deny"}
    db.commit()
    from app.audit import verify_chain
    assert verify_chain(db, "TXN-tamper") is False
    db.close()


def test_audit_endpoint_reports_server_verified_chain(paari_client):
    """Stage 14's integrity check must be performed by Paari, not only by readers."""
    ctx = paari_client
    make_intent(ctx, suffix="chain-verified")
    tx = "TXN-chain-verified"
    headers = {"Authorization": f"Bearer {ctx.session_token}"}

    r = ctx.client.get(f"/v1/audit/{tx}", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["chain_verified"] is True

    import app.models as models
    db = ctx.Session()
    victim = (db.query(models.AuditEvent).filter_by(transaction_id=tx)
                .order_by(models.AuditEvent.id).first())
    victim.detail = {"tampered": True}
    db.commit()
    db.close()

    r2 = ctx.client.get(f"/v1/audit/{tx}", headers=headers)
    assert r2.status_code == 200, r2.text
    assert r2.json()["chain_verified"] is False


def test_audit_query_rejects_other_agent(paari_client, monkeypatch):
    ctx = paari_client
    make_intent(ctx, suffix="audit-private")
    _, other_token, _, _ = ctx.register_extra_agent(suffix="-snoop")
    r = ctx.client.get(
        "/v1/audit/TXN-audit-private", headers={"Authorization": f"Bearer {other_token}"}
    )
    assert r.status_code == 403, r.text
