"""Task B1: audit hardening — structured policy results and state transitions."""
from tests.conftest import paari_client


def test_intent_decided_audit_contains_structured_policy_results(paari_client):
    ctx = paari_client
    transaction_id = "TXN-audit-hard-1"
    r = ctx.client.post(
        "/payments/intent",
        json={
            "session_token": ctx.session_token,
            "transaction_id": transaction_id,
            "idempotency_key": "idem-audit-hard-1",
            "merchant": "TestMerchant",
            "amount_minor_units": 1000,
            "currency": "INR",
            "action": "make_payment",
            "purpose": "audit hardening",
        },
    )
    assert r.status_code == 200, r.text

    r = ctx.client.get(
        f"/v1/audit/{transaction_id}",
        headers={"Authorization": f"Bearer {ctx.session_token}"},
    )
    assert r.status_code == 200
    events = r.json()["events"]
    kinds = [e["kind"] for e in events]
    assert "intent_decided" in kinds
    decided = next(e for e in events if e["kind"] == "intent_decided")
    detail = decided["detail"]
    assert "policy_results" in detail
    assert isinstance(detail["policy_results"], list)
    assert any(p.get("name") == "capability_check" for p in detail["policy_results"])
    assert any(p.get("name") == "limit_check" for p in detail["policy_results"])
    assert any(p.get("name") == "currency_check" for p in detail["policy_results"])


def test_authorization_minted_audit_contains_state_transition(paari_client):
    ctx = paari_client
    transaction_id = "TXN-audit-hard-2"
    r = ctx.client.post(
        "/payments/intent",
        json={
            "session_token": ctx.session_token,
            "transaction_id": transaction_id,
            "idempotency_key": "idem-audit-hard-2",
            "merchant": "TestMerchant",
            "amount_minor_units": 1000,
            "currency": "INR",
            "action": "make_payment",
            "purpose": "audit hardening",
        },
    )
    assert r.status_code == 200, r.text

    r = ctx.client.get(
        f"/v1/audit/{transaction_id}",
        headers={"Authorization": f"Bearer {ctx.session_token}"},
    )
    assert r.status_code == 200
    events = r.json()["events"]
    kinds = [e["kind"] for e in events]
    assert "authorization_minted" in kinds
    minted = next(e for e in events if e["kind"] == "authorization_minted")
    detail = minted["detail"]
    assert "previous_state" in detail
    assert "current_state" in detail
    assert detail["previous_state"] == "AUTHORIZED"
    assert detail["current_state"] == "AUTHORIZED"
