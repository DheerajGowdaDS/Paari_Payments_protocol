"""Causal provenance must survive to settlement, and must not be invented.

Two failure modes this pins, both of which the earlier audit found live:

1. **The chain went anonymous at the provider boundary.** `order_submitted`
   carried the `llm_*` labels, but `webhook_applied` and `reconciled` did not -
   so the audit read as an LLM-driven payment right up to the moment money
   actually moved, which is precisely where an auditor looks. The claim "you can
   trace any payment back to the model run that caused it" was only true of the
   half of the chain that costs nothing to log.

2. **Attribution was read unconditionally.** These fields are client-asserted
   trace labels and the rule is that a causal marker is never emitted for a
   request that claimed none. Splatted from the row without checking
   `llm_attributed`, an unattributed payment could pick up `llm_*` keys from
   whatever a previous code path had stashed there.

And the artifact itself: every identifier is a durable column, but the proof
bundle exposed none of them structured, so answering "which run caused this
provider payment" meant scraping free-text JSON in `audit_record.events[].detail`.
"""
import pytest

from tests.conftest import make_intent


def _settle_via_webhook(ctx, monkeypatch, suffix):
    """Consume an intent and drive a verified webhook to PAID."""
    import hashlib
    import hmac
    import json

    import app.routers.payments as payments_router

    secret = "test_causal_secret"  # noqa: S105 (test-only fiction)

    class FakeProvider:
        def create_payment(self, authorization_id, amount_minor_units, currency, notes):
            return {"id": f"order_{suffix}", "status": "created", "receipt": authorization_id,
                    "amount": amount_minor_units, "currency": currency}

        def verify_webhook(self, raw_body, signature):
            import os
            from app.providers.razorpay import verify_webhook_signature
            return verify_webhook_signature(
                raw_body, signature, os.environ.get("RAZORPAY_WEBHOOK_SECRET", ""))

    monkeypatch.setattr(payments_router, "get_provider", lambda: FakeProvider())
    monkeypatch.setenv("RAZORPAY_WEBHOOK_SECRET", secret)

    body = make_intent(ctx, suffix=suffix)
    auth_id = body["authorization"]["authorization_id"]
    r = ctx.client.post(f"/payments/authorizations/{auth_id}/consume",
                        json={"session_token": ctx.session_token})
    assert r.status_code == 200, r.text

    raw = json.dumps({
        "id": f"evt_{suffix}", "event": "payment.captured",
        "payload": {"payment": {"entity": {
            "id": f"pay_{suffix}", "order_id": f"order_{suffix}",
            "amount": 120000, "currency": "INR"}}},
    }).encode()
    w = ctx.client.post("/payments/webhooks/razorpay", content=raw,
                        headers={"X-Razorpay-Signature":
                                 hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest(),
                                 "Content-Type": "application/json"})
    assert w.status_code == 200, w.text
    return body["transaction_id"], auth_id, f"order_{suffix}"


def _audit_rows(ctx, transaction_id):
    import app.models as models

    db = ctx.Session()
    try:
        return db.query(models.AuditEvent).filter_by(
            transaction_id=transaction_id).order_by(models.AuditEvent.id).all()
    finally:
        db.close()


def _labels_claimed(ctx, transaction_id, auth_id, order_id, monkeypatch):
    """Re-run the settlement leg with attribution actually claimed on the intent."""
    import app.models as models

    db = ctx.Session()
    try:
        intent = db.query(models.PaymentIntent).filter_by(transaction_id=transaction_id).first()
        intent.llm_attributed = True
        intent.llm_run_id = "RUN-causal-1"
        intent.llm_model = "test-model-v1"
        intent.llm_tool_call_id = "call_abc123"
        intent.llm_tool_name = "propose_payment"
        db.commit()
    finally:
        db.close()


def test_attributed_payment_carries_labels_into_the_settlement_event(
        paari_client, monkeypatch):
    """The whole point of causal auditing: the label survives to `PAID`."""
    ctx = paari_client
    transaction_id, auth_id, order_id = _settle_via_webhook(ctx, monkeypatch, "causal-attr")
    _labels_claimed(ctx, transaction_id, auth_id, order_id, monkeypatch)

    # A second, corrected event so a settlement lands AFTER the labels exist -
    # otherwise this would only prove the ordering of the test, not the code.
    import hashlib
    import hmac
    import json

    import app.models as models
    secret = "test_causal_secret"  # noqa: S105
    db = ctx.Session()
    try:
        txn = db.query(models.ProviderTransaction).filter_by(razorpay_order_id=order_id).first()
        txn.state = "PROVIDER_SUBMITTED"
        txn.webhook_event_id = None
        db.commit()
    finally:
        db.close()
    raw = json.dumps({
        "id": "evt_causal_attr_2", "event": "payment.captured",
        "payload": {"payment": {"entity": {"id": "pay_causal_attr_2",
                                           "order_id": order_id,
                                           "amount": 120000, "currency": "INR"}}},
    }).encode()
    r = ctx.client.post("/payments/webhooks/razorpay", content=raw,
                        headers={"X-Razorpay-Signature":
                                 hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest(),
                                 "Content-Type": "application/json"})
    assert r.status_code == 200, r.text

    rows = _audit_rows(ctx, transaction_id)
    applied = [e for e in rows if e.kind == "webhook_applied"]
    assert applied, "no webhook_applied row was written"
    detail = applied[-1].detail
    assert detail.get("llm_run_id") == "RUN-causal-1", detail
    assert detail.get("llm_model") == "test-model-v1", detail
    assert detail.get("llm_tool_call_id") == "call_abc123", detail
    assert detail.get("provider_environment"), (
        "the settlement event must also say which provider environment attested it")


def test_unattributed_payment_gains_no_causal_labels_at_settlement(
        paari_client, monkeypatch):
    """AGENTS.md: never emit a causal marker for a request that asserted none.

    The old consume path read the columns unconditionally, so this is the case
    that could silently manufacture attribution.
    """
    ctx = paari_client
    transaction_id, _auth, _order = _settle_via_webhook(ctx, monkeypatch, "causal-none")
    rows = _audit_rows(ctx, transaction_id)
    for row in rows:
        if row.kind in ("order_submitted", "webhook_applied", "authorization_consumed"):
            for key in ("llm_run_id", "llm_model", "llm_tool_call_id"):
                assert key not in row.detail, (
                    f"{row.kind} carried {key} for a payment that never claimed "
                    f"LLM attribution: {row.detail}")


def test_bundle_exposes_causal_provenance_as_structured_fields(paari_client, monkeypatch):
    """'Which model run caused this provider payment' must be answerable from the
    artifact's fields, not by scraping audit JSON."""
    from app.proof_bundle import collect_proof_bundle

    ctx = paari_client
    transaction_id, auth_id, order_id = _settle_via_webhook(ctx, monkeypatch, "causal-bundle")
    _labels_claimed(ctx, transaction_id, auth_id, order_id, monkeypatch)

    db = ctx.Session()
    try:
        bundle = collect_proof_bundle(db, transaction_id)
    finally:
        db.close()

    prov = bundle["artifacts"]["causal_provenance"]
    assert prov["llm_attributed"] is True
    assert prov["llm_run_id"] == "RUN-causal-1"
    assert prov["llm_model"] == "test-model-v1"
    assert prov["llm_tool_call_id"] == "call_abc123"
    assert prov["authorization_id"] == auth_id
    assert prov["provider_order_id"] == order_id
    # The chain is complete as *fields*, which is what makes it queryable:
    # run -> tool call -> agent -> mandate -> transaction -> authorization ->
    # order -> payment -> environment.
    for key in ("agent_id", "transaction_id", "intent_id", "provider_environment"):
        assert key in prov, key
    assert prov["mandate_id"] is None or isinstance(prov["mandate_id"], str)


def test_causal_provenance_reports_unattributed_honestly(paari_client, monkeypatch):
    """An absent claim must read as absent, not as a refutation and not as an
    empty attribution."""
    from app.proof_bundle import collect_proof_bundle

    ctx = paari_client
    transaction_id, _a, _o = _settle_via_webhook(ctx, monkeypatch, "causal-unatt")
    db = ctx.Session()
    try:
        prov = collect_proof_bundle(db, transaction_id)["artifacts"]["causal_provenance"]
    finally:
        db.close()
    assert prov["llm_attributed"] is False
    assert prov["llm_run_id"] is None
    assert prov["llm_model"] is None


def test_causal_labels_helper_is_gated_on_the_attribution_flag():
    """Unit-level statement of the rule, so a refactor of the caller cannot
    quietly widen it."""
    from app.audit import causal_labels

    assert causal_labels(None, None) == {}


def test_mandate_id_in_a_payment_request_is_never_trusted(paari_client, monkeypatch):
    """The client may name a mandate; the server decides which one governed.

    Pinned here because the proof harnesses used to send `mandate_id` and assert
    nothing about it, which made "this mandate authorized the payment" look
    demonstrated when it was only requested.
    """
    ctx = paari_client
    body = make_intent(ctx, suffix="mandate-untrusted", mandate_id="UM-FORGED-BY-CLIENT")
    assert body["decision"] == "allow", body
    assert body.get("mandate_id") != "UM-FORGED-BY-CLIENT", (
        "a client-supplied mandate_id reached the response unexamined")
