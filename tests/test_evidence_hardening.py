"""Regression tests for the aggregation, provenance, lifecycle and evidence
defects found in the Paari v1.1 review.

- P2-9   The merchant/category allowlists are case-insensitive but the spend
         aggregation was not, so AMAZON then amazon reset the per-merchant
         budget while both passed the same allowlist entry.
- P2-10  The `llm_tool_call` audit event was written for EVERY payment,
         including clients that sent no causal ids, so the chain asserted a
         model tool invocation that never happened.
- P2-13  A velocity-parked REVIEW intent consumed mandate budget for the whole
         window with no recovery path (`review_expires_at` was written but
         never read), and `MandateStatus.EXPIRED` was an unreachable member.
- P3-14  `_mandate_view` hardcoded merchant/category spend to None while
         importing the very functions that compute them.
- P3-15  The proof bundle omitted the three Sprint 6 budget limits and all
         signature material, so the evidence could not show which constraints
         actually governed the payment.
- P3-18  `AgenticPaymentProvider` had no DI seam, only a unit test.
"""
from datetime import datetime, timedelta, timezone

from tests.conftest import make_intent
from tests.test_user_mandates import create_mandate, _admin_key
from tests.test_v2_governance import _user_keypair, _proof, _signed_mandate_post


def _llm_intent(ctx, suffix: str, **causal):
    """make_intent does not forward llm_* kwargs, so post the body directly."""
    r = ctx.client.post("/payments/intent", json={
        "session_token": ctx.session_token, "transaction_id": f"TXN-{suffix}",
        "idempotency_key": f"idem-{suffix}", "merchant": "TestMerchant",
        "amount_minor_units": 100, "currency": "INR", "action": "make_payment",
        **causal,
    })
    assert r.status_code == 200, r.text
    return r.json()


# ------------------------- P2-9 case normalization -------------------------

def test_merchant_budget_is_case_insensitive(paari_client):
    """The allowlist is case-insensitive, so the spend aggregation must be too."""
    ctx = paari_client
    create_mandate(ctx, max_per_transaction=5000, max_daily_amount=100000,
                   allowed_merchants=["TestMerchant"],
                   max_per_merchant_per_day=4000)
    first = ctx.client.post("/payments/intent", json={
        "session_token": ctx.session_token, "transaction_id": "TXN-case-1",
        "idempotency_key": "idem-case-1", "merchant": "TESTMERCHANT",
        "amount_minor_units": 3000, "currency": "INR", "action": "make_payment",
    })
    assert first.json()["decision"] == "allow", first.text
    second = ctx.client.post("/payments/intent", json={
        "session_token": ctx.session_token, "transaction_id": "TXN-case-2",
        "idempotency_key": "idem-case-2", "merchant": "TestMerchant",
        "amount_minor_units": 2000, "currency": "INR", "action": "make_payment",
    })
    assert second.json()["decision"] == "deny", second.text
    assert any("merchant" in r for r in second.json()["reasons"]), second.text


# ------------------------- P2-10 causal provenance --------------------------

def test_non_llm_payment_is_not_marked_as_llm_tool_call(paari_client):
    """The chain must never claim a model tool invocation that did not happen."""
    from app.models import AuditEvent, PaymentIntent

    ctx = paari_client
    make_intent(ctx, amount=100, suffix="no-llm")
    db = ctx.Session()
    try:
        intent = db.query(PaymentIntent).filter_by(transaction_id="TXN-no-llm").first()
        assert intent.llm_attributed is False
        kinds = [e.kind for e in db.query(AuditEvent)
                 .filter_by(transaction_id="TXN-no-llm").order_by(AuditEvent.id).all()]
        assert "llm_tool_call" not in kinds
        assert kinds[0] == "payment_proposed"
    finally:
        db.close()


def test_llm_claimed_payment_is_marked_and_linked(paari_client):
    """A payment that DOES claim an LLM origin still gets the causal marker."""
    from app.models import AuditEvent, PaymentIntent

    ctx = paari_client
    body = _llm_intent(ctx, "llm-claimed", llm_run_id="RUN-1", llm_model="m",
                       llm_tool_call_id="call-1", llm_tool_name="propose_payment")
    print('REASONS:', body.get('reasons'))
    assert body["decision"] == "allow", body
    db = ctx.Session()
    try:
        intent = db.query(PaymentIntent).filter_by(
            transaction_id=body["transaction_id"]).first()
        assert intent.llm_attributed is True
        kinds = [e.kind for e in db.query(AuditEvent)
                 .filter_by(transaction_id=body["transaction_id"])
                 .order_by(AuditEvent.id).all()]
        assert kinds[0] == "llm_tool_call"
    finally:
        db.close()


# ------------------------- P2-13 lifecycle sweepers -------------------------

def test_parked_review_releases_budget_on_expiry(paari_client):
    """A velocity-parked intent that is never step-up approved used to consume
    mandate budget for the whole window with no recovery path.
    `review_expires_at` was written but nothing ever read it."""
    from app.mandates import expire_stale_reviews
    from app.models import PaymentIntent

    ctx = paari_client
    create_mandate(ctx, max_per_transaction=900, max_daily_amount=5000)
    for i in range(5):
        make_intent(ctx, amount=100, suffix="park-{}".format(i))
    parked = make_intent(ctx, amount=100, suffix="park-6")
    assert parked["decision"] == "review", parked
    assert parked["review_expires_at"]

    db = ctx.Session()
    try:
        swept = expire_stale_reviews(db, now=datetime.now(timezone.utc)
                                    + timedelta(minutes=10))
        assert swept >= 1
        row = db.query(PaymentIntent).filter_by(
            transaction_id=parked["transaction_id"]).first()
        assert row.decision.value == "deny"
    finally:
        db.close()

    # The reservation is released, so the daily budget is no longer exhausted.
    # The new intent may still park on the velocity rule, so assert on the
    # budget reason specifically rather than the overall decision.
    after = make_intent(ctx, amount=400, suffix="park-recovered")
    assert not any("daily mandate budget" in r for r in after["reasons"]), after


def test_expired_mandate_status_is_swept(paari_client):
    """MandateStatus.EXPIRED was an unreachable enum member."""
    from app.mandates import sweep_expired_mandates
    from app.models import UserPaymentMandate

    ctx = paari_client
    now = datetime.now(timezone.utc)
    create_mandate(ctx, max_per_transaction=1000, max_daily_amount=2000,
                   valid_from=(now - timedelta(days=2)).isoformat(),
                   expires_at=(now - timedelta(days=1)).isoformat())
    db = ctx.Session()
    try:
        assert sweep_expired_mandates(db, now=now) == 1
        assert db.query(UserPaymentMandate).first().status.value == "expired"
    finally:
        db.close()


# ------------------- P3-14 / P3-15 evidence completeness --------------------

def test_proof_bundle_exposes_mandate_budgets_and_signature(paari_client):
    """The three Sprint 6 limits and the signature material must be visible in
    the evidence bundle - they are what actually governed the payment."""
    from app.proof_bundle import collect_proof_bundle

    ctx = paari_client
    user_private, user_public = _user_keypair()
    _signed_mandate_post(ctx, user_private, user_public,
                         max_per_transaction=5000, max_daily_amount=20000,
                         max_per_hour=8000, max_per_merchant_per_day=7000,
                         max_category_per_day=10000)
    # merchant_category is REQUIRED: a per-category budget fails closed when the
    # category is unknown, so this intent must declare one.
    r = ctx.client.post("/payments/intent", json={
        "session_token": ctx.session_token, "transaction_id": "TXN-bundle-evidence",
        "idempotency_key": "idem-bundle-evidence", "merchant": "TestMerchant",
        "merchant_category": "grocery", "amount_minor_units": 1000,
        "currency": "INR", "action": "make_payment",
    })
    body = r.json()
    assert r.status_code == 200, r.text
    assert body["decision"] == "allow", body

    db = ctx.Session()
    try:
        bundle = collect_proof_bundle(db, body["transaction_id"])
    finally:
        db.close()
    m = bundle["artifacts"]["user_payment_mandate"]
    assert m["max_per_hour"] == 8000
    assert m["max_per_merchant_per_day"] == 7000
    assert m["max_category_per_day"] == 10000
    assert m["signature_valid"] is True
    assert m["signature_b64"] and m["user_public_key_pem"]


def test_mandate_view_reports_real_merchant_spend(paari_client):
    """P3-14: this field was hardcoded None while the aggregation function was
    imported on the very next line."""
    ctx = paari_client
    create_mandate(ctx, max_per_transaction=5000, max_daily_amount=50000,
                   allowed_merchants=["TestMerchant"],
                   max_per_merchant_per_day=7000)
    make_intent(ctx, amount=1000, suffix="view-spend")
    path = "/v1/mandates/active/" + ctx.agent_id
    r = ctx.client.get(path, headers={
        "Authorization": "Bearer " + ctx.session_token,
        "X-Paari-Proof": _proof(ctx, "GET", path),
    })
    assert r.status_code == 200, r.text
    assert r.json()["merchant_daily_spent"] == 1000, r.json()


# ------------------------- P3-18 agentic DI seam ---------------------------

def test_agentic_provider_seam_defaults_to_not_configured(monkeypatch):
    """The boundary now has a real DI seam, and it still refuses everything."""
    from app.providers.agentic import (get_agentic_provider, AdapterStatus,
                                       NotConfiguredAgenticProvider,
                                       autonomous_settlement_configured)
    monkeypatch.delenv("PAARI_AGENTIC_PROVIDER", raising=False)
    adapter = get_agentic_provider()
    assert isinstance(adapter, NotConfiguredAgenticProvider)
    assert adapter.status() is AdapterStatus.NOT_CONFIGURED
    assert autonomous_settlement_configured() is False


def test_agentic_provider_seam_rejects_bogus_spec(monkeypatch):
    """A malformed or non-conforming PAARI_AGENTIC_PROVIDER must fail loudly
    rather than silently falling back to NOT_CONFIGURED."""
    import pytest
    from app.providers.agentic import (get_agentic_provider,
                                       AgenticProviderUnavailable)
    monkeypatch.setenv("PAARI_AGENTIC_PROVIDER", "app.config:PaariEnv")
    with pytest.raises(AgenticProviderUnavailable):
        get_agentic_provider()
    monkeypatch.setenv("PAARI_AGENTIC_PROVIDER", "no_such_module:Thing")
    with pytest.raises(AgenticProviderUnavailable):
        get_agentic_provider()


# ------------------------- Phase 8 Part B: agentic seam wired into consume ---------------------------

class _MockAgenticProvider:
    """Mock AgenticPaymentProvider for testing the consume-path wiring."""
    def __init__(self):
        self.calls = []
    def status(self):
        from app.providers.agentic import AdapterStatus
        return AdapterStatus.CONFIGURED
    def supports_autonomous_settlement(self):
        return True
    def authorize_payment(self, *, authorization_id, provider_mandate_ref,
                          amount_minor_units, currency, merchant_reference, idempotency_key):
        self.calls.append(("authorize", authorization_id))
        return {"id": "pay_mock_123", "provider_payment_ref": "pay_mock_123"}
    def capture_payment(self, *, provider_payment_ref, amount_minor_units, currency, idempotency_key):
        self.calls.append(("capture", provider_payment_ref))
        return {"id": provider_payment_ref, "status": "captured"}
    def get_payment(self, provider_payment_ref):
        return {"id": provider_payment_ref, "amount": 10000, "currency": "INR", "status": "captured"}
    def create_or_bind_mandate(self, **kwargs):
        return {}
    def validate_mandate(self, provider_mandate_ref):
        return {"valid": True}
    def verify_webhook(self, raw_body, signature):
        return True
    def revoke_mandate(self, provider_mandate_ref):
        return {}


def test_consume_without_agentic_provider_falls_through(paari_client, monkeypatch):
    """When no agentic provider is configured, consume stops at PROVIDER_SUBMITTED."""
    import app.providers.agentic as agentic_mod
    import app.routers.payments as payments_router
    monkeypatch.delenv("PAARI_AGENTIC_PROVIDER", raising=False)

    class FakeProvider:
        def create_payment(self, authorization_id, amount_minor_units, currency, notes):
            return {"id": "order_test_123", "receipt": authorization_id,
                    "amount": amount_minor_units, "currency": currency, "status": "created"}

    monkeypatch.setattr(payments_router, "get_provider", lambda: FakeProvider())
    ctx = paari_client
    mandate = create_mandate(ctx)
    intent = make_intent(ctx, amount=10000)
    auth_id = intent["authorization"]["authorization_id"]
    proof = _proof(ctx, "POST", f"/payments/authorizations/{auth_id}/consume")
    r = ctx.client.post(
        f"/payments/authorizations/{auth_id}/consume",
        json={"session_token": ctx.session_token},
        headers={"X-Paari-Proof": proof},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["state"] == "PROVIDER_SUBMITTED"


def test_consume_with_agentic_provider_settles(paari_client, monkeypatch):
    """When an agentic provider is configured and supports autonomous settlement,
    consume drives the full path: PROVIDER_SUBMITTED -> PROVIDER_AUTHORIZED -> CAPTURED -> PAID."""
    import app.providers.agentic as agentic_mod
    import app.routers.payments as payments_router
    mock = _MockAgenticProvider()
    monkeypatch.setattr(agentic_mod, "get_agentic_provider", lambda org_id=None: mock)

    class FakeProvider:
        def create_payment(self, authorization_id, amount_minor_units, currency, notes):
            return {"id": "order_test_123", "receipt": authorization_id,
                    "amount": amount_minor_units, "currency": currency, "status": "created"}

    monkeypatch.setattr(payments_router, "get_provider", lambda: FakeProvider())
    ctx = paari_client
    mandate = create_mandate(ctx)
    intent = make_intent(ctx, amount=10000)
    auth_id = intent["authorization"]["authorization_id"]
    binding_r = ctx.client.post(
        f"/v1/mandates/{mandate['mandate_id']}/provider-binding",
        json={
            "provider": "razorpay",
            "provider_mandate_ref": "mandate_mock_123",
            "currency": "INR",
            "max_amount_minor_units": 100000,
        },
        headers={"X-Admin-Api-Key": _admin_key()},
    )
    assert binding_r.status_code == 200, binding_r.text
    proof = _proof(ctx, "POST", f"/payments/authorizations/{auth_id}/consume")
    r = ctx.client.post(
        f"/payments/authorizations/{auth_id}/consume",
        json={"session_token": ctx.session_token},
        headers={"X-Paari-Proof": proof},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["state"] == "PAID"
    assert body["razorpay_payment_id"] == "pay_mock_123"
    assert ("authorize", auth_id) in mock.calls
    assert ("capture", "pay_mock_123") in mock.calls


def test_consume_with_agentic_provider_not_captured_does_not_reach_paid(paari_client, monkeypatch):
    """When the provider says the payment is NOT captured (e.g. 'authorized'),
    the row must NOT reach PAID. This is the regression test for the critical
    status-check fix."""
    import app.providers.agentic as agentic_mod
    import app.routers.payments as payments_router

    class _NotCapturedMockAgenticProvider:
        def status(self):
            from app.providers.agentic import AdapterStatus
            return AdapterStatus.CONFIGURED
        def supports_autonomous_settlement(self):
            return True
        def authorize_payment(self, *, authorization_id, provider_mandate_ref,
                              amount_minor_units, currency, merchant_reference, idempotency_key):
            return {"id": "pay_mock_456", "provider_payment_ref": "pay_mock_456"}
        def capture_payment(self, *, provider_payment_ref, amount_minor_units, currency, idempotency_key):
            return {"id": provider_payment_ref, "status": "captured"}
        def get_payment(self, provider_payment_ref):
            return {"id": provider_payment_ref, "amount": 10000, "currency": "INR", "status": "authorized"}
        def create_or_bind_mandate(self, **kwargs):
            return {}
        def validate_mandate(self, provider_mandate_ref):
            return {"valid": True}
        def verify_webhook(self, raw_body, signature):
            return True
        def revoke_mandate(self, provider_mandate_ref):
            return {}

    mock = _NotCapturedMockAgenticProvider()
    monkeypatch.setattr(agentic_mod, "get_agentic_provider", lambda org_id=None: mock)

    class FakeProvider:
        def create_payment(self, authorization_id, amount_minor_units, currency, notes):
            return {"id": "order_test_456", "receipt": authorization_id,
                    "amount": amount_minor_units, "currency": currency, "status": "created"}

    monkeypatch.setattr(payments_router, "get_provider", lambda: FakeProvider())
    ctx = paari_client
    mandate = create_mandate(ctx)
    intent = make_intent(ctx, amount=10000)
    auth_id = intent["authorization"]["authorization_id"]
    binding_r = ctx.client.post(
        f"/v1/mandates/{mandate['mandate_id']}/provider-binding",
        json={
            "provider": "razorpay",
            "provider_mandate_ref": "mandate_mock_456",
            "currency": "INR",
            "max_amount_minor_units": 100000,
        },
        headers={"X-Admin-Api-Key": _admin_key()},
    )
    assert binding_r.status_code == 200, binding_r.text
    proof = _proof(ctx, "POST", f"/payments/authorizations/{auth_id}/consume")
    r = ctx.client.post(
        f"/payments/authorizations/{auth_id}/consume",
        json={"session_token": ctx.session_token},
        headers={"X-Paari-Proof": proof},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["state"] != "PAID"
    assert body["state"] in ("CAPTURED", "PROVIDER_UNKNOWN")


def test_consume_with_agentic_provider_capture_fails_does_not_reach_paid(paari_client, monkeypatch):
    """When capture_payment returns a bad status (not 'captured' or 'already_captured'),
    the row must NOT reach PAID. This is the regression test for the capture_result
    status-check fix."""
    import app.providers.agentic as agentic_mod
    import app.routers.payments as payments_router

    class _CaptureFailsMockAgenticProvider:
        def status(self):
            from app.providers.agentic import AdapterStatus
            return AdapterStatus.CONFIGURED
        def supports_autonomous_settlement(self):
            return True
        def authorize_payment(self, *, authorization_id, provider_mandate_ref,
                              amount_minor_units, currency, merchant_reference, idempotency_key):
            return {"id": "pay_mock_789", "provider_payment_ref": "pay_mock_789"}
        def capture_payment(self, *, provider_payment_ref, amount_minor_units, currency, idempotency_key):
            return {"id": provider_payment_ref, "status": "failed"}
        def get_payment(self, provider_payment_ref):
            return {"id": provider_payment_ref, "amount": 10000, "currency": "INR", "status": "failed"}
        def create_or_bind_mandate(self, **kwargs):
            return {}
        def validate_mandate(self, provider_mandate_ref):
            return {"valid": True}
        def verify_webhook(self, raw_body, signature):
            return True
        def revoke_mandate(self, provider_mandate_ref):
            return {}

    mock = _CaptureFailsMockAgenticProvider()
    monkeypatch.setattr(agentic_mod, "get_agentic_provider", lambda org_id=None: mock)

    class FakeProvider:
        def create_payment(self, authorization_id, amount_minor_units, currency, notes):
            return {"id": "order_test_789", "receipt": authorization_id,
                    "amount": amount_minor_units, "currency": currency, "status": "created"}

    monkeypatch.setattr(payments_router, "get_provider", lambda: FakeProvider())
    ctx = paari_client
    mandate = create_mandate(ctx)
    intent = make_intent(ctx, amount=10000)
    auth_id = intent["authorization"]["authorization_id"]
    binding_r = ctx.client.post(
        f"/v1/mandates/{mandate['mandate_id']}/provider-binding",
        json={
            "provider": "razorpay",
            "provider_mandate_ref": "mandate_mock_789",
            "currency": "INR",
            "max_amount_minor_units": 100000,
        },
        headers={"X-Admin-Api-Key": _admin_key()},
    )
    assert binding_r.status_code == 200, binding_r.text
    proof = _proof(ctx, "POST", f"/payments/authorizations/{auth_id}/consume")
    r = ctx.client.post(
        f"/payments/authorizations/{auth_id}/consume",
        json={"session_token": ctx.session_token},
        headers={"X-Paari-Proof": proof},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["state"] != "PAID"
    assert body["state"] == "FAILED"
