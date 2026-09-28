"""Tests for RazorpayAgenticProvider using httpx.MockTransport.

These tests exercise the real adapter's HTTP handling, error mapping, token
parsing, and revoke logic without making live API calls.
"""
from __future__ import annotations

import json

import httpx
import pytest

from app.providers.razorpay_agentic import (
    RazorpayAgenticProvider,
    RazorpayAgenticConfigError,
    _verify_webhook_signature,
)


def _mock_client(handler) -> httpx.Client:
    """Build an httpx.Client with a MockTransport."""
    transport = httpx.MockTransport(handler)
    return httpx.Client(transport=transport, base_url="https://api.razorpay.com/v1")


def _make_provider(handler) -> RazorpayAgenticProvider:
    return RazorpayAgenticProvider(client=_mock_client(handler))


@pytest.fixture(autouse=True)
def agentic_contract_env(monkeypatch):
    """Unit tests use a mocked provider contract; live deployments must attest
    the real provider capability separately."""
    monkeypatch.setenv("RAZORPAY_AGENTIC_CAPABILITY_CONFIRMED", "1")
    monkeypatch.setenv("RAZORPAY_AGENTIC_AUTHORIZE_PATH", "/payments/create/recurring")
    monkeypatch.setenv("RAZORPAY_AGENTIC_VALIDATE_PATH", "/customers/{provider_mandate_ref}")
    monkeypatch.setenv("RAZORPAY_AGENTIC_TOKEN_LIST_PATH", "/customers/{customer_id}/tokens")
    monkeypatch.setenv("RAZORPAY_AGENTIC_PAYMENT_PATH", "/payments/{payment_id}")
    monkeypatch.setenv("RAZORPAY_AGENTIC_CAPTURE_PATH", "/payments/{payment_id}/capture")


# ---------------------------------------------------------------------------
# status / supports_autonomous_settlement
# ---------------------------------------------------------------------------

def test_status_configured(monkeypatch):
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_123")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "secret")
    provider = RazorpayAgenticProvider(client=_mock_client(lambda r: httpx.Response(200, json={})))
    from app.providers.agentic import AdapterStatus
    assert provider.status() == AdapterStatus.CONFIGURED
    assert provider.supports_autonomous_settlement() is True


def test_status_not_configured(monkeypatch):
    monkeypatch.delenv("RAZORPAY_KEY_ID", raising=False)
    monkeypatch.delenv("RAZORPAY_KEY_SECRET", raising=False)
    provider = RazorpayAgenticProvider(client=_mock_client(lambda r: httpx.Response(200, json={})))
    from app.providers.agentic import AdapterStatus
    assert provider.status() == AdapterStatus.NOT_CONFIGURED
    assert provider.supports_autonomous_settlement() is False


# ---------------------------------------------------------------------------
# create_or_bind_mandate
# ---------------------------------------------------------------------------

def test_create_or_bind_mandate_creates_new_customer(monkeypatch):
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_123")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "secret")

    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "GET" and "/customers/cust_abc" in str(request.url):
            return httpx.Response(404, json={"error": "not found"})
        if request.method == "POST" and "/customers" in str(request.url):
            return httpx.Response(200, json={"id": "cust_abc", "name": "Test"})
        return httpx.Response(404, json={})

    provider = _make_provider(handler)
    result = provider.create_or_bind_mandate(
        mandate_id="mandate_123",
        user_reference="cust_abc",
        max_amount_minor_units=100000,
        currency="INR",
        metadata={"name": "Test User"},
    )
    assert result["provider_customer_ref"] == "cust_abc"
    assert result["provider_mandate_ref"] == "cust_abc"
    assert result["status"] == "created"
    assert len(calls) == 2


def test_create_or_bind_mandate_existing_customer(monkeypatch):
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_123")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "secret")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and "/customers/cust_abc" in str(request.url):
            return httpx.Response(200, json={"id": "cust_abc", "name": "Test"})
        return httpx.Response(404, json={})

    provider = _make_provider(handler)
    result = provider.create_or_bind_mandate(
        mandate_id="mandate_123",
        user_reference="cust_abc",
        max_amount_minor_units=100000,
        currency="INR",
    )
    assert result["status"] == "exists"
    assert result["provider_customer_ref"] == "cust_abc"


# ---------------------------------------------------------------------------
# validate_mandate
# ---------------------------------------------------------------------------

def test_validate_mandate_active(monkeypatch):
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_123")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "secret")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "cust_abc"})

    provider = _make_provider(handler)
    result = provider.validate_mandate("cust_abc")
    assert result["valid"] is True
    assert result["status"] == "active"


def test_validate_mandate_not_found(monkeypatch):
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_123")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "secret")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "not found"})

    provider = _make_provider(handler)
    result = provider.validate_mandate("cust_missing")
    assert result["valid"] is False
    assert result["status"] == "inactive"


# ---------------------------------------------------------------------------
# authorize_payment
# ---------------------------------------------------------------------------

def test_authorize_payment_no_tokens_raises(monkeypatch):
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_123")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "secret")

    def handler(request: httpx.Request) -> httpx.Response:
        if "/tokens" in str(request.url):
            return httpx.Response(200, json={"items": []})
        return httpx.Response(404, json={})

    provider = _make_provider(handler)
    with pytest.raises(RazorpayAgenticConfigError, match="No tokens found"):
        provider.authorize_payment(
            authorization_id="auth_123",
            provider_mandate_ref="cust_abc",
            amount_minor_units=10000,
            currency="INR",
            merchant_reference="merchant_1",
            idempotency_key="idem_1",
        )


def test_authorize_payment_success(monkeypatch):
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_123")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "secret")

    def handler(request: httpx.Request) -> httpx.Response:
        if "/tokens" in str(request.url):
            return httpx.Response(200, json={"items": [{"id": "token_1", "status": "active"}]})
        if "/payments/create/recurring" in str(request.url):
            return httpx.Response(200, json={"id": "pay_recurring_1", "status": "authorized"})
        return httpx.Response(404, json={})

    provider = _make_provider(handler)
    result = provider.authorize_payment(
        authorization_id="auth_123",
        provider_mandate_ref="cust_abc",
        amount_minor_units=10000,
        currency="INR",
        merchant_reference="merchant_1",
        idempotency_key="idem_1",
    )
    assert result["provider_payment_ref"] == "pay_recurring_1"
    assert result["status"] == "authorized"
    assert result["token_id"] == "token_1"


def test_authorize_payment_uses_first_active_token(monkeypatch):
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_123")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "secret")

    def handler(request: httpx.Request) -> httpx.Response:
        if "/tokens" in str(request.url):
            return httpx.Response(200, json={"items": [
                {"id": "token_expired", "status": "expired"},
                {"id": "token_active", "status": "active"},
            ]})
        if "/payments/create/recurring" in str(request.url):
            body = json.loads(request.content)
            assert body["token_id"] == "token_active"
            return httpx.Response(200, json={"id": "pay_recurring_2", "status": "authorized"})
        return httpx.Response(404, json={})

    provider = _make_provider(handler)
    result = provider.authorize_payment(
        authorization_id="auth_456",
        provider_mandate_ref="cust_abc",
        amount_minor_units=5000,
        currency="INR",
        merchant_reference="merchant_2",
        idempotency_key="idem_2",
    )
    assert result["token_id"] == "token_active"


# ---------------------------------------------------------------------------
# capture_payment
# ---------------------------------------------------------------------------

def test_capture_payment_already_captured(monkeypatch):
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_123")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "secret")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and "/payments/pay_123" in str(request.url):
            return httpx.Response(200, json={"id": "pay_123", "status": "captured", "amount": 10000})
        return httpx.Response(404, json={})

    provider = _make_provider(handler)
    result = provider.capture_payment(
        provider_payment_ref="pay_123",
        amount_minor_units=10000,
        currency="INR",
        idempotency_key="idem_capture",
    )
    assert result["status"] == "already_captured"


def test_capture_payment_captures(monkeypatch):
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_123")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "secret")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and "/payments/pay_123" in str(request.url):
            return httpx.Response(200, json={"id": "pay_123", "status": "authorized", "amount": 10000})
        if request.method == "POST" and "/payments/pay_123/capture" in str(request.url):
            return httpx.Response(200, json={"id": "pay_123", "status": "captured", "amount": 10000})
        return httpx.Response(404, json={})

    provider = _make_provider(handler)
    result = provider.capture_payment(
        provider_payment_ref="pay_123",
        amount_minor_units=10000,
        currency="INR",
        idempotency_key="idem_capture",
    )
    assert result["status"] == "captured"


# ---------------------------------------------------------------------------
# get_payment
# ---------------------------------------------------------------------------

def test_get_payment(monkeypatch):
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_123")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "secret")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "pay_123", "status": "captured", "amount": 10000, "currency": "INR"})

    provider = _make_provider(handler)
    result = provider.get_payment("pay_123")
    assert result["id"] == "pay_123"
    assert result["status"] == "captured"


# ---------------------------------------------------------------------------
# verify_webhook
# ---------------------------------------------------------------------------

def test_verify_webhook_valid(monkeypatch):
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_123")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "secret")
    monkeypatch.setenv("RAZORPAY_WEBHOOK_SECRET", "whsec_123")

    import hashlib
    import hmac
    body = b'{"event":"payment.captured"}'
    sig = hmac.new(b"whsec_123", body, hashlib.sha256).hexdigest()

    provider = _make_provider(lambda r: httpx.Response(200, json={}))
    assert provider.verify_webhook(body, sig) is True


def test_verify_webhook_invalid(monkeypatch):
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_123")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "secret")
    monkeypatch.setenv("RAZORPAY_WEBHOOK_SECRET", "whsec_123")

    provider = _make_provider(lambda r: httpx.Response(200, json={}))
    assert provider.verify_webhook(b'{"event":"payment.captured"}', "invalid_sig") is False


def test_verify_webhook_empty_inputs(monkeypatch):
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_123")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "secret")
    monkeypatch.setenv("RAZORPAY_WEBHOOK_SECRET", "whsec_123")

    provider = _make_provider(lambda r: httpx.Response(200, json={}))
    assert provider.verify_webhook(b"", "sig") is False
    assert provider.verify_webhook(b"body", "") is False


# ---------------------------------------------------------------------------
# revoke_mandate
# ---------------------------------------------------------------------------

def test_revoke_mandate_deletes_tokens(monkeypatch):
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_123")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "secret")

    def handler(request: httpx.Request) -> httpx.Response:
        if "/tokens" in str(request.url) and request.method == "GET":
            return httpx.Response(200, json={"items": [{"id": "token_1"}, {"id": "token_2"}]})
        if request.method == "DELETE" and "/tokens/token_1" in str(request.url):
            return httpx.Response(200, json={"id": "token_1", "deleted": True})
        if request.method == "DELETE" and "/tokens/token_2" in str(request.url):
            return httpx.Response(200, json={"id": "token_2", "deleted": True})
        return httpx.Response(404, json={})

    provider = _make_provider(handler)
    result = provider.revoke_mandate("cust_abc")
    assert result["status"] == "revoked"
    assert result["tokens_deleted"] == 2


def test_revoke_mandate_no_tokens(monkeypatch):
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_123")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "secret")

    def handler(request: httpx.Request) -> httpx.Response:
        if "/tokens" in str(request.url):
            return httpx.Response(200, json={"items": []})
        return httpx.Response(404, json={})

    provider = _make_provider(handler)
    result = provider.revoke_mandate("cust_abc")
    assert result["status"] == "revoked"
    assert result["tokens_deleted"] == 0
