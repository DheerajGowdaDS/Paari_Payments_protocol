"""Task 1: provider interface + reconcilable PROVIDER_UNKNOWN (Amendment 1)."""
import httpx
import pytest

from tests.conftest import make_intent


def _fake_order_list_client(receipt):
    def handler(request):
        assert request.url.path.endswith("/orders")
        return httpx.Response(
            200,
            json={"items": [{"id": "order_found_1", "receipt": receipt, "status": "created"}]},
        )
    return httpx.Client(transport=httpx.MockTransport(handler), base_url="https://x.test")


def test_unknown_order_recoverable_by_receipt():
    from app.providers.razorpay import RazorpayAdapter
    adapter = RazorpayAdapter(client=_fake_order_list_client("auth-123"))
    found = adapter.fetch_order_by_receipt("auth-123")
    assert found["receipt"] == "auth-123"


def test_consume_timeout_leaves_unknown_not_failed(paari_client, monkeypatch):
    import app.routers.payments as payments_router

    class TimeoutProvider:
        def create_payment(self, **kwargs):
            raise httpx.TimeoutException("simulated provider timeout")

    monkeypatch.setattr(payments_router, "get_provider", lambda: TimeoutProvider())
    ctx = paari_client
    body = make_intent(ctx, suffix="t1-timeout")
    auth_id = body["authorization"]["authorization_id"]
    r = ctx.client.post(
        f"/payments/authorizations/{auth_id}/consume",
        json={"session_token": ctx.session_token},
    )
    assert r.status_code == 502, r.text
    assert r.json()["state"] == "PROVIDER_UNKNOWN"

    import app.models as models
    db = ctx.Session()
    txn = db.query(models.ProviderTransaction).filter_by(authorization_id=auth_id).first()
    db.close()
    assert txn.state == "PROVIDER_UNKNOWN"
