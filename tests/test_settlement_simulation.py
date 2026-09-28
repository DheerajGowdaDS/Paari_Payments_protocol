"""Offline tests for the local Razorpay simulator used by the LLM E2E.

These matter because the simulator is what turns a green E2E into a meaningful one: if its
capture state, receipt lookup, or webhook signature were wrong, Paari would appear to
settle payments that never happened.
"""
from __future__ import annotations

import importlib.util
import json
import socket
from pathlib import Path

import httpx
import pytest

from app.providers.razorpay import verify_webhook_signature

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("stub_razorpay", ROOT / "scripts" / "stub_razorpay.py")
stub = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(stub)

SECRET = "unit-test-webhook-secret"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture()
def api():
    server = stub.serve(_free_port())
    client = httpx.Client(base_url=f"http://127.0.0.1:{server.server_address[1]}/v1",
                          auth=("sim_key", "sim_secret"), timeout=10.0)
    yield client
    client.close()
    server.shutdown()


def _capture(client, amount=100, currency="INR", receipt="sim-receipt"):
    order = client.post("/orders", json={"amount": amount, "currency": currency,
                                         "receipt": receipt}).json()
    payment = client.post("/payments", json={"order_id": order["id"], "amount": amount,
                                             "currency": currency}).json()
    captured = client.post(f"/payments/{payment['id']}/capture",
                           json={"amount": amount, "currency": currency}).json()
    return order, payment, captured


def test_capture_moves_both_payment_and_order_to_settled(api):
    order, payment, captured = _capture(api)
    assert captured["status"] == "captured"
    assert captured["order_id"] == order["id"]
    refetched = api.get(f"/orders/{order['id']}").json()
    assert refetched["status"] == "paid"
    assert refetched["amount_paid"] == 100 and refetched["amount_due"] == 0


def test_payments_collection_matches_what_reconcile_reads(api):
    order, payment, _ = _capture(api, receipt="sim-reconcile")
    items = api.get(f"/orders/{order['id']}/payments").json()["items"]
    assert [p["id"] for p in items] == [payment["id"]]
    assert items[0]["status"] == "captured"
    assert items[0]["amount"] == 100 and items[0]["currency"] == "INR"


def test_receipt_lookup_finds_the_order(api):
    order, _, _ = _capture(api, receipt="sim-by-receipt")
    found = api.get("/orders", params={"receipt": "sim-by-receipt", "count": 1}).json()
    assert [o["id"] for o in found["items"]] == [order["id"]]


def test_unknown_ids_and_bad_amounts_are_refused(api):
    assert api.get("/orders/order_does_not_exist").status_code == 404
    assert api.post("/payments", json={"order_id": "order_nope", "amount": 5}).status_code == 404
    assert api.post("/orders", json={"amount": 0, "currency": "INR"}).status_code == 400


def test_missing_basic_auth_is_rejected_like_the_real_api():
    port_server = stub.serve(_free_port())
    port = port_server.server_address[1]
    try:
        r = httpx.get(f"http://127.0.0.1:{port}/v1/orders", timeout=10.0)
        assert r.status_code == 401
        assert r.json()["error"]["description"] == "Authentication failed"
    finally:
        port_server.shutdown()


def test_capture_webhook_verifies_against_the_providers_own_checker():
    payment = {"id": "pay_evt_1", "order_id": "order_evt_1", "amount": 100, "currency": "INR",
               "status": "captured"}
    raw, signature = stub.build_capture_webhook(payment, SECRET)
    assert verify_webhook_signature(raw, signature, SECRET) is True
    event = json.loads(raw)
    entity = event["payload"]["payment"]["entity"]
    assert event["event"] == "payment.captured"
    assert (entity["order_id"], entity["amount"], entity["currency"]) == ("order_evt_1", 100, "INR")


def test_tampered_body_invalidates_the_signature():
    payment = {"id": "pay_evt_2", "order_id": "order_evt_2", "amount": 100, "currency": "INR",
               "status": "captured"}
    raw, signature = stub.build_capture_webhook(payment, SECRET)
    inflated = raw.replace(b'"amount": 100', b'"amount": 99999')
    assert inflated != raw, "the fixture stopped matching the encoder"
    assert verify_webhook_signature(inflated, signature, SECRET) is False


def test_signature_from_another_secret_is_rejected():
    payment = {"id": "pay_evt_3", "order_id": "order_evt_3", "amount": 100, "currency": "INR",
               "status": "captured"}
    raw, _ = stub.build_capture_webhook(payment, SECRET)
    _, other = stub.build_capture_webhook(payment, "a-different-secret")
    assert verify_webhook_signature(raw, other, SECRET) is False
    assert verify_webhook_signature(raw, "", SECRET) is False
