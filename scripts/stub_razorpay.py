"""Local stand-in for the Razorpay orders + payments API, and a webhook signer.

Lets the LLM E2E run all the way to PAID with no account credentials and no human.
This is a simulation: no money exists here and nothing about real Razorpay behaviour is
proven by it. Point the server at real RAZORPAY_* credentials to test the real provider.

The simulated roles are separated deliberately:
  * POST /v1/orders                 -> what Paari calls when it submits an authorization
  * POST /v1/payments               -> the payer's card authorisation (harness, not agent)
  * POST /v1/payments/{id}/capture  -> the issuer's capture   (harness, not agent)
  * build_capture_webhook()         -> the provider's signed notification to Paari

    python scripts/stub_razorpay.py 9911
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ORDERS: dict[str, dict] = {}
PAYMENTS: dict[str, dict] = {}
_counter = 0
_lock = threading.Lock()

TRAILING_ID = re.compile(r"^/orders/([^/]+)$")
TRAILING_ORDER_PAYMENTS = re.compile(r"^/orders/([^/]+)/payments$")
TRAILING_PAYMENT = re.compile(r"^/payments/([^/]+)$")
TRAILING_CAPTURE = re.compile(r"^/payments/([^/]+)/capture$")


def _next_id(prefix: str) -> str:
    global _counter
    with _lock:
        _counter += 1
        return f"{prefix}_SIM{_counter:05d}"


def create_order(amount: int, currency: str, receipt: str = "", notes: dict | None = None) -> dict:
    order = {
        "id": _next_id("order"),
        "entity": "order",
        "amount": int(amount),
        "amount_paid": 0,
        "amount_due": int(amount),
        "currency": currency,
        "receipt": receipt,
        "status": "created",
        "notes": notes or {},
    }
    ORDERS[order["id"]] = order
    return order


def create_payment(order_id: str, amount: int, currency: str) -> dict | None:
    order = ORDERS.get(order_id)
    if order is None:
        return None
    payment = {
        "id": _next_id("pay"),
        "entity": "payment",
        "order_id": order_id,
        "amount": int(amount),
        "amount_paid": 0,
        "currency": currency,
        "status": "created",
        "method": "card",
    }
    PAYMENTS[payment["id"]] = payment
    return payment


def capture_payment(payment_id: str, amount: int, currency: str) -> dict | None:
    """Marks the payment captured and the order paid, mirroring the real API."""
    payment = PAYMENTS.get(payment_id)
    if payment is None:
        return None
    order = ORDERS.get(payment["order_id"])
    payment["status"] = "captured"
    payment["amount_paid"] = int(amount)
    if order is not None:
        order["status"] = "paid"
        order["amount_paid"] = order["amount"]
        order["amount_due"] = 0
    return payment


def payments_for_order(order_id: str) -> list[dict]:
    return [p for p in PAYMENTS.values() if p["order_id"] == order_id]


def sign_body(raw: bytes, secret: str) -> str:
    return hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()


def build_capture_webhook(payment: dict, secret: str) -> tuple[bytes, str]:
    """Returns (raw_body, signature) exactly as Razorpay signs payment.captured.

    Amount and currency are what Paari checks against the authorization, so a signed
    event for a different value must still be refused.
    """
    body = {
        "entity": "event",
        "id": _next_id("evt"),
        "event": "payment.captured",
        "created_at": 1780000000,
        "payload": {"payment": {"entity": dict(payment)}},
    }
    raw = json.dumps(body).encode()
    return raw, sign_body(raw, secret)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            return json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return {}

    @property
    def _authed(self) -> bool:
        return self.headers.get("Authorization", "").startswith("Basic ")

    def _path(self) -> str:
        parsed = urlparse(self.path)
        path = parsed.path
        return path[3:] if path.startswith("/v1") else path

    def do_GET(self):  # noqa: N802 - http.server naming
        if not self._authed:
            return self._send(401, {"error": {"code": "BAD_REQUEST_ERROR",
                                              "description": "Authentication failed"}})
        path, query = self._path(), parse_qs(urlparse(self.path).query)
        if path == "/orders":
            items = list(ORDERS.values())
            receipt = (query.get("receipt") or [""])[0]
            if receipt:
                items = [o for o in items if o.get("receipt") == receipt]
            return self._send(200, {"entity": "collection", "count": len(items), "items": items})
        match = TRAILING_ORDER_PAYMENTS.match(path)
        if match:
            items = payments_for_order(match.group(1))
            return self._send(200, {"entity": "collection", "count": len(items), "items": items})
        match = TRAILING_ID.match(path)
        if match:
            order = ORDERS.get(match.group(1))
            return (self._send(200, order) if order
                    else self._send(404, {"error": {"description": "order not found"}}))
        match = TRAILING_PAYMENT.match(path)
        if match:
            payment = PAYMENTS.get(match.group(1))
            return (self._send(200, payment) if payment
                    else self._send(404, {"error": {"description": "payment not found"}}))
        return self._send(404, {"error": {"description": f"no route for GET {path}"}})

    def do_POST(self):  # noqa: N802
        if not self._authed:
            return self._send(401, {"error": {"code": "BAD_REQUEST_ERROR",
                                              "description": "Authentication failed"}})
        path, payload = self._path(), self._read_json()
        if path == "/orders":
            amount = payload.get("amount")
            if not isinstance(amount, int) or amount <= 0:
                return self._send(400, {"error": {"description": "amount must be a positive integer"}})
            return self._send(200, create_order(amount, str(payload.get("currency", "INR")),
                                                str(payload.get("receipt", "")),
                                                payload.get("notes") or {}))
        if path == "/payments":
            payment = create_payment(str(payload.get("order_id", "")),
                                     int(payload.get("amount") or 0),
                                     str(payload.get("currency", "INR")))
            return (self._send(200, payment) if payment
                    else self._send(404, {"error": {"description": "unknown order_id"}}))
        match = TRAILING_CAPTURE.match(path)
        if match:
            payment = capture_payment(match.group(1), int(payload.get("amount") or 0),
                                      str(payload.get("currency", "INR")))
            return (self._send(200, payment) if payment
                    else self._send(404, {"error": {"description": "unknown payment_id"}}))
        return self._send(404, {"error": {"description": f"no route for POST {path}"}})

    def log_message(self, *args) -> None:
        pass


def serve(port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


if __name__ == "__main__":
    listen = int(sys.argv[1]) if len(sys.argv) > 1 else 9911
    print(f"stub razorpay listening on 127.0.0.1:{listen}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", listen), Handler).serve_forever()
