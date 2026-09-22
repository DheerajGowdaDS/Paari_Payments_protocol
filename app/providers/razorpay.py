"""Real Razorpay provider over httpx. No mock path."""
import hashlib
import hmac
import os
import secrets

import httpx

from app.providers.base import PaymentProvider


class RazorpayConfigError(RuntimeError):
    pass


def get_config() -> dict:
    key_id = os.environ.get("RAZORPAY_KEY_ID", "")
    key_secret = os.environ.get("RAZORPAY_KEY_SECRET", "")
    webhook_secret = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")
    base = os.environ.get("RAZORPAY_API_BASE", "https://api.razorpay.com/v1").rstrip("/")
    if not key_id or not key_secret:
        raise RazorpayConfigError(
            "RAZORPAY_KEY_ID/RAZORPAY_KEY_SECRET must be set for Phase 5 execution"
        )
    return {
        "key_id": key_id,
        "key_secret": key_secret,
        "webhook_secret": webhook_secret,
        "base": base,
    }


def create_order(
    authorization_id: str,
    amount_minor_units: int,
    currency: str,
    notes: dict | None,
    client: httpx.Client | None = None,
) -> dict:
    cfg = get_config()
    if amount_minor_units <= 0:
        raise ValueError("amount must be positive")
    payload = {
        "amount": amount_minor_units,
        "currency": currency,
        "receipt": authorization_id,
        "notes": notes or {},
    }
    own_client = client or httpx.Client(
        base_url=cfg["base"], auth=(cfg["key_id"], cfg["key_secret"]), timeout=10.0
    )
    close = client is None
    try:
        r = own_client.post("/orders", json=payload)
        r.raise_for_status()
        data = r.json()
        if "id" not in data:
            raise RuntimeError(f"Razorpay order response missing id: {data!r}")
        return data
    finally:
        if close:
            own_client.close()


def verify_webhook_signature(raw_body: bytes, signature: str, secret: str) -> bool:
    if not raw_body or not signature or not secret:
        return False
    expected = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return bool(signature) and secrets.compare_digest(signature, expected)


class RazorpayAdapter(PaymentProvider):
    """PaymentProvider over the Razorpay REST API.

    Pass an httpx.Client explicitly in tests (MockTransport); in production
    the adapter builds and owns its client from get_config().
    """

    def __init__(self, client: httpx.Client | None = None,
                 key_id: str = "", key_secret: str = "", webhook_secret: str = ""):
        self._client = client
        self._key_id_override = key_id
        self._key_secret_override = key_secret
        self._webhook_secret_override = webhook_secret

    @property
    def key_id(self) -> str:
        return self._key_id_override or os.environ.get("RAZORPAY_KEY_ID", "")

    @property
    def key_secret(self) -> str:
        return self._key_secret_override or os.environ.get("RAZORPAY_KEY_SECRET", "")

    def _request_client(self) -> tuple[httpx.Client, bool]:
        if self._client is not None:
            return self._client, False
        cfg = get_config()
        return httpx.Client(
            base_url=cfg["base"],
            auth=(self._key_id_override or cfg["key_id"],
                  self._key_secret_override or cfg["key_secret"]),
            timeout=10.0,
        ), True

    def create_payment(
        self,
        authorization_id: str,
        amount_minor_units: int,
        currency: str,
        notes: dict | None,
    ) -> dict:
        if amount_minor_units <= 0:
            raise ValueError("amount must be positive")
        client, close = self._request_client()
        try:
            r = client.post(
                "/orders",
                json={
                    "amount": amount_minor_units,
                    "currency": currency,
                    "receipt": authorization_id,
                    "notes": notes or {},
                },
                headers={"X-Razorpay-Idempotency-Key": authorization_id},
            )
            r.raise_for_status()
            data = r.json()
            if "id" not in data:
                raise RuntimeError(f"Razorpay order response missing id: {data!r}")
            return data
        finally:
            if close:
                client.close()

    def get_payment(self, payment_id: str) -> dict:
        client, close = self._request_client()
        try:
            r = client.get(f"/payments/{payment_id}")
            r.raise_for_status()
            return r.json()
        finally:
            if close:
                client.close()

    def fetch_payments(self, order_id: str) -> list:
        client, close = self._request_client()
        try:
            r = client.get(f"/orders/{order_id}/payments")
            r.raise_for_status()
            return r.json().get("items", [])
        finally:
            if close:
                client.close()

    def fetch_order_by_receipt(self, receipt: str) -> dict | None:
        client, close = self._request_client()
        try:
            # Razorpay supports receipt filtering; use it instead of
            # scanning the account's first N orders. This keeps UNKNOWN
            # reconciliation bounded even on large merchant accounts.
            r = client.get("/orders", params={"receipt": receipt, "count": 1})
            r.raise_for_status()
            items = r.json().get("items", [])
            return items[0] if items else None
        finally:
            if close:
                client.close()

    def verify_webhook(self, raw_body: bytes, signature: str) -> bool:
        try:
            secret = self._webhook_secret_override or get_config().get("webhook_secret", "")
        except RazorpayConfigError:
            return False
        return verify_webhook_signature(raw_body, signature, secret)

    def refund(self, payment_id: str, amount_minor_units: int) -> dict:
        if amount_minor_units <= 0:
            raise ValueError("amount must be positive")
        client, close = self._request_client()
        try:
            r = client.post(f"/payments/{payment_id}/refund", json={"amount": amount_minor_units})
            r.raise_for_status()
            return r.json()
        finally:
            if close:
                client.close()

    def reconcile(self, authorization_id: str) -> dict:
        order = self.fetch_order_by_receipt(authorization_id)
        return {"found": order is not None, "order": order}
