"""Provider-native Razorpay agentic settlement adapter.

IMPORTANT: Razorpay exposes several mandate/recurring products, but the exact
server-to-server debit capability is account/product dependent. Paari MUST NOT
invent or assume an endpoint. This adapter therefore requires an explicitly
configured provider contract before it reports autonomous capability.

Required configuration when a real Razorpay agentic contract is provisioned:
    RAZORPAY_KEY_ID
    RAZORPAY_KEY_SECRET
    RAZORPAY_WEBHOOK_SECRET
    RAZORPAY_AGENTIC_CAPABILITY_CONFIRMED=1
    RAZORPAY_AGENTIC_AUTHORIZE_PATH=/provider-specific/path
    RAZORPAY_AGENTIC_CAPTURE_PATH=/provider-specific/{payment_id}/capture   # optional
    RAZORPAY_AGENTIC_TOKEN_LIST_PATH=/customers/{customer_id}/tokens        # if needed

The adapter stores only provider-issued references. It never receives raw card,
CVV, UPI PIN, or bank credentials.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from typing import Any

import httpx

from app.providers.agentic import AdapterStatus, AgenticPaymentProvider
from app.providers.razorpay import PRODUCTION_API_BASE


class RazorpayAgenticConfigError(RuntimeError):
    pass


def _get_config() -> dict[str, Any]:
    key_id = os.environ.get("RAZORPAY_KEY_ID", "")
    key_secret = os.environ.get("RAZORPAY_KEY_SECRET", "")
    webhook_secret = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")
    base = os.environ.get("RAZORPAY_API_BASE", PRODUCTION_API_BASE).rstrip("/")
    confirmed = os.environ.get("RAZORPAY_AGENTIC_CAPABILITY_CONFIRMED") == "1"
    authorize_path = os.environ.get("RAZORPAY_AGENTIC_AUTHORIZE_PATH", "").strip()
    capture_path = os.environ.get("RAZORPAY_AGENTIC_CAPTURE_PATH", "").strip()
    token_list_path = os.environ.get("RAZORPAY_AGENTIC_TOKEN_LIST_PATH", "").strip()
    payment_path = os.environ.get("RAZORPAY_AGENTIC_PAYMENT_PATH", "").strip()
    if not key_id or not key_secret:
        raise RazorpayAgenticConfigError(
            "RAZORPAY_KEY_ID/RAZORPAY_KEY_SECRET must be configured"
        )
    if not confirmed or not authorize_path or not payment_path:
        raise RazorpayAgenticConfigError(
            "Razorpay agentic capability is not configured. Set "
            "RAZORPAY_AGENTIC_CAPABILITY_CONFIRMED=1 only after Razorpay has "
            "enabled/provided the documented server-to-server mandate/debit "
            "contract, and set the exact documented authorize and payment-read paths."
        )
    return {
        "key_id": key_id,
        "key_secret": key_secret,
        "webhook_secret": webhook_secret,
        "base": base,
        "authorize_path": authorize_path,
        "capture_path": capture_path,
        "token_list_path": token_list_path,
        "payment_path": payment_path,
    }


def _verify_webhook_signature(raw_body: bytes, signature: str, secret: str) -> bool:
    if not raw_body or not signature or not secret:
        return False
    expected = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return secrets.compare_digest(signature, expected)


def _expand(path_template: str, **values: str) -> str:
    try:
        return path_template.format(**values)
    except KeyError as exc:
        raise RazorpayAgenticConfigError(
            f"Razorpay agentic path is missing template value {exc.args[0]!r}: {path_template!r}"
        ) from exc


class RazorpayAgenticProvider(AgenticPaymentProvider):
    """Adapter for a *real, explicitly provisioned* Razorpay agentic contract.

    Paari does not claim that a normal Razorpay Test-Mode order is an autonomous
    payment. The adapter is considered capable only when the deployment
    explicitly attests that the required provider contract is enabled and gives
    Paari the exact provider paths. This prevents unsupported endpoints from
    being guessed in application code.
    """

    def __init__(self, client: httpx.Client | None = None):
        self._client = client

    @property
    def _config(self) -> dict[str, Any]:
        return _get_config()

    def _get_client(self) -> tuple[httpx.Client, bool]:
        cfg = self._config
        if self._client is not None:
            return self._client, False
        return httpx.Client(
            base_url=cfg["base"],
            auth=(cfg["key_id"], cfg["key_secret"]),
            timeout=15.0,
        ), True

    def status(self) -> AdapterStatus:
        try:
            _get_config()
            return AdapterStatus.CONFIGURED
        except RazorpayAgenticConfigError:
            return AdapterStatus.NOT_CONFIGURED

    def create_or_bind_mandate(
        self,
        *,
        mandate_id: str,
        user_reference: str,
        max_amount_minor_units: int,
        currency: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create/bind a provider customer reference for enrollment.

        A Razorpay customer ID is NOT itself proof that a spendable mandate
        exists. The returned customer reference is therefore only an
        enrollment/binding handle; the actual provider mandate/token must be
        created through the provider-enabled consent flow before autonomous
        debit is attempted.
        """
        cfg = self._config
        client, close = self._get_client()
        try:
            r = client.get(f"/customers/{user_reference}")
            if r.status_code == 200:
                data = r.json()
                return {
                    "provider_customer_ref": data["id"],
                    "provider_mandate_ref": data["id"],
                    "status": "exists",
                }
            payload = {
                "name": (metadata or {}).get("name", f"Paari User {mandate_id[:8]}"),
                "email": (metadata or {}).get("email", ""),
                "contact": (metadata or {}).get("contact", ""),
                "notes": {
                    "paari_mandate_id": mandate_id,
                    "paari_user_reference": user_reference,
                    "paari_max_amount_minor_units": max_amount_minor_units,
                    "paari_currency": currency.upper(),
                },
            }
            payload = {k: v for k, v in payload.items() if v}
            r = client.post("/customers", json=payload)
            r.raise_for_status()
            data = r.json()
            return {
                "provider_customer_ref": data["id"],
                "provider_mandate_ref": data["id"],
                "status": "created",
            }
        finally:
            if close:
                client.close()

    def validate_mandate(self, provider_mandate_ref: str) -> dict[str, Any]:
        """Validate a provider mandate through the configured contract.

        A provider-specific mandate status endpoint may be supplied using
        RAZORPAY_AGENTIC_VALIDATE_PATH=/.../{provider_mandate_ref}. If omitted,
        mandate validation falls back to the configured token-list path.
        """
        cfg = self._config
        validate_path = os.environ.get("RAZORPAY_AGENTIC_VALIDATE_PATH", "").strip()
        token_list_path = cfg.get("token_list_path")
        client, close = self._get_client()
        try:
            if validate_path:
                r = client.get(_expand(validate_path, provider_mandate_ref=provider_mandate_ref))
                if r.status_code != 200:
                    return {"valid": False, "status": "inactive", "reason": r.text[:300]}
                data = r.json()
                return {
                    "valid": str(data.get("status", "active")).lower() in {"active", "authorized", "valid"},
                    "status": data.get("status", "active"),
                    **data,
                }
            path = _expand(token_list_path, customer_id=provider_mandate_ref)
            r = client.get(path)
            r.raise_for_status()
            tokens = r.json().get("items", [])
            active = [t for t in tokens if str(t.get("status", "")).lower() == "active"]
            return {
                "valid": bool(active),
                "status": "active" if active else "inactive",
                "customer_id": provider_mandate_ref,
                "active_token_count": len(active),
            }
        finally:
            if close:
                client.close()

    def authorize_payment(
        self,
        *,
        authorization_id: str,
        provider_mandate_ref: str,
        amount_minor_units: int,
        currency: str,
        merchant_reference: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        if amount_minor_units <= 0:
            raise ValueError("amount must be positive")
        cfg = self._config
        client, close = self._get_client()
        try:
            # Tokenized-card recurring is supported as a provider-contract mode
            # when the account exposes a token list and recurring debit API.
            # Crucially, only ACTIVE tokens are eligible; expired/inactive tokens
            # are never silently selected.
            token_id = None
            token_list_path = cfg.get("token_list_path")
            if token_list_path:
                r = client.get(_expand(token_list_path, customer_id=provider_mandate_ref))
                r.raise_for_status()
                tokens = r.json().get("items", [])
                active_tokens = [
                    token for token in tokens
                    if str(token.get("status", "")).lower() == "active"
                ]
                if not active_tokens:
                    raise RazorpayAgenticConfigError(
                        "No tokens found with status=active for provider mandate/customer."
                    )
                token_id = active_tokens[0].get("id")
                if not token_id:
                    raise RazorpayAgenticConfigError("Provider returned an active token without an id")

            payload_mode = os.environ.get(
                "RAZORPAY_AGENTIC_AUTH_PAYLOAD_MODE", "razorpay_recurring_token"
            ).strip().lower()
            if payload_mode == "provider_mandate":
                payload = {
                    "mandate_ref": provider_mandate_ref,
                    "amount": amount_minor_units,
                    "currency": currency,
                    "notes": {
                        "paari_authorization_id": authorization_id,
                        "paari_merchant_reference": merchant_reference,
                    },
                }
            else:
                if not token_id:
                    raise RazorpayAgenticConfigError(
                        "RAZORPAY_AGENTIC_TOKEN_LIST_PATH must be configured for tokenized recurring mode"
                    )
                payload = {
                    "customer_id": provider_mandate_ref,
                    "token_id": token_id,
                    "amount": amount_minor_units,
                    "currency": currency,
                    "recurring": "1",
                    "notes": {
                        "paari_authorization_id": authorization_id,
                        "paari_merchant_reference": merchant_reference,
                    },
                }
            r = client.post(
                cfg["authorize_path"],
                json=payload,
                headers={"X-Razorpay-Idempotency-Key": idempotency_key},
            )
            if r.status_code == 404:
                raise RazorpayAgenticConfigError(
                    "Configured Razorpay agentic authorization path returned 404. "
                    "The configured provider contract is not available to this account."
                )
            r.raise_for_status()
            data = r.json()
            payment_ref = data.get("id") or data.get("payment_id") or data.get("payment_ref")
            if not payment_ref:
                raise RazorpayAgenticConfigError(
                    "Provider agentic authorization response contained no payment reference"
                )
            return {
                "provider_payment_ref": payment_ref,
                "status": data.get("status", "authorized"),
                "token_id": token_id,
                "amount": data.get("amount", amount_minor_units),
                "currency": data.get("currency", currency),
                "raw": data,
            }
        finally:
            if close:
                client.close()

    def capture_payment(
        self,
        *,
        provider_payment_ref: str,
        amount_minor_units: int,
        currency: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        cfg = self._config
        client, close = self._get_client()
        try:
            payment = self.get_payment(provider_payment_ref)
            if str(payment.get("status", "")).lower() == "captured":
                return {"status": "already_captured", "amount": payment.get("amount"), "currency": payment.get("currency")}
            path = cfg.get("capture_path")
            if not path:
                # Never guess a provider capture endpoint. If the configured
                # provider contract auto-captures, the preceding read is the
                # only evidence available here. Otherwise the deployment must
                # supply the exact documented capture path.
                status = str(payment.get("status", "unknown")).lower()
                if status in {"captured", "paid", "completed"}:
                    return {"status": status, "amount": payment.get("amount"), "currency": payment.get("currency")}
                raise RazorpayAgenticConfigError(
                    "Provider payment is not captured and RAZORPAY_AGENTIC_CAPTURE_PATH "
                    "is not configured; Paari refuses to guess a capture endpoint."
                )
            r = client.post(
                _expand(path, payment_id=provider_payment_ref),
                json={"amount": amount_minor_units, "currency": currency},
                headers={"X-Razorpay-Idempotency-Key": idempotency_key},
            )
            if r.status_code == 404:
                raise RazorpayAgenticConfigError(
                    "Configured Razorpay agentic capture path returned 404; "
                    "the provider-native capture contract is not available to this account."
                )
            r.raise_for_status()
            data = r.json()
            return {
                "status": data.get("status", "unknown"),
                "amount": data.get("amount", amount_minor_units),
                "currency": data.get("currency", currency),
            }
        finally:
            if close:
                client.close()

    def get_payment(self, provider_payment_ref: str) -> dict[str, Any]:
        cfg = self._config
        client, close = self._get_client()
        try:
            path = cfg["payment_path"]
            r = client.get(_expand(path, payment_id=provider_payment_ref))
            r.raise_for_status()
            return r.json()
        finally:
            if close:
                client.close()

    def verify_webhook(self, raw_body: bytes, signature: str) -> bool:
        cfg = self._config
        return _verify_webhook_signature(raw_body, signature, cfg["webhook_secret"])

    def revoke_mandate(self, provider_mandate_ref: str) -> dict[str, Any]:
        """Revoke provider token(s) for a bound customer/mandate reference.

        A provider-specific revoke endpoint can be configured. Otherwise the
        adapter may revoke all provider tokens exposed by the configured token
        list endpoint. This never deletes a generic customer as a proxy for
        revocation.
        """
        cfg = self._config
        path = os.environ.get("RAZORPAY_AGENTIC_REVOKE_PATH", "").strip()
        client, close = self._get_client()
        try:
            if path:
                r = client.post(_expand(path, provider_mandate_ref=provider_mandate_ref), json={})
                r.raise_for_status()
                return r.json() if r.content else {"status": "revoked"}
            token_list_path = cfg.get("token_list_path")
            if not token_list_path:
                raise RazorpayAgenticConfigError("Provider token/revoke capability is not configured")
            r = client.get(_expand(token_list_path, customer_id=provider_mandate_ref))
            r.raise_for_status()
            tokens = r.json().get("items", [])
            deleted = 0
            for token in tokens:
                token_id = token.get("id")
                if not token_id:
                    continue
                rr = client.delete(f"/customers/{provider_mandate_ref}/tokens/{token_id}")
                if rr.status_code in (200, 204):
                    deleted += 1
            return {"status": "revoked", "tokens_deleted": deleted}
        finally:
            if close:
                client.close()

    def supports_autonomous_settlement(self) -> bool:
        if self.status() != AdapterStatus.CONFIGURED:
            return False
        payload_mode = os.environ.get(
            "RAZORPAY_AGENTIC_AUTH_PAYLOAD_MODE", "razorpay_recurring_token"
        ).strip().lower()
        if payload_mode == "razorpay_recurring_token" and not os.environ.get(
            "RAZORPAY_AGENTIC_TOKEN_LIST_PATH", ""
        ).strip():
            return False
        return True
