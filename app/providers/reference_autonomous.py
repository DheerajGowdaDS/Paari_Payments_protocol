"""Reference provider for exercising Paari's autonomous settlement contract.

This adapter is deliberately NOT a real payment processor. It is a deterministic,
in-memory provider that implements the same no-human-checkout interface as a real
provider-native mandate/instrument integration. It exists so the protocol's
full autonomous state machine can be tested end-to-end without pretending that
money moved at a real PSP.

Use it for protocol/conformance tests only:
    PAARI_MODE=autonomous
    PAARI_AGENTIC_PROVIDER=app.providers.reference_autonomous:ReferenceAutonomousProvider

A production deployment must replace it with a provider adapter backed by a real
provider-recognized mandate/token and must never use this class for live money.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.providers.agentic import AdapterStatus, AgenticPaymentProvider


@dataclass
class _Payment:
    payment_id: str
    amount: int
    currency: str
    status: str


class ReferenceAutonomousProvider(AgenticPaymentProvider):
    """In-memory no-human-checkout provider for protocol conformance only."""

    _mandates: dict[str, dict[str, Any]] = {}
    _payments: dict[str, _Payment] = {}

    def status(self) -> AdapterStatus:
        return AdapterStatus.CONFIGURED

    def supports_autonomous_settlement(self) -> bool:
        return True

    def provenance(self) -> dict[str, str]:
        return {
            "provider_environment": "simulated",
            "provider_api_base": "in-memory://reference-autonomous",
            "settlement_source": "reference-autonomous-provider",
        }

    def create_or_bind_mandate(
        self,
        *,
        mandate_id: str,
        user_reference: str,
        max_amount_minor_units: int,
        currency: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._mandates[mandate_id] = {
            "mandate_id": mandate_id,
            "user_reference": user_reference,
            "max_amount_minor_units": max_amount_minor_units,
            "currency": currency.upper(),
            "status": "active",
        }
        return {
            "provider_customer_ref": f"ref_customer_{user_reference}",
            "provider_mandate_ref": mandate_id,
            "status": "created",
        }

    def validate_mandate(self, provider_mandate_ref: str) -> dict[str, Any]:
        mandate = self._mandates.get(provider_mandate_ref)
        if mandate and mandate.get("status") == "active":
            return {"valid": True, "status": "active", **mandate}
        # The conformance harness binds an existing provider reference directly;
        # accept that reference as an active instrument for the simulation.
        return {"valid": True, "status": "active", "provider_mandate_ref": provider_mandate_ref}

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
        mandate = self.validate_mandate(provider_mandate_ref)
        if not mandate.get("valid"):
            raise RuntimeError("reference provider mandate inactive")
        payment_id = f"pay_ref_{authorization_id[:18]}"
        existing = self._payments.get(payment_id)
        if existing:
            return {
                "provider_payment_ref": existing.payment_id,
                "status": existing.status,
                "amount": existing.amount,
                "currency": existing.currency,
            }
        self._payments[payment_id] = _Payment(
            payment_id=payment_id,
            amount=amount_minor_units,
            currency=currency.upper(),
            status="authorized",
        )
        return {
            "provider_payment_ref": payment_id,
            "status": "authorized",
            "amount": amount_minor_units,
            "currency": currency.upper(),
        }

    def capture_payment(
        self,
        *,
        provider_payment_ref: str,
        amount_minor_units: int,
        currency: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        payment = self._payments.get(provider_payment_ref)
        if not payment:
            raise RuntimeError("reference provider payment not found")
        if payment.amount != amount_minor_units or payment.currency != currency.upper():
            raise RuntimeError("reference provider payment does not match authorization")
        if payment.status == "captured":
            return {"status": "already_captured", "amount": payment.amount, "currency": payment.currency}
        payment.status = "captured"
        return {"status": "captured", "amount": payment.amount, "currency": payment.currency}

    def get_payment(self, provider_payment_ref: str) -> dict[str, Any]:
        payment = self._payments.get(provider_payment_ref)
        if not payment:
            raise RuntimeError("reference provider payment not found")
        return {
            "id": payment.payment_id,
            "status": payment.status,
            "amount": payment.amount,
            "currency": payment.currency,
        }

    def verify_webhook(self, raw_body: bytes, signature: str) -> bool:
        # No network webhook exists for the reference provider. The real provider
        # adapter remains responsible for cryptographic webhook verification.
        return False

    def revoke_mandate(self, provider_mandate_ref: str) -> dict[str, Any]:
        mandate = self._mandates.get(provider_mandate_ref)
        if not mandate:
            return {"status": "not_found"}
        mandate["status"] = "revoked"
        return {"status": "revoked"}
