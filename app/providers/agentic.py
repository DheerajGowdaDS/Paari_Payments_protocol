"""Provider-side agentic payment boundary (Paari v2, Sprint 4 completion).

This is intentionally a capability interface, not a fake implementation.
Paari can only perform fully autonomous settlement when the underlying payment
provider exposes a provider-recognized mandate / tokenized instrument that was
previously consented to by the user.

The interface below is COMPLETE per the v2 plan so an adapter can be written
against a documented provider contract without inventing endpoints. Until a
provider actually exposes an agentic/mandated payment API and Paari has
program access, the only Razorpay implementation is the NOT_CONFIGURED stub
below: it refuses every operation rather than pretending to settle.

Adapters must never hold raw card credentials - only provider-issued
references (mandate ids, customer references, instrument tokens).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any


class AdapterStatus(str, Enum):
    """Honest capability status for an adapter.

    NOT_CONFIGURED means the provider's agentic API is not available to this
    deployment: every agentic operation must refuse. CONFIGURED means the
    adapter is bound to a real, documented provider API.
    """

    NOT_CONFIGURED = "not_configured"
    CONFIGURED = "configured"


class AgenticPaymentProvider(ABC):
    """Provider-native agentic payment operations (complete surface)."""

    @abstractmethod
    def status(self) -> AdapterStatus:
        """Whether this adapter is bound to a real provider capability."""

    @abstractmethod
    def create_or_bind_mandate(self, *, mandate_id: str, user_reference: str,
                               max_amount_minor_units: int, currency: str,
                               metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create/bind a provider-side mandate or return its existing reference."""

    @abstractmethod
    def validate_mandate(self, provider_mandate_ref: str) -> dict[str, Any]:
        """Ask the provider whether its mandate is currently valid/spendable."""

    @abstractmethod
    def authorize_payment(self, *, authorization_id: str, provider_mandate_ref: str,
                          amount_minor_units: int, currency: str,
                          merchant_reference: str,
                          idempotency_key: str) -> dict[str, Any]:
        """Request provider authorization for one payment under the mandate."""

    @abstractmethod
    def capture_payment(self, *, provider_payment_ref: str,
                        amount_minor_units: int, currency: str,
                        idempotency_key: str) -> dict[str, Any]:
        """Capture a provider-authorized payment (provider-side funds move)."""

    @abstractmethod
    def get_payment(self, provider_payment_ref: str) -> dict[str, Any]:
        """Fetch one provider payment by its provider reference."""

    @abstractmethod
    def verify_webhook(self, raw_body: bytes, signature: str) -> bool:
        """Verify a provider webhook delivery. Pure function of (body, signature)."""

    @abstractmethod
    def revoke_mandate(self, provider_mandate_ref: str) -> dict[str, Any]:
        """Revoke the provider-side mandate when supported."""

    @abstractmethod
    def supports_autonomous_settlement(self) -> bool:
        """Whether the adapter supports no-human-checkout settlement."""


class NotConfiguredAgenticProvider(AgenticPaymentProvider):
    """Refuses every agentic operation: honest placeholder until a provider
    contract is actually available. Never fakes settlement."""

    def status(self) -> AdapterStatus:
        return AdapterStatus.NOT_CONFIGURED

    def create_or_bind_mandate(self, *, mandate_id: str, user_reference: str,
                               max_amount_minor_units: int, currency: str,
                               metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        raise NotImplementedError(
            "Agentic mandate creation is NOT_CONFIGURED: no provider agentic API "
            "is available to this deployment. Wire a real adapter only against a "
            "documented provider contract."
        )

    def validate_mandate(self, provider_mandate_ref: str) -> dict[str, Any]:
        raise NotImplementedError(
            "Agentic mandate validation is NOT_CONFIGURED: no provider agentic API "
            "is available to this deployment."
        )

    def authorize_payment(self, *, authorization_id: str, provider_mandate_ref: str,
                          amount_minor_units: int, currency: str,
                          merchant_reference: str,
                          idempotency_key: str) -> dict[str, Any]:
        raise NotImplementedError(
            "Agentic payment authorization is NOT_CONFIGURED: no provider agentic "
            "API is available to this deployment. Settlement remains at the "
            "PROVIDER_SUBMITTED boundary via the existing order/checkout flow."
        )

    def capture_payment(self, *, provider_payment_ref: str,
                        amount_minor_units: int, currency: str,
                        idempotency_key: str) -> dict[str, Any]:
        raise NotImplementedError(
            "Agentic capture is NOT_CONFIGURED: capturing requires a real "
            "provider-recognized mandate. Paari never simulates money movement."
        )

    def get_payment(self, provider_payment_ref: str) -> dict[str, Any]:
        raise NotImplementedError(
            "Agentic payment lookup is NOT_CONFIGURED: no provider agentic API "
            "is available to this deployment."
        )

    def verify_webhook(self, raw_body: bytes, signature: str) -> bool:
        raise NotImplementedError(
            "Agentic webhook verification is NOT_CONFIGURED: no provider agentic "
            "API is available to this deployment."
        )

    def revoke_mandate(self, provider_mandate_ref: str) -> dict[str, Any]:
        raise NotImplementedError(
            "Agentic mandate revocation is NOT_CONFIGURED: no provider agentic API "
            "is available to this deployment."
        )

    def supports_autonomous_settlement(self) -> bool:
        return False


class AgenticProviderUnavailable(RuntimeError):
    """Raised when autonomous settlement is attempted on a deployment that has
    no provider agentic API bound. Always a refusal, never a simulated payment."""


def _resolve_agentic_spec(org_id: str | None) -> str:
    import os
    import re

    resolved = org_id or "default"
    if resolved != "default":
        tag = re.sub(r"\W", "", resolved).upper()
        # Non-default tenants MUST have an explicitly scoped adapter.
        # Falling back to the global adapter would permit one tenant to
        # accidentally use another tenant's provider capability.
        return os.environ.get(f"PAARI_AGENTIC_PROVIDER__{tag}", "").strip()
    return (os.environ.get("PAARI_AGENTIC_PROVIDER") or "").strip()


def get_agentic_provider(org_id: str | None = None) -> AgenticPaymentProvider:
    """Single DI seam for the agentic boundary, mirroring the shape of
    `app.providers.base.get_provider` and `app.provider_accounts
    .get_provider_for_org`.

    Resolution order:

    1. `PAARI_AGENTIC_PROVIDER__{ORG_TAG}=module:ClassName` for the specific
       org (same pattern as `RAZORPAY_KEY_ID__{TAG}` in provider_accounts).
    2. `PAARI_AGENTIC_PROVIDER=module:ClassName` as the global default.
    3. otherwise the honest `NotConfiguredAgenticProvider`, which refuses every
       operation with `status() == NOT_CONFIGURED`.

    There is deliberately NO guessed Razorpay agentic implementation. A
    deployment without step 1 or 2 configured cannot settle autonomously, and
    `supports_autonomous_settlement()` returns False so callers can gate on it
    instead of discovering the refusal at payment time.
    """
    import importlib

    spec = _resolve_agentic_spec(org_id)
    if not spec:
        return NotConfiguredAgenticProvider()
    module_name, _, class_name = spec.partition(":")
    if not module_name or not class_name:
        raise AgenticProviderUnavailable(
            f"PAARI_AGENTIC_PROVIDER={spec!r} is malformed; expected 'module:ClassName'"
        )
    try:
        module = importlib.import_module(module_name)
        adapter_cls = getattr(module, class_name)
    except (ImportError, AttributeError) as exc:
        raise AgenticProviderUnavailable(
            f"PAARI_AGENTIC_PROVIDER={spec!r} could not be loaded: {exc}"
        ) from exc
    if not (isinstance(adapter_cls, type) and issubclass(adapter_cls, AgenticPaymentProvider)):
        raise AgenticProviderUnavailable(
            f"{spec} is not a subclass of AgenticPaymentProvider"
        )
    return adapter_cls()


def autonomous_settlement_configured() -> bool:
    """Cheap capability probe for health checks and startup logs."""
    try:
        return get_agentic_provider().supports_autonomous_settlement()
    except AgenticProviderUnavailable:
        return False
