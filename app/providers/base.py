"""Provider abstraction. Exactly one method per provider capability; the
routers call get_provider(), never a concrete adapter module directly."""
from abc import ABC, abstractmethod


class PaymentProvider(ABC):
    @abstractmethod
    def create_payment(
        self,
        authorization_id: str,
        amount_minor_units: int,
        currency: str,
        notes: dict | None,
    ) -> dict:
        """Create the provider-side payment object. Must be idempotent on
        authorization_id (retried consumes never double-create)."""

    @abstractmethod
    def get_payment(self, payment_id: str) -> dict:
        """Fetch one provider payment by its id."""

    @abstractmethod
    def fetch_payments(self, order_id: str) -> list:
        """All payment attempts on one order, oldest first (empty when none)."""

    @abstractmethod
    def fetch_order_by_receipt(self, receipt: str) -> dict | None:
        """Find an order the adapter never learned the id of (recovery path
        for PROVIDER_UNKNOWN). Returns None when nothing matches."""

    @abstractmethod
    def verify_webhook(self, raw_body: bytes, signature: str) -> bool:
        """Verify a webhook delivery. Pure function of (body, signature)."""

    @abstractmethod
    def refund(self, payment_id: str, amount_minor_units: int) -> dict:
        """Full or partial refund of a captured payment."""

    def cancel(self, order_id: str) -> dict:
        """Cancel an uncaptured order. Not every provider supports this -
        adapters without a provider-side cancel leave this raising."""
        raise NotImplementedError(f"{type(self).__name__} has no order cancel")

    @abstractmethod
    def reconcile(self, authorization_id: str) -> dict:
        """Answer 'what does the provider actually hold for this
        authorization?' as {"found": bool, "order": dict | None}."""


def get_provider() -> PaymentProvider:
    """Single Razorpay instance for now; the seam where a second provider
    (registry / per-org selection) plugs in later."""
    from app.providers.razorpay import RazorpayAdapter
    return RazorpayAdapter()
