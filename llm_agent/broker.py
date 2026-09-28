"""Key custody between the model and Paari.

The model only ever sees `execute(name, arguments)`. The `PaariAgentClient` — and with
it the agent's Ed25519 private key used for `X-Paari-Proof` — is reachable by nothing
the model controls, so a proposal becomes a signed request only after this module
vets it. Refusals here are deliberately redundant with server governance: the server
is still the authority, and this keeps a runaway model from spending API calls and
burning single-use authorizations on the way there.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from paari_agent.client import PaariProtocolError

from .tools import ToolArgsError, validate


class BrokerError(RuntimeError):
    pass


def _refuse(code: str, message: str, **extra) -> dict[str, Any]:
    return {"ok": False, "code": code, "error": message, **extra}


@dataclass(frozen=True)
class CausalContext:
    """Minimum LLM causal identifiers attached to a payment proposal.

    Identifier-only by design (v2 Sprint 7): never the conversation, never
    prompts, never secrets. Paari stores these on the intent row and the
    hash-chained audit so every payment is traceable from model tool
    invocation to governed execution.
    """
    run_id: str
    model: str
    tool_call_id: str | None = None
    tool_name: str | None = None


@dataclass(frozen=True)
class _Pending:
    authorization_id: str
    transaction_id: str
    merchant: str
    amount_minor_units: int
    currency: str
    merchant_category: str | None = None
    expires_at: str | None = None


@dataclass
class PaariBroker:
    client: Any
    max_amount_minor_units: int
    currency: str
    max_consumes: int = 1
    causal: CausalContext | None = None
    _pending: dict[str, _Pending] = field(default_factory=dict)
    _known_transactions: set[str] = field(default_factory=set)
    _consumes: int = 0

    def execute(self, name: str, args: Any) -> dict[str, Any]:
        """Run one model-issued tool call. Never raises: errors are data for the model."""
        try:
            clean = validate(name, args)
        except ToolArgsError as exc:
            return _refuse(exc.code, exc.message)
        handler = getattr(self, f"_tool_{name}", None)
        if handler is None:  # validate() already gates this; kept from drifting apart.
            return _refuse("UNKNOWN_TOOL", f"'{name}' has no handler")
        try:
            return handler(**clean)
        except PaariProtocolError as exc:
            return _refuse("SERVER_REJECTED", str(exc.detail), http_status=exc.status_code)

    def _card_limits(self) -> dict[str, Any]:
        card = getattr(self.client, "card", None) or {}
        return dict(card.get("limits") or {})

    def _tool_get_delegation(self) -> dict[str, Any]:
        card = getattr(self.client, "card", None) or {}
        return {
            "ok": True,
            "agent_id": getattr(self.client, "agent_id", None),
            "currency": self.currency,
            "max_amount_minor_units": self.max_amount_minor_units,
            "card_limits": self._card_limits(),
            "capabilities": card.get("capabilities") or [],
            "payments_remaining": self.max_consumes - self._consumes,
        }

    def _tool_get_payment_authority(self) -> dict[str, Any]:
        getter = getattr(self.client, "get_active_mandate", None)
        if getter is None:
            return _refuse("MANDATE_UNAVAILABLE", "this client does not expose the user payment mandate endpoint")
        try:
            mandate = getter()
        except PaariProtocolError as exc:
            if exc.status_code == 404:
                return _refuse("NO_ACTIVE_MANDATE", "there is no active user payment mandate")
            raise
        return {"ok": True, "authority_type": "user_payment_mandate", "mandate": mandate}

    def _tool_propose_payment(self, merchant: str, amount_minor_units: int, currency: str,
                              purpose: str = "", merchant_category: str | None = None) -> dict[str, Any]:
        if amount_minor_units <= 0:
            return _refuse("BAD_AMOUNT", "amount_minor_units must be positive",
                           max_amount_minor_units=self.max_amount_minor_units)
        if amount_minor_units > self.max_amount_minor_units:
            return _refuse("AMOUNT_OVER_LIMIT",
                           f"{amount_minor_units} exceeds the granted cap of "
                           f"{self.max_amount_minor_units} {self.currency}. Propose less, "
                           "or ask the parent to re-delegate.",
                           max_amount_minor_units=self.max_amount_minor_units,
                           currency=self.currency)
        if currency.upper() != self.currency.upper():
            return _refuse("UNSUPPORTED_CURRENCY", f"only {self.currency} is delegated to you",
                           currency=self.currency)

        transaction_id = f"TXN-llm-{uuid.uuid4().hex[:8]}"
        # Registered first: a rejected intent still leaves an audit trail worth reading.
        self._known_transactions.add(transaction_id)
        causal_kwargs = {}
        if self.causal is not None:
            causal_kwargs = {
                "llm_run_id": self.causal.run_id,
                "llm_model": self.causal.model,
                "llm_tool_call_id": self.causal.tool_call_id,
                "llm_tool_name": self.causal.tool_name or "propose_payment",
            }
        body = self.client.payment_intent(
            transaction_id=transaction_id,
            idempotency_key=f"idem-{transaction_id}",
            merchant=merchant,
            amount_minor_units=amount_minor_units,
            currency=self.currency,
            purpose=purpose or "llm agent payment",
            merchant_category=merchant_category,
            **causal_kwargs,
        )
        if not isinstance(body, dict):
            raise BrokerError("payment_intent returned a non-object body")

        decision = str(body.get("decision", "")).lower()
        reasons = [str(r) for r in (body.get("reasons") or [])]
        if decision != "allow":
            return {"ok": False, "status": "denied" if decision == "deny" else (decision or "unknown"),
                    "decision": decision, "reasons": reasons or ["no reason recorded"],
                    "mfa_required": bool(body.get("mfa_required")),
                    "transaction_id": transaction_id}

        authorization = body.get("authorization") or {}
        authorization_id = str(authorization.get("authorization_id") or "")
        if not authorization_id:
            return _refuse("NO_AUTHORIZATION",
                           "governance allowed this payment but issued no authorization to spend",
                           transaction_id=transaction_id)
        self._pending[authorization_id] = _Pending(
            authorization_id=authorization_id,
            transaction_id=transaction_id,
            merchant=merchant,
            amount_minor_units=amount_minor_units,
            currency=self.currency,
            merchant_category=merchant_category,
            expires_at=authorization.get("expires_at"),
        )
        return {"ok": True, "status": "authorized", "authorization_id": authorization_id,
                "transaction_id": transaction_id, "merchant": merchant,
                "amount_minor_units": amount_minor_units, "currency": self.currency,
                "expires_at": authorization.get("expires_at"),
                "next_step": "call confirm_payment with this authorization_id to execute it"}

    def _tool_confirm_payment(self, authorization_id: str) -> dict[str, Any]:
        if self._consumes >= self.max_consumes:
            return _refuse("CONSUME_LIMIT", "this run may execute at most "
                                            f"{self.max_consumes} payment(s)")
        pending = self._pending.pop(authorization_id, None)
        if pending is None:
            return _refuse("UNKNOWN_AUTHORIZATION",
                           "only an authorization_id returned by a successful propose_payment in "
                           "this run can be confirmed",
                           known=[pid for pid in self._pending])
        result = self.client.consume(pending.authorization_id)
        if not isinstance(result, dict):
            raise BrokerError("consume returned a non-object body")
        self._consumes += 1
        return {"ok": True, "state": result.get("state"),
                "provider_order_id": result.get("razorpay_order_id")
                or result.get("razorpay_payment_id"),
                "remaining_uses": result.get("remaining_uses"),
                "authorization_id": pending.authorization_id,
                "transaction_id": pending.transaction_id,
                "merchant": pending.merchant,
                "amount_minor_units": pending.amount_minor_units}

    def _tool_read_proof(self, transaction_id: str) -> dict[str, Any]:
        if transaction_id not in self._known_transactions:
            return _refuse("UNKNOWN_TRANSACTION",
                           "you may only read proof for a transaction this run proposed")
        bundle = self.client.proof_bundle(transaction_id)
        if not isinstance(bundle, dict):
            raise BrokerError("proof_bundle returned a non-object body")
        artifacts = bundle.get("artifacts") or {}
        audit = artifacts.get("audit_record") or {}
        execution = artifacts.get("payment_execution") or {}
        result = artifacts.get("payment_result") or {}
        return {"ok": True, "transaction_id": transaction_id,
                "chain_verified": bool(audit.get("chain_verified")),
                "audit_event_count": len(audit.get("events") or []),
                "stage_count": len(artifacts), "stages": sorted(artifacts),
                "state": execution.get("state"),
                "final_state": result.get("final_state"),
                "terminal": bool(result.get("terminal")),
                "webhook_verified": bool(result.get("webhook_verified")),
                "provider_order_id": result.get("provider_order_id"),
                # Settlement provenance belongs in the model's own view, not just
                # in the artifact. A model told `final_state: PAID` with no
                # qualifier will write "the payment completed" to the user; told
                # the source as well, it can say whether the provider settled it
                # or a local simulator did. Same reasoning that put the column on
                # the row in the first place.
                "settlement_source": result.get("settlement_source"),
                "provider_environment": result.get("provider_environment")}
