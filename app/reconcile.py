"""Provider reconciliation for missed webhooks and unknown executions."""
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app import models
from app.provider_accounts import get_provider_for_org


def get_provider():
    """Default-org provider seam; non-default organizations use strict routing."""
    from app.providers.razorpay import RazorpayAdapter
    return RazorpayAdapter()
from app.transitions import TERMINAL_STATES, IllegalTransitionError, transition_txn

# Reconciliation is the corroborating read, so a provider status of `captured`
# observed HERE is what promotes CAPTURED -> PAID. Via a webhook it only reaches
# CAPTURED; see app/transitions.py for why the two paths differ.
_PROVIDER_STATUS_TO_STATE = {
    "captured": "PAID",
    "failed": "FAILED",
    "authorized": "PROVIDER_AUTHORIZED",
}

_ORDER_STATUS_TO_STATE = {"cancelled": "CANCELLED", "expired": "EXPIRED"}


def _trace_key(db, txn) -> str:
    auth = db.query(models.BoundedAuthorization).filter_by(authorization_id=txn.authorization_id).first()
    return auth.transaction_id if auth else txn.authorization_id


def _audit(db, txn, kind: str, detail: dict):
    from app.audit import record_audit
    agent = db.query(models.Agent).filter_by(agent_id=txn.agent_id).first()
    parent_id = None
    if agent:
        parent = db.query(models.ParentAuthority).filter_by(id=agent.parent_pk).first()
        parent_id = parent.parent_id if parent else None
    record_audit(db, transaction_id=_trace_key(db, txn), agent_id=txn.agent_id, parent_id=parent_id,
                 kind=kind, detail=detail, org_id=txn.org_id)


def reconcile_one(db: Session, authorization_id: str) -> dict:
    txn = db.query(models.ProviderTransaction).filter_by(authorization_id=authorization_id).first()
    if not txn:
        return {"status": "not_found", "state": None}
    if txn.state in TERMINAL_STATES:
        return {"status": "terminal", "state": txn.state}
    auth = db.query(models.BoundedAuthorization).filter_by(authorization_id=authorization_id, org_id=txn.org_id).first()
    if not auth:
        return {"status": "unreconciled", "state": txn.state}
    try:
        provider = get_provider() if txn.org_id == "default" else get_provider_for_org(db, txn.org_id)
    except Exception as exc:
        txn.last_error = str(exc)[:2000]; db.commit()
        return {"status": "unreconciled", "state": txn.state}

    if txn.state == "PROVIDER_UNKNOWN" and not txn.razorpay_order_id:
        found = provider.fetch_order_by_receipt(authorization_id)
        if found and found.get("id"):
            txn.razorpay_order_id = found["id"]

    payment = None
    try:
        if txn.razorpay_payment_id:
            payment = provider.get_payment(txn.razorpay_payment_id)
        elif txn.razorpay_order_id:
            attempts = provider.fetch_payments(txn.razorpay_order_id)
            payment = attempts[-1] if attempts else None
    except Exception as exc:
        txn.last_error = str(exc)[:2000]; db.commit()
        return {"status": "unreconciled", "state": txn.state}
    if not payment:
        db.commit(); return {"status": "unreconciled", "state": txn.state}

    if txn.razorpay_order_id:
        try:
            order = provider.fetch_order_by_receipt(authorization_id)
        except Exception:
            order = None
        if order:
            order_status = str(order.get("status", "")).lower()
            if order_status == "cancelled":
                try:
                    old = txn.state; transition_txn(txn, "CANCELLED")
                except IllegalTransitionError:
                    return {"status": "unreconciled", "state": txn.state}
                txn.reconciled_at = datetime.now(timezone.utc); txn.updated_at = datetime.now(timezone.utc)
                _audit(db, txn, "reconciled", {"from_state": old, "to_state": "CANCELLED",
                                                "order_id": order.get("id"), "provider_environment": txn.provider_environment})
                db.commit()
                return {"status": "reconciled", "state": txn.state}
            if order_status == "expired":
                try:
                    old = txn.state; transition_txn(txn, "EXPIRED")
                except IllegalTransitionError:
                    return {"status": "unreconciled", "state": txn.state}
                txn.reconciled_at = datetime.now(timezone.utc); txn.updated_at = datetime.now(timezone.utc)
                _audit(db, txn, "reconciled", {"from_state": old, "to_state": "EXPIRED",
                                                "order_id": order.get("id"), "provider_environment": txn.provider_environment})
                db.commit()
                return {"status": "reconciled", "state": txn.state}

    status = str(payment.get("status", "")).lower()
    if status == "failed":
        error_code = str(payment.get("error_code", "")).lower()
        if error_code in ("card_declined", "insufficient_funds", "bank_declined", "declined"):
            try:
                old = txn.state; transition_txn(txn, "DECLINED")
            except IllegalTransitionError:
                return {"status": "unreconciled", "state": txn.state}
            txn.reconciled_at = datetime.now(timezone.utc); txn.updated_at = datetime.now(timezone.utc)
            _audit(db, txn, "reconciled", {"from_state": old, "to_state": "DECLINED",
                                            "payment_id": payment.get("id"), "provider_environment": txn.provider_environment})
            db.commit()
            return {"status": "reconciled", "state": txn.state}
    target = _PROVIDER_STATUS_TO_STATE.get(status)
    if target is None:
        return {"status": "unreconciled", "state": txn.state}
    # Provider truth is only acceptable if it matches the exact authorization.
    if payment.get("amount") is not None and int(payment.get("amount")) != auth.amount_minor_units:
        txn.last_error = "provider payment amount mismatch"; _audit(db, txn, "reconcile_value_mismatch", {
            "provider_amount": payment.get("amount"), "authorized_amount": auth.amount_minor_units,
            "provider_currency": payment.get("currency"), "authorized_currency": auth.currency,
        }); db.commit(); return {"status": "unreconciled", "state": txn.state}
    if payment.get("currency") and str(payment.get("currency")).upper() != auth.currency.upper():
        txn.last_error = "provider payment currency mismatch"; _audit(db, txn, "reconcile_value_mismatch", {
            "provider_amount": payment.get("amount"), "authorized_amount": auth.amount_minor_units,
            "provider_currency": payment.get("currency"), "authorized_currency": auth.currency,
        }); db.commit(); return {"status": "unreconciled", "state": txn.state}

    if target != txn.state:
        try:
            old = txn.state; transition_txn(txn, target)
        except IllegalTransitionError:
            return {"status": "unreconciled", "state": txn.state}
        from app.audit import causal_labels
        _audit(db, txn, "reconciled", {"from_state": old, "to_state": target, "payment_id": payment.get("id"),
                                        "amount_minor_units": auth.amount_minor_units, "currency": auth.currency,
                                        "provider_environment": txn.provider_environment,
                                        **causal_labels(db, txn.intent_id)})
    if target == "PAID" and payment.get("id"):
        txn.razorpay_payment_id = payment["id"]
    txn.reconciled_at = datetime.now(timezone.utc); txn.updated_at = datetime.now(timezone.utc)
    db.commit()
    return {"status": "reconciled", "state": txn.state}


def reconcile_pending(db: Session, limit: int = 100) -> dict:
    txns = db.query(models.ProviderTransaction).filter(models.ProviderTransaction.state.notin_(TERMINAL_STATES)).limit(limit).all()
    count = 0
    for txn in txns:
        if reconcile_one(db, txn.authorization_id).get("status") == "reconciled": count += 1
    return {"checked": len(txns), "reconciled": count}


def confirm_capture(db: Session, provider, txn, authorization_id: str) -> str:
    """Independently corroborate a provider capture. Returns the new state.

    Called from the webhook path after `payment.captured` has moved the row to
    CAPTURED. The webhook proves the provider *announced* a capture; this proves
    the provider still *says so* when asked directly. PAID is reserved for the
    case where both agree, which is the only formulation of "settled" that does
    not rest on a single unverified inbound message - signed or not.

    Deliberately conservative in three ways:

    * Any transport/parse failure returns the state unchanged. Staying in
      CAPTURED costs a reconciliation cycle; guessing wrong costs a false
      settlement record on an evidence product.
    * A provider status that is neither captured nor failed is not evidence of
      anything, so it is also left alone.
    * Amount and currency must equal the bounded authorization exactly. A
      correctly-signed event for the wrong value is still the wrong value.
    """
    from app.transitions import transition_txn, IllegalTransitionError

    auth = db.query(models.BoundedAuthorization).filter_by(
        authorization_id=authorization_id).first()
    if auth is None:
        return txn.state
    payment = None
    try:
        if txn.razorpay_payment_id:
            payment = provider.get_payment(txn.razorpay_payment_id)
        elif txn.razorpay_order_id:
            attempts = provider.fetch_payments(txn.razorpay_order_id)
            payment = attempts[-1] if attempts else None
    except Exception as exc:
        txn.last_error = f"capture confirmation unavailable: {str(exc)[:500]}"
        db.commit()
        return txn.state
    if not payment:
        return txn.state

    status = str(payment.get("status", "")).lower()
    if status == "captured":
        if (payment.get("amount") is not None
                and int(payment.get("amount")) != auth.amount_minor_units):
            txn.last_error = "confirmation amount mismatch"
            _audit(db, txn, "reconcile_value_mismatch", {
                "provider_amount": payment.get("amount"),
                "authorized_amount": auth.amount_minor_units,
                "stage": "capture_confirmation"})
            db.commit()
            return txn.state
        if (payment.get("currency")
                and str(payment.get("currency")).upper() != auth.currency.upper()):
            txn.last_error = "confirmation currency mismatch"
            _audit(db, txn, "reconcile_value_mismatch", {
                "provider_currency": payment.get("currency"),
                "authorized_currency": auth.currency,
                "stage": "capture_confirmation"})
            db.commit()
            return txn.state
        try:
            old = txn.state
            transition_txn(txn, "PAID")
        except IllegalTransitionError:
            return txn.state
        txn.razorpay_payment_id = payment.get("id") or txn.razorpay_payment_id
        txn.updated_at = datetime.now(timezone.utc)
        _audit(db, txn, "settlement_confirmed", {
            "from_state": old, "to_state": "PAID", "payment_id": payment.get("id"),
            "amount_minor_units": auth.amount_minor_units, "currency": auth.currency,
            "provider_environment": txn.provider_environment})
        db.commit()
        return txn.state

    if status == "failed":
        # The provider now says the capture it announced did not land. Record
        # that rather than leaving a CAPTURED row implying money moved.
        try:
            old = txn.state
            transition_txn(txn, "PROVIDER_UNKNOWN")
        except IllegalTransitionError:
            return txn.state
        txn.last_error = f"provider reports failed after capture event: {payment.get('error_code')}"
        txn.updated_at = datetime.now(timezone.utc)
        _audit(db, txn, "settlement_not_confirmed", {
            "from_state": old, "to_state": "PROVIDER_UNKNOWN",
            "payment_id": payment.get("id"), "provider_status": status,
            "provider_environment": txn.provider_environment})
        db.commit()
        return txn.state

    return txn.state
