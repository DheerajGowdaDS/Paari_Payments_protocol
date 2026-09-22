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

_PROVIDER_STATUS_TO_STATE = {"captured": "PAID", "failed": "FAILED", "authorized": "PAYMENT_PENDING"}


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

    status = str(payment.get("status", "")).lower()
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
        _audit(db, txn, "reconciled", {"from_state": old, "to_state": target, "payment_id": payment.get("id"),
                                        "amount_minor_units": auth.amount_minor_units, "currency": auth.currency})
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
