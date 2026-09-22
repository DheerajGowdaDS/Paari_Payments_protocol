"""Append-only hash-chained audit log. Writers only add rows and flush;
the surrounding request transaction owns the commit, so a rolled-back
request can never leave a gapless-looking chain with a hole in it."""
import hashlib

from sqlalchemy.orm import Session

from app import crypto_utils, models

GENESIS_HASH = "GENESIS"


def _hash_event(prev_hash: str, detail: dict) -> str:
    return hashlib.sha256(
        (prev_hash + crypto_utils.canonical_json(detail)).encode("utf-8")
    ).hexdigest()


def record_audit(
    db: Session,
    *,
    transaction_id: str,
    agent_id: str,
    parent_id: str | None,
    kind: str,
    detail: dict,
    org_id: str | None = None,
) -> models.AuditEvent:
    """Append one event to the chain for transaction_id. Flushes only -
    the caller commits (or rolls back) the surrounding transaction.
    The event's org is explicit org_id when given, else the owning agent's
    org, else 'default' (platform-scope rows like org creation)."""
    if org_id is None:
        agent = db.query(models.Agent).filter_by(agent_id=agent_id).first()
        org_id = agent.org_id if agent is not None else "default"
    prev = (
        db.query(models.AuditEvent)
        .filter_by(transaction_id=transaction_id)
        .order_by(models.AuditEvent.id.desc())
        .first()
    )
    prev_hash = prev.event_hash if prev is not None else GENESIS_HASH
    event = models.AuditEvent(
        transaction_id=transaction_id,
        agent_id=agent_id,
        parent_id=parent_id,
        kind=kind,
        detail=detail,
        prev_hash=prev_hash,
        event_hash=_hash_event(prev_hash, detail),
        org_id=org_id,
    )
    db.add(event)
    db.flush()
    return event


def verify_chain(db: Session, transaction_id: str) -> bool:
    """Recompute every link. False means a row was tampered with (or the
    chain was written by something that didn't follow the hash rule)."""
    events = (
        db.query(models.AuditEvent)
        .filter_by(transaction_id=transaction_id)
        .order_by(models.AuditEvent.id.asc())
        .all()
    )
    prev_hash = GENESIS_HASH
    for event in events:
        if event.prev_hash != prev_hash:
            return False
        if event.event_hash != _hash_event(event.prev_hash, event.detail):
            return False
        prev_hash = event.event_hash
    return True
