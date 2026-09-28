"""Append-only hash-chained audit log. Writers only add rows and flush;
the surrounding request transaction owns the commit, so a rolled-back
request can never leave a gapless-looking chain with a hole in it."""
import hashlib

from sqlalchemy.orm import Session

from app import crypto_utils, models
from app.serialization import acquire_chain_lock

GENESIS_HASH = "GENESIS"

HASH_VERSION_1 = 1
HASH_VERSION_2 = 2


def _hash_event_v1(prev_hash: str, detail: dict) -> str:
    return hashlib.sha256(
        (prev_hash + crypto_utils.canonical_json(detail)).encode("utf-8")
    ).hexdigest()


def _hash_event_v2(prev_hash: str, *, kind: str, agent_id: str, parent_id: str | None,
                   org_id: str, transaction_id: str, created_at: str, detail: dict) -> str:
    payload = {
        "prev_hash": prev_hash,
        "kind": kind,
        "agent_id": agent_id,
        "parent_id": parent_id,
        "org_id": org_id,
        "transaction_id": transaction_id,
        "created_at": created_at,
        "detail": detail,
    }
    return hashlib.sha256(
        crypto_utils.canonical_json(payload).encode("utf-8")
    ).hexdigest()


def _hash_event(prev_hash: str, detail: dict, *, kind: str = "", agent_id: str = "",
                parent_id: str | None = None, org_id: str = "", transaction_id: str = "",
                created_at: str = "", hash_version: int = HASH_VERSION_2) -> str:
    if hash_version == HASH_VERSION_1:
        return _hash_event_v1(prev_hash, detail)
    return _hash_event_v2(prev_hash, kind=kind, agent_id=agent_id, parent_id=parent_id,
                          org_id=org_id, transaction_id=transaction_id, created_at=created_at,
                          detail=detail)


def causal_labels(db: Session, intent_id: str | None) -> dict:
    """The LLM trace labels Paari must carry forward into settlement events.

    Read from the stored intent, never from a request body: by the time a webhook
    or a reconciliation lands, the only trustworthy copy of "which model run
    caused this" is the one the authorization path already persisted and
    validated.

    Gated on `llm_attributed`. These fields are client-asserted trace labels, and
    the project's rule is that a causal marker is never emitted for a request that
    claimed none - so an unattributed payment stays unattributed all the way to
    settlement, rather than gaining an `llm_*` key because some later reader had
    one available. Returns {} in that case, and callers splat it into the detail.
    """
    if not intent_id:
        return {}
    intent = db.query(models.PaymentIntent).filter_by(intent_id=intent_id).first()
    if intent is None or not getattr(intent, "llm_attributed", False):
        return {}
    return {
        "llm_run_id": intent.llm_run_id,
        "llm_model": intent.llm_model,
        "llm_tool_call_id": intent.llm_tool_call_id,
        "llm_tool_name": getattr(intent, "llm_tool_name", None),
    }


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
    # Serialize appends for this transaction. Without it, two concurrent
    # requests sharing a client-supplied transaction_id both read the same
    # tail and fork the chain, after which verify_chain returns False forever
    # on a legitimate bundle. This lock never commits/rolls back - record_audit
    # stays flush-only, the caller still owns the transaction.
    acquire_chain_lock(db, f"paari:audit:{transaction_id}")
    prev = (
        db.query(models.AuditEvent)
        .filter_by(transaction_id=transaction_id)
        .order_by(models.AuditEvent.id.desc())
        .first()
    )
    prev_hash = prev.event_hash if prev is not None else GENESIS_HASH
    hash_version = HASH_VERSION_2
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    created_at_str = now.isoformat()
    event = models.AuditEvent(
        transaction_id=transaction_id,
        agent_id=agent_id,
        parent_id=parent_id,
        kind=kind,
        detail=detail,
        prev_hash=prev_hash,
        event_hash=_hash_event(prev_hash, detail, kind=kind, agent_id=agent_id,
                                parent_id=parent_id, org_id=org_id,
                                transaction_id=transaction_id,
                                created_at=created_at_str,
                                hash_version=hash_version),
        org_id=org_id,
        hash_version=hash_version,
        created_at=now,
    )
    db.add(event)
    db.flush()
    return event


def verify_chain(db: Session, transaction_id: str) -> bool:
    """Recompute every link. False means a row was tampered with (or the
    chain was written by something that didn't follow the hash rule).
    Supports both hash versions: v1 (detail-only) and v2 (full metadata)."""
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
        hv = getattr(event, "hash_version", 1) or 1
        if hv == HASH_VERSION_1:
            expected = _hash_event_v1(event.prev_hash, event.detail)
        else:
            expected = _hash_event_v2(
                event.prev_hash,
                kind=event.kind,
                agent_id=event.agent_id,
                parent_id=event.parent_id,
                org_id=event.org_id,
                transaction_id=event.transaction_id,
                created_at=event.created_at.isoformat() if event.created_at else "",
                detail=event.detail,
            )
        if event.event_hash != expected:
            return False
        prev_hash = event.event_hash
    return True
