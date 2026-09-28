"""Cross-dialect serialization gates.

Two distinct locking needs, deliberately separated because they have very
different transaction contracts:

- `acquire_gate` - the MANDATE BUDGET gate. It must begin a write transaction
  *before* the aggregation reads and hold it until the spend record commits,
  so it commits any pending session work first (that is the documented
  contract in app.mandates.evaluate_mandate).

- `acquire_chain_lock` - the AUDIT CHAIN lock. record_audit is documented as
  flush-only (the caller owns the commit), so this lock must NEVER commit or
  roll back. It only takes a blocking transaction-scoped advisory lock on
  Postgres; SQLite already serializes writers, so it is a no-op there.

Both fail closed: a gate that cannot be acquired must block the operation.
"""
from __future__ import annotations

import hashlib
import time

from sqlalchemy import text
from sqlalchemy.orm import Session


def _signed_lock_key(name: str) -> int:
    """Stable 64-bit key from an arbitrary string, in Postgres' signed bigint
    range (pg_try_advisory_xact_lock rejects values >= 2**63)."""
    digest = hashlib.sha256(name.encode("utf-8")).digest()
    key = int.from_bytes(digest[:8], "big")
    if key >= 0x8000000000000000:
        key -= 0x10000000000000000
    return key


def _is_postgres(db: Session) -> bool:
    return db.get_bind().dialect.name == "postgresql"


def acquire_gate(db: Session, name: str, timeout_seconds: int = 5) -> bool:
    """Acquire the write gate for `name`, or return False (caller fails closed).

    Any pending work on the session is committed first so the gate wraps a
    transaction that begins BEFORE the protected reads.
    """
    db.commit()  # end any open read transaction so the gate starts here
    if _is_postgres(db):
        lock_key = _signed_lock_key(name)
        deadline = time.monotonic() + timeout_seconds
        while True:
            got = db.execute(
                text("SELECT pg_try_advisory_xact_lock(:key)").bindparams(key=lock_key)
            ).scalar()
            if got:
                return True
            if time.monotonic() >= deadline:
                db.rollback()
                return False
            time.sleep(0.05)
    try:
        # SQLite: a single writer exists anyway; BEGIN IMMEDIATE acquires the
        # write lock early so the protected reads see a stable snapshot.
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")
        return True
    except Exception:
        db.rollback()
        return False


def acquire_chain_lock(db: Session, name: str) -> None:
    """Serialize hash-chain appends for `name` WITHOUT touching the
    transaction. Safe to call from flush-only code paths."""
    if not _is_postgres(db):
        return  # SQLite serializes writers at the database level
    db.execute(
        text("SELECT pg_advisory_xact_lock(:key)").bindparams(key=_signed_lock_key(name))
    ).scalar()