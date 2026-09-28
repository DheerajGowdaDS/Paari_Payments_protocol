"""Shared rate limits. Table-backed counters so every uvicorn worker sees
the same number; SQLite-compatible SQL only (no FOR UPDATE - the unique
(scope, window_start) constraint plus a savepoint-guarded insert makes the
increment safe under races: losers fall back to UPDATE)."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import models

PRUNE_AFTER = timedelta(hours=1)


class RateLimitedError(Exception):
    def __init__(self, scope: str, limit: int, retry_after_seconds: int):
        super().__init__(f"rate limit exceeded for {scope}: {limit} per window")
        self.scope = scope
        self.limit = limit
        self.retry_after_seconds = retry_after_seconds


def check_rate(db: Session, scope: str, limit: int, window_seconds: int,
               org_id: str = "default") -> None:
    """Increment the counter for scope in the current window. Raises
    RateLimitedError when the scope already used its budget. Must be called
    before the endpoint does any domain writes (the race fallback rolls back
    to a savepoint, which only discards this function's own work)."""
    now = datetime.now(timezone.utc)
    epoch = int(now.timestamp())
    window_start = datetime.fromtimestamp(epoch - (epoch % window_seconds), tz=timezone.utc)

    db.query(models.RateBucket).filter(
        models.RateBucket.window_start < now - PRUNE_AFTER).delete()

    where = (
        (models.RateBucket.scope == scope)
        & (models.RateBucket.window_start == window_start)
    )
    if db.execute(
        update(models.RateBucket).where(where)
        .values(count=models.RateBucket.count + 1)
    ).rowcount:
        count = db.scalar(select(models.RateBucket.count).where(where))
    else:
        try:
            with db.begin_nested():
                db.add(models.RateBucket(scope=scope, window_start=window_start,
                                         count=1, org_id=org_id))
                db.flush()
            count = 1
        except IntegrityError:
            # Lost the insert race: someone else created the row.
            db.execute(
                update(models.RateBucket).where(where)
                .values(count=models.RateBucket.count + 1))
            count = db.scalar(select(models.RateBucket.count).where(where))

    if count > limit:
        # The rejected attempt still consumed budget - persist before raising.
        db.commit()
        raise RateLimitedError(scope, limit, window_seconds - (epoch % window_seconds))
    # Commit independently of the caller's transaction: endpoints that answer
    # without writing (idempotent replays, parked REVIEWs) roll back, and the
    # budget must survive that rollback or limits silently never trigger.
    db.commit()
