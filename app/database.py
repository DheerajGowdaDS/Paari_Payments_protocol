"""
Database wiring for Paari.

DATABASE_URL is read from the environment so a production deployment can
point this at Postgres (`postgresql+psycopg://...`) without touching any
other code - everything else goes through SQLAlchemy. Defaults to a local
SQLite file for development only.

P0 FIX (datetime handling): plain `DateTime(timezone=True)` columns are
useless on SQLite - it silently stores timezone-aware datetimes as naive
ones, which is exactly what caused

    TypeError: can't compare offset-naive and offset-aware datetimes

in app/routers/auth.py at runtime. `models.py` now uses the `UTCDateTime`
type decorator defined here for every timestamp column: it normalizes
whatever comes in to aware UTC before binding, and always returns aware
UTC on the way out - regardless of backend. Postgres already round-trips
tz-aware values correctly, but routing every timestamp through the same
type decorator means the app behaves identically on both engines instead
of "works on Postgres, breaks on SQLite."
"""
import os
from datetime import datetime, timezone

from sqlalchemy import create_engine, DateTime
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from sqlalchemy.types import TypeDecorator

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./paari.db")


def get_engine(url: str | None = None):
    """Build an engine for any URL (tests/Postgres/transients) without touching the global one."""
    resolved = url or DATABASE_URL
    connect_args = {"check_same_thread": False} if resolved.startswith("sqlite") else {}
    return create_engine(resolved, connect_args=connect_args)


_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=_connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class UTCDateTime(TypeDecorator):
    """
    A DateTime column that is always aware and always UTC, on every backend.

    - process_bind_param: naive datetimes are assumed to already be UTC and
      are tagged as such; aware datetimes are converted to UTC. Either way,
      what actually reaches the driver is aware UTC.
    - process_result_value: SQLite hands back a naive datetime (it doesn't
      persist tzinfo) - we re-attach UTC. Postgres hands back aware UTC
      already, which passes through unchanged.

    This guarantees every datetime the rest of the app sees from the ORM is
    tz-aware, so comparisons against `datetime.now(timezone.utc)` never
    raise.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def process_result_value(self, value: datetime | None, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
