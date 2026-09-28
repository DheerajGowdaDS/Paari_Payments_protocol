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
This module also owns the two database-safety rules, because both `app` and
the test harness must agree on them and the harness used to be the only place
that knew about either:

1. `resolve_database_url()` is the single definition of where the URL comes
   from. `PAARI_DATABASE_URL` overrides `DATABASE_URL`, which lets a developer
   or a test harness point at a throwaway database without rewriting the
   deployment's `DATABASE_URL`. Before this, `tests/conftest.py` read
   `DATABASE_URL` directly and then issued `DROP SCHEMA public CASCADE` against
   whatever it pointed at - so running `pytest` with a sourced production shell
   environment destroyed a live database from a command that reads as read-only.
2. `assert_disposable_database_url()` gates every schema-destroying operation.
   A URL only qualifies as disposable if it is a SQLite file that is obviously
   a scratch database, or a Postgres database whose name ends in `_test`.
   Anything else raises; the caller refuses to run rather than guessing.

SQLite foreign keys are also turned on per connection here (see
`_enable_sqlite_foreign_keys`). `PRAGMA foreign_keys` defaults to OFF, so
without it every `ForeignKey(...)` the models declare - including
`payment_intents.agent_id` - is documentation on SQLite and only reality on
Postgres, which means the dev database silently accepts rows the production
database will reject.
"""
import os
import tempfile
from datetime import datetime, timezone

from sqlalchemy import create_engine, event, DateTime
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from sqlalchemy.types import TypeDecorator

_SQLITE_PREFIX = "sqlite"

# Suffixes that mark a Postgres database as an explicitly disposable target.
_TEST_DB_SUFFIXES = ("_test", "_testing", "_pytest")


def resolve_database_url() -> str:
    """Where the database URL comes from - defined once.

    `PAARI_DATABASE_URL` wins over `DATABASE_URL` so a harness can retarget
    without clobbering the operator's deployment variable.
    """
    return os.environ.get("PAARI_DATABASE_URL") or os.environ.get(
        "DATABASE_URL", "sqlite:///./paari.db"
    )


def _sqlite_file_path(url: str) -> str:
    """The filesystem path of a sqlite URL, or '' for an in-memory database."""
    return url.split(":///", 1)[1] if ":///" in url else ""


def is_disposable_database_url(url: str) -> bool:
    """True only for a target that is unambiguously a scratch database.

    Deliberately conservative: anything that is not clearly disposable is not
    disposable, because the operation being gated deletes schemas.
    """
    if url.startswith(_SQLITE_PREFIX):
        path = _sqlite_file_path(url).replace("\\", "/")
        if not path or path == ":memory:":
            return True
        name = path.rsplit("/", 1)[-1]
        stem = name[: name.rfind(".")] if "." in name else name
        stem = stem.lower()
        temp_root = tempfile.gettempdir().replace("\\", "/").lower().rstrip("/")
        return bool(
            stem.startswith(("test", ".phase", "paari_test", "probe"))
            or stem.endswith(_TEST_DB_SUFFIXES)
            or (temp_root and path.lower().startswith(temp_root + "/"))
        )
    # Server-side backends: judge by database name only, never by host.
    dbname = url.rstrip("/").rsplit("/", 1)[-1].split("?")[0]
    return dbname.lower().endswith(_TEST_DB_SUFFIXES)


def assert_disposable_database_url(url: str, purpose: str) -> None:
    """Refuse to run a schema-destroying operation against a real database."""
    if is_disposable_database_url(url):
        return
    raise RuntimeError(
        f"Refusing to {purpose}: {url!r} is not a recognised disposable test "
        "database. A destructive reset requires a SQLite scratch file or a "
        "Postgres database whose name ends in "
        f"{_TEST_DB_SUFFIXES}. Set PAARI_DATABASE_URL to such a target."
    )


def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record):
    """`PRAGMA foreign_keys` is per-connection and OFF by default on SQLite."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def get_engine(url: str | None = None):
    """Build an engine for any URL (tests/Postgres/transients) without touching the global one."""
    resolved = url or DATABASE_URL
    connect_args = {"check_same_thread": False} if resolved.startswith(_SQLITE_PREFIX) else {}
    new_engine = create_engine(resolved, connect_args=connect_args)
    if resolved.startswith(_SQLITE_PREFIX):
        event.listen(new_engine, "connect", _enable_sqlite_foreign_keys)
    return new_engine


DATABASE_URL = resolve_database_url()

_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith(_SQLITE_PREFIX) else {}

engine = create_engine(DATABASE_URL, connect_args=_connect_args)
if DATABASE_URL.startswith(_SQLITE_PREFIX):
    event.listen(engine, "connect", _enable_sqlite_foreign_keys)
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
