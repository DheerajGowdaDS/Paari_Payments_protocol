"""Alembic environment: metadata comes from app.models; URL from ALEMBIC_URL or alembic.ini."""
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool, Enum as SaEnum, String as SaString

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

if os.environ.get("ALEMBIC_URL"):
    config.set_main_option("sqlalchemy.url", os.environ["ALEMBIC_URL"])

from app.database import Base  # noqa: E402
import app.models  # noqa: E402,F401  (register every mapped table)

target_metadata = Base.metadata


def compare_type(context_, inspected_column, metadata_column, inspected_type, metadata_type):
    """Teach `alembic check` about the one thing SQLite cannot express.

    SQLite has no native ENUM. SQLAlchemy stores an `Enum` column as VARCHAR and
    reflects it back as VARCHAR, so every native-enum migration makes
    `alembic check` report a permanent, unfixable `modify_type` diff on SQLite -
    which is exactly the noise that let real drift hide. Revision d3e4f5a6b7c8
    converts `user_payment_mandates.status` to a native enum on Postgres and,
    correctly, does nothing on SQLite; the remaining question is only whether the
    SQLite VARCHAR is wide enough to hold every declared value.

    So: on SQLite, an Enum over a VARCHAR is NOT drift if the longest value fits.
    If it does not fit, that IS drift and gets reported. Nothing is whitelisted
    blindly, and Postgres comparisons keep their default behaviour.
    """
    if isinstance(metadata_type, SaEnum) and isinstance(inspected_type, SaString):
        bind = getattr(context_, "bind", None)
        if bind is not None and bind.dialect.name == "sqlite":
            widest = max((len(str(v)) for v in metadata_type.enums), default=0)
            if inspected_type.length is None or widest <= inspected_type.length:
                return False
    return None


def _common_kwargs() -> dict:
    return {
        "target_metadata": target_metadata,
        "compare_type": compare_type,
        # SQLite cannot ALTER TABLE; batch mode rebuilds instead. Without this,
        # any future constraint migration would generate SQL SQLite rejects.
        "render_as_batch": True,
    }


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, literal_binds=True, **_common_kwargs())
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, **_common_kwargs())
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
