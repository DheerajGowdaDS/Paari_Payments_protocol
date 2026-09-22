"""Task G1: Postgres migration test."""
import os

import pytest


def test_alembic_migrates_postgres_if_url_provided():
    url = os.environ.get("DATABASE_URL", "")
    if not url.startswith("postgresql"):
        pytest.skip("DATABASE_URL not set to postgresql; skipping migration test")
    from alembic import command
    from alembic.config import Config
    import pathlib

    cfg = Config(str(pathlib.Path("alembic.ini")))
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")
    command.check(cfg)
