"""Task 0: Alembic baseline must round-trip on SQLite before anything else lands."""
import pathlib

import sqlalchemy as sa

PAARI_FIXED = pathlib.Path(__file__).resolve().parents[1]


def _cfg_for(db_path: pathlib.Path):
    from alembic.config import Config

    cfg = Config(str(PAARI_FIXED / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    return cfg


def test_baseline_migration_roundtrip(tmp_path):
    from alembic import command

    db = tmp_path / "mig_test.db"
    cfg = _cfg_for(db)
    command.upgrade(cfg, "head")
    eng = sa.create_engine(f"sqlite:///{db}")
    with eng.begin() as c:
        c.execute(
            sa.text(
                "INSERT INTO parent_authorities (parent_id, name, parent_type, contact, public_key_pem, status, created_at, trust_tier, org_id)"
                " VALUES ('p1','n','developer','c','k','active','2026-09-17 00:00:00+00:00','self_asserted','default')"
            )
        )
    command.downgrade(cfg, "-1")
    command.upgrade(cfg, "head")
    assert db.exists()
