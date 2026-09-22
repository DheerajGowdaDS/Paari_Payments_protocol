import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from sqlalchemy import text

from app.routers import agents, auth, parents, payments, v1
from app.protocol.discovery import document as protocol_discovery
from app.protocol.errors import paari_exception_handler, PaariHTTPException
from app.config import load_config

# Phase 6: tables are created by Alembic migrations (`alembic upgrade head`),
# never implicitly at import - importing the app must not touch the database.

logger = logging.getLogger("paari")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.paari_config = load_config()
    if os.environ.get("PAARI_LIVE") == "1":
        database_url = os.environ.get("DATABASE_URL", "")
        if not database_url.startswith(("postgresql://", "postgresql+psycopg://")):
            raise RuntimeError("PAARI_LIVE=1 requires a PostgreSQL DATABASE_URL")
        for name in ("RAZORPAY_KEY_ID", "RAZORPAY_KEY_SECRET", "RAZORPAY_WEBHOOK_SECRET", "PAARI_ADMIN_API_KEY", "PAARI_SIGNING_KEY_PATH"):
            if not os.environ.get(name):
                raise RuntimeError(f"PAARI_LIVE=1 requires {name} to be set")
    if not os.environ.get("PAARI_ADMIN_API_KEY"):
        logger.warning("PAARI_ADMIN_API_KEY unset - running with an ephemeral admin key")
    yield

app = FastAPI(
    title="Paari",
    description=(
        "Agentic Payment Protocol v1.0 — trust, delegation, authentication, "
        "payment governance, bounded provider authorization, verified settlement, "
        "reconciliation, audit, and multi-tenancy. Legacy Phase 1-5 routes remain "
        "for compatibility; external agents should use /v1 and /.well-known/paari."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_exception_handler(PaariHTTPException, paari_exception_handler)

app.include_router(parents.router)
app.include_router(agents.router)
app.include_router(auth.router)
app.include_router(payments.router)
app.include_router(v1.router)


@app.get("/.well-known/paari")
def paari_discovery(request: Request):
    return protocol_discovery(str(request.base_url).rstrip("/"))


@app.get("/health")
def health():
    db_ok = False
    try:
        from app.database import engine
        with engine.connect() as c:
            c.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        pass
    config = getattr(app.state, "paari_config", {})
    return {
        "status": "ok" if db_ok else "degraded",
        "service": "paari",
        "env": config.get("env", "unknown"),
        "database": "up" if db_ok else "down",
    }
