import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from sqlalchemy import text

from app.routers import agents, auth, parents, payments, v1
from app.protocol.discovery import document as protocol_discovery
from app.protocol.errors import paari_exception_handler, PaariHTTPException
from app.config import load_config, PaariEnv
from app.database import resolve_database_url

# Phase 6: tables are created by Alembic migrations (`alembic upgrade head`),
# never implicitly at import - importing the app must not touch the database.

logger = logging.getLogger("paari")

# The only Razorpay API base that moves real money.
PRODUCTION_API_BASE = "https://api.razorpay.com/v1"


def startup_guards(config: dict) -> list[str]:
    """Cross-check the deployment's own configuration and return reasons to refuse.

    These exist because the failure mode is silent and one-directional: a
    simulator pointed at a production database produces genuine-looking
    `PAID` evidence, and a development SQLite file pointed at a production
    posture makes an operator believe they are live. Neither announces itself,
    so both are refused at boot rather than discovered during an audit.
    """
    reasons: list[str] = []
    env = config.get("env")
    url = config.get("database_url") or resolve_database_url()
    is_live = config.get("is_live")
    wants_postgres = is_live or env in (PaariEnv.PROD, PaariEnv.PROD_LIVE)

    if wants_postgres and not url.startswith(("postgresql://", "postgresql+psycopg://")):
        scheme = url.split("://", 1)[0] if "://" in url else url
        reasons.append(
            f"PAARI_ENV={env} / PAARI_LIVE=1 requires a PostgreSQL DATABASE_URL, "
            f"got a {scheme!r} target. A SQLite file is a development database and "
            "must not back a live deployment."
        )

    api_base = os.environ.get("RAZORPAY_API_BASE", "")
    if env in (PaariEnv.PROD, PaariEnv.PROD_LIVE):
        if api_base != PRODUCTION_API_BASE:
            reasons.append(
                f"PAARI_ENV={env} requires RAZORPAY_API_BASE={PRODUCTION_API_BASE}, "
                f"got {api_base or '(unset)'}. Pointing a production deployment at a "
                "local simulator would let simulated captures mint real, durable "
                "PAID evidence."
            )
        if not config.get("mandate_required"):
            reasons.append(
                f"PAARI_ENV={env} must run with the autonomous posture "
                "(PAARI_MODE=autonomous): a live deployment that treats a user "
                "mandate as optional can authorize payments the user never granted."
            )
    return reasons


@asynccontextmanager
async def lifespan(app: FastAPI):
    config = load_config()
    app.state.paari_config = config
    refusals = startup_guards(config)
    if refusals:
        raise RuntimeError(
            "Paari refuses to start:\n  - " + "\n  - ".join(refusals)
        )
    if os.environ.get("PAARI_LIVE") == "1":
        for name in ("RAZORPAY_KEY_ID", "RAZORPAY_KEY_SECRET", "RAZORPAY_WEBHOOK_SECRET", "PAARI_ADMIN_API_KEY", "PAARI_SIGNING_KEY_PATH"):
            if not os.environ.get(name):
                raise RuntimeError(f"PAARI_LIVE=1 requires {name} to be set")
    if not os.environ.get("PAARI_ADMIN_API_KEY"):
        logger.warning("PAARI_ADMIN_API_KEY unset - running with an ephemeral admin key")
    from app.reconcile_worker import ReconciliationWorker, ReconciliationAlertSink
    worker = ReconciliationWorker(
        interval_seconds=int(os.environ.get("PAARI_RECONCILE_INTERVAL", "60")),
        dead_letter_after=int(os.environ.get("PAARI_RECONCILE_DEAD_LETTER_AFTER", "5")),
        alert_sink=ReconciliationAlertSink(webhook_url=os.environ.get("PAARI_RECONCILE_ALERT_WEBHOOK", "")),
    )
    worker.start()
    logger.info("Reconciliation worker started (interval=%ds, dead_letter_after=%d)",
                worker.interval_seconds, worker.dead_letter_after)
    try:
        yield
    finally:
        worker.stop()
        logger.info("Reconciliation worker stopped")

app = FastAPI(
    title="Paari",
    description=(
        "Agentic Payment Protocol v1.0 + user-payment-authority extension — trust, delegation, authentication, "
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
    from app.providers.agentic import autonomous_settlement_configured, get_agentic_provider
    from app.providers.agentic import AdapterStatus
    _agentic = get_agentic_provider()
    _configured = _agentic.status() == AdapterStatus.CONFIGURED
    agentic_name = _agentic.__class__.__name__
    agentic_provenance = {}
    provenance = getattr(_agentic, "provenance", None)
    if callable(provenance):
        try:
            agentic_provenance = provenance() or {}
        except Exception:
            agentic_provenance = {}
    return {
        "status": "ok" if db_ok else "degraded",
        "service": "paari",
        "env": config.get("env", "unknown"),
        "database": "up" if db_ok else "down",
        # Governance posture is operator-visible, not an environment guess.
        "mandate_mode": config.get("mandate_mode", "unknown"),
        "mandate_required": config.get("mandate_required", False),
        "require_signed_mandate": config.get("require_signed_mandate", False),
        # Honest capability flags: configured means an adapter is bound;
        # autonomous_settlement means it claims to support no-human-checkout.
        # Neither implies a real-money payment has actually settled.
        "agentic_adapter_configured": _configured,
        "agentic_provider": agentic_name,
        "autonomous_settlement": autonomous_settlement_configured(),
        "agentic_provider_environment": agentic_provenance.get("provider_environment", "unknown"),
        "agentic_provider_api_base": agentic_provenance.get("provider_api_base"),
        # Provider identity, reported by the process that actually talks to the
        # provider. Proof harnesses must READ this instead of inferring a mode
        # from their own os.environ.
        **provider_identity(),
    }


def provider_identity() -> dict:
    """Non-secret description of where provider calls would actually go.

    Never raises: /health must stay answerable while a deployment is still
    wiring credentials, and an unreadable provider is exactly the state an
    operator needs to see.
    """
    unknown = {
        "provider": "unknown",
        "provider_environment": "unknown",
        "provider_api_base": None,
        "provider_key_id_prefix": None,
    }
    try:
        from app.providers.razorpay import RazorpayAdapter
        prov = RazorpayAdapter().provenance()
    except Exception:
        return unknown
    environment = prov.get("provider_environment") or "unknown"
    label = {
        "live": "real-razorpay(live)",
        "test": "real-razorpay(test-mode)",
        "simulated": "local-simulator",
    }.get(environment, "unconfigured")
    configured = bool(prov.get("provider_key_id_prefix"))
    return {
        "provider": label if configured else "unconfigured",
        "provider_environment": environment,
        "provider_api_base": prov.get("provider_api_base"),
        "provider_key_id_prefix": prov.get("provider_key_id_prefix"),
    }
