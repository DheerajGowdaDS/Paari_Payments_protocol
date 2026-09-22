# AGENTS.md — Paari

Paari is a trust/governance layer between AI agents and payment infrastructure (FastAPI + SQLAlchemy + Pydantic + PyJWT, Ed25519 crypto). Python 3.11.

## Commands

- Install (dev): `pip install -r requirements-dev.txt` — adds `pytest`, `pytest-asyncio`, `respx`.
- Install (postgres): `pip install -r requirements-postgres.txt` — adds `psycopg[binary]`.
- Run server: `uvicorn app.main:app --reload`
- Migrate: `alembic upgrade head` — **tables are never created at import**; the app will 503/404 without a migrated DB. Migrations live in `alembic/versions/` and read `ALEMBIC_URL` (app runtime reads `DATABASE_URL` instead — set both to the same value; `alembic.ini` holds only a placeholder URL).
- Tests: `pytest -q` (88 passing, 1 skipped — the skipped one is the Postgres migration test, which runs in CI with a live service). CI runs `python -m compileall -q app sdk scripts` then `pytest -q`.
- Single test: `pytest tests/test_foo.py -q`
- There is **no** linter/formatter/typecheck config — CI only compiles and runs pytest. Don't assume `ruff`/`mypy`/`black` exist.

## Architecture

- `app/main.py` — FastAPI app; mounts legacy routers (`/agents`, `/auth`, `/payments`, `/parents`) and the versioned `app/routers/v1.py`.
- `app/routers/v1.py` — stable `/v1` protocol surface (register, challenge/verify, payment intent, consume, MFA, webhook, reconcile, audit, rotate, revoke, orgs). **New external integrations use `/v1`**, not the legacy unversioned routes.
- `app/protocol/` — envelope signing/verification, discovery, messages.
- `app/providers/` — `PaymentProvider` abstraction; `Razorpay` is the only implementation.
- `app/transitions.py` — single source of truth for `ProviderTransaction.state` transitions; illegal jumps raise `IllegalTransitionError`.
- `app/database.py` — `UTCDateTime` type decorator guarantees tz-aware UTC timestamps on **both** SQLite and Postgres (SQLite silently drops tzinfo otherwise).
- `sdk/paari_agent/` — reference external-agent SDK. It imports **no** server modules; the agent owns its private key.
- `tests/conftest.py` — shared fixtures. `paari_client` builds an isolated SQLite DB via Alembic, overrides `get_db`, and pre-registers an authenticated agent.

## Environment

Required for payment execution: `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, `RAZORPAY_WEBHOOK_SECRET`, `PAARI_ADMIN_API_KEY`, `PAARI_SIGNING_KEY_PATH`, `DATABASE_URL`.

- `PAARI_LIVE=1` enforces Postgres `DATABASE_URL` + all of the above at boot; without it the server refuses to start.
- `PAARI_ADMIN_API_KEY` unset → server generates an ephemeral key and prints it (dev only).
- Default dev storage is SQLite (`sqlite:///./paari.db`).
- `paari_signing_key.pem` is an **unencrypted Ed25519 private key** — it is gitignored (`*.pem`, `*.key`, `*.db`, `.env`). Never commit it; every token issued under a committed key stays forgeable forever.

## Conventions & gotchas

- Session token: prefer `Authorization: Bearer <session>`. Legacy JSON `session_token` field still accepted. **Never put session tokens in URLs.**
- Protected v1 payment requests require `X-Paari-Proof`, a sender-constrained JWT bound to the session token hash, HTTP method, exact path, issue time, and a one-time JTI (replay is burned in the DB).
- Agent-requested capabilities/limits/currency are **never** authoritative — only the parent-signed delegation values apply.
- Authorization usage is reserved atomically (conditional DB update), not check-then-set. Provider submission uses `authorization_id` as the idempotency key.
- Settlement only happens from a signature-verified webhook or reconciliation — never from client claims. Unknown provider outcomes become `PROVIDER_UNKNOWN` and require reconciliation.
- Multi-tenancy: `org_id` on tenant-scoped rows; non-default orgs use their own provider credentials and **never** fall back to another org's.
- Key rotation leaves a `key_sunset_at` grace window during which the old key is still accepted for session binding.

## Docs

- Protocol surface & objects: `docs/PROTOCOL.md`, `schemas/`
- Conformance contract (required interoperability tests): `docs/CONFORMANCE.md`
- Security model & threat table: `docs/SECURITY.md`
- Phase notes: `docs/PHASE6_HARDENING.md`, `docs/PHASE7_8.md`