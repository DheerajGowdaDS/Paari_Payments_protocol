# AGENTS.md — Paari

Paari is a trust/governance layer between AI agents and payment infrastructure (FastAPI + SQLAlchemy + Pydantic + PyJWT, Ed25519 crypto). Python 3.11.

## Commands

- Install (dev): `pip install -r requirements-dev.txt` — adds `pytest`, `pytest-asyncio`, `respx`.
- Install (postgres): `pip install -r requirements-postgres.txt` — adds `psycopg[binary]`.
- Run server: `uvicorn app.main:app --reload`
- Migrate: `alembic upgrade head` — **tables are never created at import**; the app will 503/404 without a migrated DB. Migrations live in `alembic/versions/` and read `ALEMBIC_URL` (`alembic.ini` holds only a placeholder URL). The app resolves its database via `app.database.resolve_database_url()`: `PAARI_DATABASE_URL` overrides `DATABASE_URL`.
- Schema parity check: `alembic check` must report `No new upgrade operations detected` on **both** SQLite and Postgres. `tests/test_migrations.py` does not assert this; `tests/test_provider_provenance.py` and the Postgres job are the closest automated coverage, so run it by hand after any model change.
- Tests: `pytest -q` (238 passing, 2 skipped — both skips are in `tests/test_postgres_migration.py` and run in CI against a live service). CI runs `python -m compileall -q app sdk scripts` then `pytest -q`, then the Postgres full-suite job, then the proof harnesses. Never run two `pytest` processes in this repo at once: they share `./.phase5_test.db` and the second one fails with a Windows file-lock `PermissionError` that looks like a real regression.
- E2E harnesses: `python scripts/autonomous_payment_e2e.py` (self-hosts the simulator + a temp SQLite DB; no network), `python scripts/llm_agent_e2e.py --with-server --rehearse --require-mandate` (deterministic model — the real-LLM variant needs `BYNARA_*`), and `python scripts/foreign_agent_proof.py` with `PAARI_PAY_TIMEOUT=0` against a running server. `PAARI_PAY_TIMEOUT=0` prints `MILESTONE PARTIAL`, not `GREEN`: a skipped settlement is not a passed settlement.
- Single test: `pytest tests/test_foo.py -q`
- There is **no** linter/formatter/typecheck config — CI only compiles and runs pytest. Don't assume `ruff`/`mypy`/`black` exist.

## Architecture

- `app/main.py` — FastAPI app; mounts legacy routers (`/agents`, `/auth`, `/payments`, `/parents`) and the versioned `app/routers/v1.py`.
- `app/routers/v1.py` — stable `/v1` protocol surface (register, challenge/verify, payment intent, consume, MFA, webhook, reconcile, audit, rotate, revoke, orgs). **New external integrations use `/v1`**, not the legacy unversioned routes.
- `app/protocol/` — envelope signing/verification, discovery, messages.
- `app/providers/` — `PaymentProvider` abstraction; `RazorpayAdapter` is the only implementation that performs real calls. `app/providers/agentic.py` is the `AgenticPaymentProvider` seam for provider-native settlement: it exists, is fully typed, and **refuses every operation** unless `PAARI_AGENTIC_PROVIDER` names a real adapter. That refusal is intentional — see the settlement invariant below.
- `app/transitions.py` — single source of truth for `ProviderTransaction.state` transitions; illegal jumps raise `IllegalTransitionError`. Phase 9 vocabulary: `AUTHORIZED -> PROVIDER_SUBMITTED -> PROVIDER_AUTHORIZED -> CAPTURED -> PAID`. `PAYMENT_PENDING` is retired (migration `c3d4e5f6a7b8` rewrites rows) but keeps legal exits so pre-existing rows and replays still move.
- `app/database.py` — `UTCDateTime` type decorator guarantees tz-aware UTC timestamps on **both** SQLite and Postgres (SQLite silently drops tzinfo otherwise). It also owns `resolve_database_url()` (single definition of where the URL comes from), `assert_disposable_database_url()` (gates every schema-destroying operation), and a `PRAGMA foreign_keys=ON` connect listener — without that pragma, SQLite silently enforces **no** foreign key at all.
- `sdk/paari_agent/` — reference external-agent SDK. It imports **no** server modules; the agent owns its private key.
- `tests/conftest.py` — shared fixtures. `paari_client` builds an isolated DB via Alembic, overrides `get_db`, and pre-registers an authenticated agent. Its database comes from `TEST_DATABASE_URL` (then `PAARI_DATABASE_URL`, then a SQLite scratch file) and **never** from `DATABASE_URL`: the suite `DROP SCHEMA public CASCADE`s its target, so reading the deployment variable meant `pytest -q` could destroy a live database. The ORDER of module-level statements there is load-bearing — `app.database` freezes its global engine at import, so `PAARI_DATABASE_URL` must be set *before* it is imported. An assertion in `isolate_test_environment` catches it if the two diverge.

## Environment

Required for payment execution: `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, `RAZORPAY_WEBHOOK_SECRET`, `PAARI_ADMIN_API_KEY`, `PAARI_SIGNING_KEY_PATH`, `DATABASE_URL`.

- `PAARI_LIVE=1` enforces Postgres `DATABASE_URL` + all of the above at boot; without it the server refuses to start.
- `app.main.startup_guards()` additionally refuses to boot a `PAARI_ENV=prod|prod-live` deployment that (a) points at SQLite, (b) has `RAZORPAY_API_BASE` set to anything but `https://api.razorpay.com/v1`, or (c) is not in the autonomous posture. Each of those is a way to make simulated or unauthorised activity look like production evidence.
- `PAARI_ADMIN_API_KEY` unset → server generates an ephemeral key and prints it (dev only).
- Default dev storage is SQLite (`sqlite:///./paari.db`).
- `paari_signing_key.pem` is an **unencrypted Ed25519 private key** — it is gitignored (`*.pem`, `*.key`, `*.db`, `.env`). Never commit it; every token issued under a committed key stays forgeable forever.

## Conventions & gotchas

- Session token: prefer `Authorization: Bearer <session>`. Legacy JSON `session_token` field still accepted. **Never put session tokens in URLs.**
- Protected v1 payment requests require `X-Paari-Proof`, a sender-constrained JWT bound to the session token hash, HTTP method, exact path, issue time, and a one-time JTI (replay is burned in the DB).
- Agent-requested capabilities/limits/currency are **never** authoritative — only the parent-signed delegation values apply.
- **Mandate resolution is a tri-state.** `NONE` (never had one) / `LAPSED` (existed but expired, revoked, or out of window) / `ACTIVE`. `LAPSED` must DENY in *every* mode — a lapsed grant is not an absent grant. Multiple active mandates are enforced as an **intersection**; never let the most permissive one widen a stricter one.
- **The mandate Ed25519 signature is enforced in the authorization path**, not just at creation — `app.mandates.check_mandate_signature` is called from `evaluate_mandate` and again from `_revalidate_execution` at consume time. A valid signature is never a liveness signal.
- Spending windows are **rolling** and clamped to the mandate's `valid_from`, never calendar-boundary based. Merchant/category comparisons are case-normalized in both allowlist checks and spend aggregation.
- **Governance posture has exactly one definition**: `app.config.mandate_policy()`. Never re-read `PAARI_MODE` from `os.environ` in a router, and never let an unrecognised value default to the permissive mode.
- `llm_*` fields are **client-asserted trace labels**. The `llm_tool_call` audit event is written only when attribution was claimed; `PaymentIntent.llm_attributed` records the claim. Never emit a causal marker for a request that asserted none.
- Authorization usage is reserved atomically (conditional DB update), not check-then-set. Provider submission uses `authorization_id` as the idempotency key.
- Settlement only happens from a signature-verified webhook or reconciliation — never from client claims.
- **A webhook cannot mint `PAID`.** `payment.authorized` -> `PROVIDER_AUTHORIZED`, `payment.captured` -> `CAPTURED`, and `PAID` only once `app.reconcile.confirm_capture` corroborates the capture with a direct provider read whose amount and currency equal the bounded authorization. If the read fails, the row stays `CAPTURED` (non-terminal, so the reconciler keeps working on it) — never optimistically promoted. The `PROVIDER_SUBMITTED -> PAID` edge exists solely for reconciliation of a missed webhook; the handler-side rule is pinned by reading the mapping source in `tests/test_phase9_state_machine.py`.
- `DECLINED` belongs in `TERMINAL_STATES`. A dead-end state left out of that set is re-selected by the reconciler's `notin_(TERMINAL_STATES)` filter forever — an unbounded work queue of rows that can never resolve.
- Unknown provider outcomes become `PROVIDER_UNKNOWN` and require reconciliation — never a guess.
- Multi-tenancy: `org_id` on tenant-scoped rows; non-default orgs use their own provider credentials and **never** fall back to another org's.
- Key rotation leaves a `key_sunset_at` grace window during which the old key is still accepted for session binding.

- **Autonomous provider-side settlement: seam wired, adapter implemented, live settlement NOT yet demonstrated.** `RazorpayAgenticProvider` (`app/providers/razorpay_agentic.py`) implements the `AgenticPaymentProvider` ABC over Razorpay's recurring/token API. The consume path calls `get_agentic_provider(auth.org_id)` and, when a binding exists, drives `PROVIDER_SUBMITTED → PROVIDER_AUTHORIZED → CAPTURED → PAID` through the real transition table. Settlement requires `status == "captured"` from both `capture_payment` and `get_payment` before `PAID` is granted. **No live autonomous settlement has been demonstrated yet** — the recurring endpoint requires a real token from a first checkout payment. Never claim a payment reached `PAID` without a provider-confirmed capture.
- **Say "the agent proposed a payment and Paari validated its authority", not "the agent autonomously authorized/paid".** Governance ALLOW, a bounded authorization, and a created provider order are three different facts from settlement. `docs/RELEASE_NOTES_V2_GOVERNANCE.md` and `README.md` carry the canonical wording — keep new prose consistent with it, and never let a test-count or capability claim in a doc disagree with the tree it describes.
- **Provider provenance is a column, not a banner.** `ProviderTransaction.provider_environment` / `provider_key_id_prefix` / `provider_api_base` are stamped at consume time from the adapter that actually made the call (`RazorpayAdapter.provenance()`), and `app.proof_bundle._settlement_source` maps them to `provider|simulator|unattributed`. A bundle whose environment is `unknown` or `simulated` must never be presented as a provider settlement, and `webhook_verified` means only "a signature verified" — it does not say whose webhook it was.
- **Proof harnesses read posture and provider from the server (`/health`), never from their own `os.environ` or CLI flags.** `mandate_mode`, `provider`, and `provider_environment` are server-reported; a harness that infers them can print `mode: autonomous` against a standard-mode server, which is the false-green this rule exists to prevent. Assert denial *reasons*, not just `decision == "deny"` — an over-mandate probe with caps set equal to the delegated limit proves the delegation check, not the mandate.

## Docs

- Protocol surface & objects: `docs/PROTOCOL.md`, `schemas/`
- Conformance contract (required interoperability tests): `docs/CONFORMANCE.md`
- Security model & threat table: `docs/SECURITY.md`
- Phase notes: `docs/PHASE6_HARDENING.md`, `docs/PHASE7_8.md`