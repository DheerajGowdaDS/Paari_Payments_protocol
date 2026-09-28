# Paari v2 governance extension — signed mandates, spend windows, causal audit

This document records the governance milestone release. A later provider-native
settlement extension supersedes the old "provider boundary" stopping point for
protocol conformance: see `docs/PROVIDER_AUTONOMOUS_SETTLEMENT.md` and the
`reference_autonomous` provider. Real-money autonomous settlement remains
provider-entitlement dependent and is never simulated as live payment.

## Added — Sprint 5: cryptographic mandate signing

- `app/mandate_signing.py`: canonical mandate payload (signature excluded),
  Ed25519 sign/verify over `canonical_json(payload)`, stored verification
  material (`user_public_key_pem`, `signing_key_id`, `signed_at`).
- `POST /v1/mandates` accepts `user_public_key_pem` +
  `mandate_signature_b64` (+ optional `signing_key_id`) and **verifies before
  persisting**; a bad signature is rejected with 400.
- Optional client-chosen `mandate_id` (same trust pattern as `delegation_id`)
  so a trusted surface can pre-compute the signed payload; uniqueness
  enforced (409).
- Mandate views (`/v1/mandates/active/{agent}`, mandate responses) now expose
  `signature_b64`, `signature_valid`, `signing_key_id`, `signed_at`.
- Verification is fail-closed and independent of liveness: a valid signature
  does NOT make an expired or revoked mandate spendable (tested).

## Added — Sprint 6: advanced spending governance

- New mandate limits: `max_per_hour`, `max_per_merchant_per_day`,
  `max_category_per_day` (model, migration, API, responses).
- `app/mandates.py`: `hourly_spend`, `merchant_daily_spend`,
  `category_daily_spend` over a shared `_spend_since` aggregation; all wired
  into `evaluate_mandate` (NULL limit = not enforced).
- Concurrency: mandate evaluation runs under a serialization gate
  (`acquire_mandate_serialization`) — SQLite `BEGIN IMMEDIATE`, Postgres
  `pg_try_advisory_xact_lock` — re-resolving the mandate under the gate, so
  concurrent submissions cannot both pass on stale totals. Gate acquisition
  failure fails closed.
- Category budgets fail closed when a category is required but absent.

## Added — Sprint 7: LLM causal audit

- `PaymentIntent` gains `llm_run_id`, `llm_model`, `llm_tool_call_id`,
  `llm_tool_name` (identifier-only, normalized, never authorization inputs).
- New `llm_tool_call` audit event; causal ids are carried into
  `intent_decided`, `authorization_minted`, `authorization_consumed`,
  `order_submitted`, `webhook_applied`, `mfa_verified` details.
- Audit chain now reads `llm_tool_call → intent_decided → … → PAID`
  (existing chain tests updated).
- Plumbing: `PaariAgentClient.payment_intent(...)` accepts the four fields;
  `PaariBroker.causal` (`CausalContext`) stamps run/model/tool-call ids; the
  agent loop refreshes the tool-call id per invocation.

## Changed — governance posture (PAARI_MODE)

- `PAARI_MODE=autonomous` (or legacy `PAARI_REQUIRE_USER_MANDATE=1`) makes an
  active user payment mandate REQUIRED; `PAARI_MODE=standard` (default)
  preserves legacy v1 behavior. In both modes an existing mandate's
  constraints are always enforced.
- Provider-mandate binding now fails closed (409) for a mandate outside its
  validity window, not just a revoked one.
- `app/transitions.py` documents the plan↔implementation state-name mapping
  (`PAYMENT_PENDING ≈ PROVIDER_AUTHORIZED`, `PAID ≈ CAPTURED+settlement`).

## Added — provider boundary completion (Priority 4, honest)

- `AgenticPaymentProvider` surface completed: `status`, `validate_mandate`,
  `authorize_payment`, `capture_payment`, `get_payment`, `verify_webhook`,
  `revoke_mandate`, `supports_autonomous_settlement`.
- `NotConfiguredAgenticProvider` (status `NOT_CONFIGURED`) refuses every
  agentic operation with explicit `NotImplementedError`. No endpoint is
  invented; no capture is simulated.

## Added — Sprint 8: autonomous E2E harness

- `scripts/autonomous_payment_e2e.py`: owns the full stack, implements the
  canonical mandate payload **independently** (as an external trusted surface
  would), proves signed-mandate acceptance + forged-signature rejection,
  authority read, expired-mandate binding refusal, governed payment with
  causal ids, single-use consume, replay refusal, and the hash-chained audit
  chain starting at `llm_tool_call` — then prints
  `AUTONOMOUS_PROVIDER_CAPTURE: NOT_CONFIGURED`.

## Tests

- `tests/test_mandate_hardening.py`: 11 tests. Regression cover for the three
  P0 money-path defects plus posture hardening, and the blueprint's missing
  expiry matrix (expired +/- valid signature / revoked / valid delegation).
- `tests/test_evidence_hardening.py`: 9 tests. Case-normalized aggregation,
  causal-attribution honesty, lifecycle sweepers, and evidence completeness.
- `tests/test_v2_governance.py`: 13 tests covering signing roundtrip via the
  API, tamper rejection, expiry-with-valid-signature, hourly/merchant/category
  budgets, fail-closed category, causal audit chain, autonomous mode,
  NOT_CONFIGURED adapter, expired binding.
- Full suite: **214 passed, 2 skipped** (`pytest -q`), as of 2026-09-26.

## Fixed — P0 money-path defects (2026-09-26 review)

These were live defects on the payment path. Each has a regression test that
fails against the pre-fix code.

### 1. A lapsed mandate no longer silently becomes "no mandate"

`active_mandate()` filtered on `expires_at > now`, so an expired or revoked
mandate resolved to the same value as "this agent never had a mandate". In
`standard` mode that turned an expired spending cap into **no cap at all**:
the payment was `ALLOW`ed with `reasons=["all checks passed"]` and
`mandate_id=null`. Mandate resolution is now a tri-state
(`app.mandates.MandateState`: `NONE` / `LAPSED` / `ACTIVE`) and `LAPSED` denies
in **every** mode. `GET /v1/mandates/active/{agent_id}` now distinguishes the
two cases in its 404 detail.

### 2. The Ed25519 mandate signature is now enforced in the authorization path

It was verified exactly once, at creation, and again for display - so it was
write-once decoration and a direct DB edit could freely raise a *signed*
mandate's limits. `app.mandates.check_mandate_signature` is now called from
`evaluate_mandate` **and** from `_revalidate_execution` at consume time. A
mandate that carries a signature must always verify; an unsigned mandate is
rejected when `PAARI_REQUIRE_SIGNED_MANDATE=1`.

### 3. The tightest active mandate governs

`active_mandate()` ordered by `expires_at DESC`, selecting the longest-lived
mandate regardless of its limits, so a broad 90-day grant silently overrode a
narrow 1-day one. All active mandates are now evaluated and the effective
policy is their **intersection**; gates are acquired for every active mandate
in sorted (deadlock-free) order.

### 4. Governance posture has one definition and fails closed

The posture was defined three times (a dead `_mandate_mode()` in
`routers/v1.py`, an inline copy in `routers/payments.py`, and an unread key in
`load_config`), and an unrecognised `PAARI_MODE` silently degraded to
`standard` - making the mandate optional. `app.config.mandate_policy()` is now
the single source of truth, validated against a literal mode set, and surfaced
on `/health` alongside `autonomous_settlement`.

## Fixed — aggregation, provenance, lifecycle, evidence

- **Rolling windows.** Budgets reset on calendar boundaries (UTC midnight / top
  of the hour), which a caller could straddle to spend a full budget twice
  within seconds. Windows are now rolling and clamped to the mandate's own
  `valid_from`.
- **Case-normalized dimensions.** Allowlists are case-insensitive but spend
  aggregation was not, so `AMAZON` then `amazon` reset the per-merchant budget.
- **Honest causal attribution.** The `llm_tool_call` audit event was written for
  *every* payment, including clients that sent no causal ids, so the chain
  asserted a model tool invocation that never happened. It is now written only
  when attribution was actually claimed; otherwise a `payment_proposed` event
  is recorded, and `PaymentIntent.llm_attributed` makes the claim queryable.
  Causal ids remain **client-asserted trace labels**: Paari proves the
  authenticated agent submitted them (they ride on the sender-constrained
  `Paari-Proof-JWT`), not that a model produced them.
- **Lifecycle sweepers.** `review_expires_at` was written but never read, so a
  velocity-parked intent burned mandate budget for the whole window with no
  recovery path; `MandateStatus.EXPIRED` was an unreachable enum member. Both
  are now swept by `app.mandates.run_sweepers`, exposed at
  `POST /v1/admin/mandates/sweep`.
- **Audit chain serialization.** `record_audit` chains off the last event for a
  client-supplied `transaction_id`; concurrent requests could fork the chain
  and make `verify_chain` return `False` forever. Appends are now serialized
  via a transaction-scoped advisory lock that never commits (see
  `app/serialization.py`).
- **Evidence completeness.** The proof bundle now carries the three Sprint 6
  limits and the full signature material, and `_mandate_view` reports real
  merchant/category spend instead of a hardcoded `None`.
- **Timestamp invariant.** The v2 migration used `DateTime(timezone=True)` for
  `signed_at`, violating the repo-wide `UTCDateTime` rule; fixed.
- **Agentic DI seam.** `app.providers.agentic.get_agentic_provider(org_id)`
  mirrors `get_provider_for_org` and resolves via an explicit
  `PAARI_AGENTIC_PROVIDER=module:Class` opt-in, defaulting to the refusing
  `NotConfiguredAgenticProvider`. A malformed or non-conforming spec raises
  rather than silently falling back.

## Fixed — PostgreSQL-only defects found by a live E2E run (2026-09-26)

Running the suite against a real PostgreSQL 16.15 instance (not SQLite)
surfaced defects that the SQLite-only suite structurally could not detect.

### The test suite had never actually been validated against Postgres

`tests/conftest.py::_migrate_fresh` reset the database with
`url.removeprefix("sqlite:///")` and `Path(...).unlink()`. For any non-SQLite
URL that expression returns the whole DSN, `Path(...)` never exists, and the
reset was a **silent no-op** — every test shared one accumulating database.
A Postgres run failed with `duplicate key ... organizations_org_id_key` and
similar `UniqueViolation` noise unrelated to the code under test. `_reset_database`
now drops and recreates the `public` schema for server-side databases, so each
test gets a genuinely empty schema on both dialects. Effect: a full Postgres
run went from **42 failed / 131 passed** to **172 passed / 1 failed**.

### `ParentStatus.SUSPENDED` was unreachable on PostgreSQL

`models.ParentStatus` has carried `SUSPENDED` since the trust-provider work, but
the baseline migration created the native Postgres enum type with only
PENDING_VERIFICATION / ACTIVE / REJECTED / REVOKED and no later revision
extended it. On PostgreSQL, `UPDATE parent_authorities SET status = 'SUSPENDED'`
raised a `DataError` — **an operator could not suspend a parent authority at
all**, while SQLite (label stored as TEXT) accepted it silently. Revision
`c2d3e4f5a6b7` adds the missing label via `ALTER TYPE ... ADD VALUE IF NOT
EXISTS` inside an autocommit block.

### `user_payment_mandates.status` model/migration drift

The model declares `Enum(MandateStatus)` (a native `mandatestatus` type on
Postgres) but migration `d0e1f2a3b4c5` created the column as `varchar(20)` with
a lowercase server default of `'active'` — a different case from the label the
ORM writes. `alembic check` reported permanent drift, and the case mismatch was
a latent hazard for any row falling back to the default. Revision
`d3e4f5a6b7c8` creates the native type, upper-cases existing values, and
converts the column.

### Two tests that only passed because SQLite does not enforce foreign keys

- `tests/test_reconcile_worker.py` inserted a `BoundedAuthorization` whose
  `intent_id` had no matching `PaymentIntent`. The Phase 6 multi-tenancy
  migration adds a real FK on Postgres; SQLite passes because FK enforcement is
  off by default. The fixture now creates the intent.
- `tests/test_migrations.py::test_baseline_migration_roundtrip` set an explicit
  SQLite URL, but `alembic/env.py` lets an ambient `ALEMBIC_URL` override it, so
  under a Postgres run the test migrated Postgres and then failed with
  `no such table: parent_authorities` on its own tmp file. The test now clears
  the ambient override.

### Schema drift — resolved 2026-09-26 (was: "known remaining drift, not fixed")

Everything listed below as previously outstanding is now closed:

- **`payment_intents.agent_id -> agents.agent_id`** has a migration
  (`e4f5a6b7c8d9`) and, on PostgreSQL, an enforced constraint.
- **Unique constraint versus unique index** mismatches on
  `payment_instrument_bindings`, `provider_accounts` and
  `user_payment_mandates`, and the hand-created
  `ix_user_payment_mandates_active_lookup` composite index, now agree between
  model and migration.
- **The eight foreign keys that only existed on PostgreSQL** — the multitenancy
  and request-proof revisions each wrapped `create_foreign_key` in
  `if bind.dialect.name == "postgresql"`, so on the default development backend
  every FK the models declare was documentation rather than a constraint — are
  now emitted on both backends by `f5a6b7c8d9e0`, which introspects the live
  schema and adds only what is absent. `PRAGMA foreign_keys` is turned on per
  connection in `app/database.py`, so SQLite enforces them too.
- **`alembic check`** reports `No new upgrade operations detected` on a freshly
  migrated SQLite database. The one remaining apparent difference —
  `user_payment_mandates.status` as `VARCHAR(20)` on SQLite versus the model's
  `Enum` — is not fixable there, because SQLite has no native ENUM type;
  `alembic/env.py:compare_type` encodes that backend limitation explicitly and
  still reports drift when the stored column is too narrow for the declared
  values.

Caveat that has NOT been retired: PostgreSQL parity was verified by reading the
migration chain, not by executing it — no PostgreSQL instance was reachable in
the environment where this was written. The new `postgres-full-suite` CI job is
what actually proves it.

### Not validated end to end

`scripts/foreign_agent_proof.py` step 10 ("browser pays the order; webhook
captured") requires a human to complete Razorpay Test-Mode checkout, or a
publicly reachable webhook URL. Neither is available in this environment, so
that step is unproven here. Steps 1-9 were verified green against real
PostgreSQL and real Razorpay, including a real `order_...` id confirmed by
fetching it back from `api.razorpay.com`.

## Validation performed

> **These are the 2026-09-19 results, preserved as run.** They are not the
> current numbers and the last bullet is now superseded: `alembic check` is
> clean on SQLite, the FK listed as missing under "known drift" exists, and the
> suite is at **214 passed, 2 skipped**. Kept rather than edited because a
> verification log that silently updates itself is worthless as evidence —
> append, don't overwrite.


- `python -m compileall -q app sdk scripts tests` - clean.
- `pytest -q` (SQLite, the default CI path) - **172 passed, 1 skipped**.
- `pytest -q` against a **real PostgreSQL 16.15** with per-test isolation -
  **172 passed, 1 failed** (the failure is `alembic check` reporting known
  cosmetic index/constraint drift, documented above).
- `pg_try_advisory_xact_lock` concurrency gate verified passing on real
  PostgreSQL, not just SQLite's `BEGIN IMMEDIATE`.
- `python scripts/autonomous_payment_e2e.py` with real Razorpay credentials -
  **AUTONOMOUS E2E GREEN**, `provider mode: real-razorpay`, stopping at
  `AUTONOMOUS_PROVIDER_CAPTURE: NOT_CONFIGURED`. The created order
  (`order_TgfCzGYkiTvD0s`) was independently confirmed by fetching it back
  from `https://api.razorpay.com/v1/orders/...` (HTTP 200, correct amount,
  receipt = authorization_id, Paari notes attached, status `created`).
- `python scripts/foreign_agent_proof.py` against real PostgreSQL + real
  Razorpay - steps 1-9 PASS, including a second real order
  (`order_TgfMMNw6laSntY`) confirmed directly against the Razorpay API. Step 10
  is unproven (needs human checkout or a public webhook URL).
- The harness now prints its provider mode in the final verdict, because a
  GREEN run against the local stub must not be mistaken for a live Razorpay
  proof.
