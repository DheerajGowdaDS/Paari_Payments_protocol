# Paari Blueprint Implementation Report + Live E2E Proof Log

Date: 2026-09-18 · Environment: `PAARI_ENV=sandbox`, Razorpay Test Mode
Scope: blueprint Tracks 1–2 (Phases 7.1–7.7, 8.1–8.7) mapped against the
actual implementation, plus the full log of the live end-to-end proof run
that closed with **MILESTONE GREEN: 15/15**.

Test suite at time of writing: **76 passed, 1 skipped** (`pytest -q`).

---

## PART A — Blueprint implementation status

Status key: **Done** = implemented and covered by tests and/or the live run.
**Partial** = present but with a noted gap. All file references are repo paths.

### Track 1 — Protocol Productionization

| Phase | Status | Evidence |
|---|---|---|
| 7.1 Protocol freeze | **Done** | `docs/PROTOCOL.md` (v1.0, canonical JSON, Ed25519/EdDSA pinning, expiry/version rules, error codes, 12 normative security requirements), 12 JSON schemas in `schemas/`, discovery `/.well-known/paari`, signed v1 Agent Card (`/v1/agents/{id}/card`), envelope signing (`app/protocol/`), `tests/test_protocol*.py`, `tests/test_schemas.py` |
| 7.2 External agent SDK | **Done** | `sdk/paari_agent/` (`client.py`, `crypto.py`, `pyproject.toml`) — imports no server modules; covers discovery, envelopes, card verification, auth, request proofs, intent/consume/reconcile/revoke. Covered by `tests/test_sdk.py`. Live proof used an even stricter client (stdlib + httpx + cryptography only, `scripts/foreign_agent_proof.py`) |
| 7.3 Parent/KYB trust | **Done (MVP)** | `app/trust.py` defines the replaceable `ParentTrustProvider` boundary; reference impl is admin approval. States present: `pending_verification`/`self_asserted`, `active`/`admin_approved`, `suspended`, `revoked` (`app/models.py` `ParentStatus`, trust tiers). **Gap vs blueprint naming:** no literal `KYB_VERIFIED` state — a real KYB provider plugs in via the interface without protocol change |
| 7.4 Payment security | **Done** | Per-org provider routing, non-default orgs never fall back (`app/routers/payments.py:_provider_for`, `app/provider_accounts.py`); webhook HMAC over raw body + exact order/amount/currency/authorization match; single-use authorizations reserved atomically; trust revalidated at execution; key rotation with `key_sunset_at` grace (`app/models.py`, `tests/test_rotation.py`, `tests/test_multitenancy.py`, `tests/test_webhook*.py`, `tests/test_consume_atomic.py`). **Live-run fix:** org-mismatch guard now only fires for `rzp_*` key IDs; `acc_*` account IDs are a different namespace (see Part B) |
| 7.5 Audit hardening | **Done** | Append-only hash-chained `audit_events`; `intent_decided` carries evaluated policies/reasons; transitions carry before/after (`from_state`/`to_state`); `tests/test_audit*.py`. Live run step 12 verified the chain locally |
| 7.6 Reconciliation | **Done** | Exact receipt/order provider lookup with amount/currency verification, legal-transition-only updates, audit event (`app/reconcile.py`); background worker module (`app/reconcile_worker.py`); `tests/test_reconcile*.py`. Ops note: schedule the worker continuously and alert on long-lived `PROVIDER_UNKNOWN` (per `docs/PHASE7_8.md`) |
| 7.7 Production ops | **Partial** | Alembic migrations + Postgres migration tests (`tests/test_migrations.py`, `tests/test_postgres_migration.py`); `PAARI_LIVE=1` fail-closed boot; sandbox/prod separation test (`tests/test_sandbox_separation.py`); health checks. **Remaining for real deployment:** secrets manager, TLS/stable domain, monitoring/alerts, backups, CI/CD — infra, not code |

### Track 2 — Independent-Agent Validation

| Phase | Status | Evidence |
|---|---|---|
| 8.1 True foreign agent | **Done** | `scripts/foreign_agent_proof.py` — zero `app.*` imports (self-aborting black-box check), own Ed25519 crypto, own envelope/proof code |
| 8.2 Black-box registration | **Done** | Live steps 1–7: health → parent register → approval → self-verifying delegation → v1 register → signed-card check → challenge/auth, all from outside |
| 8.3 Authentication tests | **Done** | `docs/CONFORMANCE.md` (12 required tests) + `tests/test_phase8_security.py`, `tests/test_protocol_security_final.py`; live steps 7/15 (valid auth, revoked blocked) |
| 8.4 Governance attack suite | **Done** | `tests/test_governance_attacks.py`; live steps 5b (request limits ignored), 13 (over-delegation DENY) |
| 8.5 E2E provider test | **Done** | This run (Part B): foreign agent → trust → auth → intent → governance → bounded auth → Razorpay Test Mode → real webhook → PAID → reconcile → audit |
| 8.6 Failure & recovery | **Done** | `tests/test_failure_recovery.py` (duplicate/delayed webhook, restart, mismatch, expiry, revocation); live run itself survived 3 bugs + server restarts without double-payment (idempotency by `authorization_id`, webhook dedup by event id) |
| 8.7 Sandbox/prod separation | **Done (code)** | Separate DB/keys/secrets/credentials enforced; `tests/test_sandbox_separation.py`. Live run used sandbox-only keys and a disposable DB |

### Gaps / follow-ups (honest list)
1. Blueprint name `KYB_VERIFIED` has no literal enum — add it when a real KYB provider lands (interface already supports it).
2. 7.7 infra items (secrets manager, TLS, monitoring, backups, CI/CD) are deployment work, unchanged by this run.
3. Reconciler scheduling/alerting is an ops job (`app/reconcile_worker.py` exists).

---

## PART B — Live E2E proof run (2026-09-18)

Topology: local uvicorn + fresh `paari_live_e2e.db` + cloudflared tunnel
(`https://chess-disclosure-ensuring-interesting.trycloudflare.com`, ngrok
absent) + Razorpay Test Mode. Two ₹1 Test-Mode payments were made; the
certificate rests on the second (clean 15/15 transcript).

- Preflight: test keys validated (`GET /v1/orders?count=1` → `items[]`).
- Webhook registered by human in Test-Mode dashboard (events incl.
  `payment.authorized`, `payment.captured`, `payment.failed`).
- Bugs found by the run and fixed with explicit human approval each time:
  1. Proof script sent `Paari-Proof-JWT` header; server requires `X-Paari-Proof` → step 8 `401 PROOF_REPLAYED`. Fixed script (5 header renames).
  2. Webhook org guard compared event `acc_*` account IDs against `rzp_*` key IDs → every real webhook `403`. Guard now fires only for `rzp_*` IDs.
  3. Script omitted `agent_id` in steps 13/15 bodies → `422` + `KeyError`. Added the field.
- Run 1 (order `order_TdWsKTjuo5waPv`, payment `pay_TdWvaTlWWDtpTQ`): 12/15, crashed at 13 on bug 3.
- Run 2 (order `order_TdXBPQUUBh4SSY`, payment `pay_TdXDCpX6N1W0MN`): **15/15**.
- Raw log: `docs/e2e_transcript_2026-09-18.log` (19 lines, machine-verified
  secret-free: no key_secret, admin key, or webhook secret present).
- Teardown: server + tunnel killed; `paari_live_e2e.db` kept as audit record.

### Certificate
- `order_id`: `order_TdXBPQUUBh4SSY`
- `payment_id`: `pay_TdXDCpX6N1W0MN`
- Audit verdict: hash chain locally verified
  (`intent_decided → authorization_minted → authorization_consumed →
  order_submitted → webhook_applied → webhook_applied`); reconcile terminal
  `PAID`; over-delegation `DENY`; revoked agent blocked (`401 AGENT_REVOKED`).
- **MILESTONE GREEN: 15/15 steps passed.**

### Secret handling
Test `key_secret` lived in process env only, never printed or written.
Generated admin key + webhook secret likewise; the dashboard webhook secret
was user-supplied. No commits were made (working tree only).
