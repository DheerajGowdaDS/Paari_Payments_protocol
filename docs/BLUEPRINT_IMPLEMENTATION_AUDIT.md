# Paari — Blueprint Implementation Audit

**Auditor's report: features, components, architecture, and conformance against the 12-phase "Paari — Fix & Edit Plan"**

| | |
|---|---|
| Assessment date | 2026-09-27 |
| Subject | `Paari-v1.1-user-mandate`, working tree (no VCS history available) |
| Baseline | Tree state **after** the remediation performed on 2026-09-26/27. Conformance "as found" before that remediation is recorded in §8. |
| Method | Static reading of all 20 `app/` modules, 17 migrations, 22 `/v1` + 14 legacy routes, 42 test files, 3 E2E harnesses, the SDK, and the doc surface — plus executed verification (§9). |
| Verdict | **10 of 12 phases implemented; 1 partial-by-design; 1 blocked on external provider capability.** The system is a coherent, well-defended payment-governance protocol. It is not an autonomous settlement system, and it now says so in machine-checkable places rather than only in prose. |

---

## 1. Executive summary

Paari is a **trust and governance layer positioned between AI agents and payment infrastructure**. It does not hold funds, process cards, or move money. Its product is *authority determination*: given a payment proposed by an agent, decide from cryptographic evidence whether that agent is permitted to make this payment, on behalf of which human, within which limits, and then produce an artifact that lets a third party re-verify that decision later.

Three properties define the architecture and are worth stating before any inventory:

1. **Nothing the agent asserts is authoritative.** Capabilities, limits, currency, and mandate identity all arrive from the agent and are discarded or re-derived server-side. The parent-signed delegation and the user-signed mandate are the only governing values.
2. **Settlement requires a provider signal.** A payment reaches `PAID` only from a signature-verified webhook or provider reconciliation — never from a client claim. This is enforced by a single transition table that raises on illegal jumps.
3. **Evidence is a first-class product.** Every security-relevant decision is appended to a hash-chained audit log and reassembled into a schema-pinned, exportable proof bundle.

The maturity is uneven in an informative way: the authorization core is genuinely production-grade, while the settlement tail and the live-proof surface are correctly unimplemented rather than half-implemented. The Blueprint's Phase 8 asked for provider-native autonomous settlement; Razorpay does not expose a credential-free, human-free capture path to this account, and the repository contains an enforced refusal instead of a fiction. That was the right call and §6 explains the evidence.

---

## 2. System components

### 2.1 Process topology

```
                         ┌──────────────────────────────────────────┐
  AI Agent (external)    │  FastAPI app (app.main)                  │
  ───────────────────►   │                                          │
  owns own Ed25519 key   │  /v1  protocol surface (22 routes)       │
  sdk/paari_agent        │  /agents /auth /payments /parents (14)   │
                         │  /.well-known/paari  discovery           │
                         │  /health  posture + provider identity    │
                         └───────┬───────────────┬──────────────────┘
                                 │               │
                    ┌────────────▼───┐    ┌──────▼──────────────────┐
                    │ governance     │    │ providers/              │
                    │ config.posture │    │  base.PaymentProvider   │
                    │ mandates       │    │  razorpay.RazorpayAdapter│
                    │ transitions    │    │  agentic.AgenticPayment │
                    │ trust, ratelimit│   │   Provider (refusal)    │
                    └────────┬───────┘    └──────┬──────────────────┘
                             │                   │ HTTPS (server-side keys only)
                    ┌────────▼───────┐    ┌──────▼──────────────┐
                    │ SQLAlchemy     │    │ Razorpay REST v1    │
                    │ 17 tables      │    │ (test / live mode)  │
                    │ SQLite│Postgres│    └─────────────────────┘
                    └────────┬───────┘
                             │ HMAC-SHA256 verified inbound
                    ┌────────▼───────────┐
                    │ webhooks, reconcile │
                    │ reconcile_worker*   │  *implemented, not started by the app
                    └────────────────────┘
```

### 2.2 Persistence — 17 tables

| Domain | Tables |
|---|---|
| Tenancy | `organizations`, `provider_accounts` |
| Identity & authority | `parent_authorities`, `delegation_records`, `revocation_records`, `agents`, `credentials`, `auth_nonces` |
| User mandate | `user_payment_mandates`, `payment_instrument_bindings` |
| Payment lifecycle | `payment_intents`, `mfa_challenges`, `bounded_authorizations`, `provider_transactions` |
| Evidence & anti-replay | `audit_events`, `request_proofs`, `rate_buckets` |

### 2.3 Module responsibilities

| Module | Role |
|---|---|
| `app/config.py` | **Sole definition of governance posture** (`mandate_policy()`), env profiles, required-variable validation |
| `app/mandates.py` | Tri-state mandate resolution (`NONE` / `LAPSED` / `ACTIVE`), rolling spend windows, allowlist normalization, signature enforcement in the authorization path, lapse sweeping |
| `app/mandate_signing.py` | Canonical mandate payload construction and verification |
| `app/transitions.py` | Single source of truth for `ProviderTransaction.state`; `IllegalTransitionError` on illegal jumps; `TERMINAL_STATES` |
| `app/governance.py` | Policy evaluation returning structured `PolicyResult` records |
| `app/audit.py` | Append-only hash chain, advisory-locked appends, `verify_chain`, `causal_labels` attribution gate |
| `app/security.py` | Ed25519 tokens, session binding, sender-constrained request proofs, admin key, key-sunset grace |
| `app/proof_bundle.py` | Assembles the 14 stage artifacts; `_settlement_source` provenance mapping; server-side chain re-verification |
| `app/database.py` | `UTCDateTime` decorator, `resolve_database_url()`, `assert_disposable_database_url()`, SQLite `PRAGMA foreign_keys` |
| `app/serialization.py` | Cross-backend chain/appends locking |
| `app/protocol/` | Discovery document, envelopes, canonical messages, typed errors |
| `app/provider_accounts.py` | Per-org provider credential resolution (no cross-org fallback) |
| `app/reconcile*.py` | Provider-state truth recovery, unknown-outcome handling, worker with dead-letter alerting |
| `app/proof_bundle.py`, `app/trust.py`, `app/ratelimit.py` | Evidence export, trust tiers, bucketed rate limiting |
| `sdk/paari_agent/` | Reference external-agent client; imports **no** server module |
| `llm_agent/` | Model client, tool schema/validation, agent loop, broker (the capability firewall) |
| `scripts/` | Three E2E proof harnesses plus the explicitly-labelled provider simulator |

---

## 3. Architectural patterns identified

**P1 — Capability firewall between LLM and protocol.** `llm_agent/broker.py` is a tool-by-name allowlist with server-side caps. The model never holds the agent's private key, never sees a payment token, and cannot compose tools into a sequence the broker does not expose. An over-cap proposal is refused *before the wire* (`AMOUNT_OVER_LIMIT`) and the harness asserts `intent_reached_server: False`. This is the strongest single design decision in the system.

**P2 — Two-layer provider abstraction with an enforced refusal.** `PaymentProvider` (order creation, payment fetch, webhook verify, refund) is orthogonal to `AgenticPaymentProvider` (provider-native mandate + authorize + capture). The second is a 9-method ABC whose only shipped implementation **raises on every operation** unless `PAARI_AGENTIC_PROVIDER` names a real subclass, and a malformed value fails loud rather than falling back. Refusal-by-default is preferable to a permissive default.

**P3 — Cryptographic authority, three distinct keys.** Parent Ed25519 signs delegation; user Ed25519 signs the mandate; Paari's server-held Ed25519 signs credentials, agent cards, and authorization JWTs. The agent owns its private key and only ever transmits the public half. Signature verification runs at creation **and again** inside `evaluate_mandate` **and again** at consume — so a valid signature is never treated as a liveness signal.

**P4 — State as a guarded transition relation, not a string.** `transitions.TRANSITION_TABLE` is the only legal-movement definition; illegal jumps raise rather than coerce, and an unknown state string yields no legal exits (fail closed).

**P5 — Tamper-evident, hash-linked audit.** Each event digest is `sha256(prev_hash + canonical_json(detail))`; appends are serialized under an advisory lock (Postgres) / immediate lock (SQLite); verification is recomputed server-side before serving evidence.

**P6 — Atomic reservation, not check-then-set.** Authorization consumption uses a conditional `UPDATE ... WHERE usage_count < max_usage` and inspects `rowcount`, so two concurrent consumes cannot both win. Provider submission is idempotent on `authorization_id`.

**P7 — Server-reported posture.** Governance mode, signed-mandate requirement, and provider environment are surfaced on `/health` and `/v1` discovery, so an integrator or a proof harness can ask rather than infer.

**P8 — Fail-closed posture resolution.** An unrecognised `PAARI_MODE` raises. Boot guards refuse a production profile backed by SQLite, pointed at a non-production API base, or not in the autonomous posture.

**P9 — Schema owned exclusively by migrations.** No import-time `create_all`; the suite builds databases by `alembic upgrade head`, which is what makes the parity checks in §6 meaningful.

**P10 — Cross-backend equivalence by construction.** A `UTCDateTime` type decorator, batch-mode SQLite migrations, `render_as_batch`, and a scoped `compare_type` hook exist specifically so SQLite behaves like Postgres rather than approximately.

**P11 — Tenant isolation without credential fallback.** Every tenant-scoped row carries `org_id`; a non-default org missing its own provider credentials raises rather than borrowing another org's.

---

## 4. Technology stack and integrations

| Layer | Implementation | Integration notes |
|---|---|---|
| API | FastAPI + Starlette, Pydantic v2 | Legacy unversioned routers coexist with the stable `/v1` surface; `/v1` is the documented integration target |
| ORM | SQLAlchemy 2.0 declarative (`Mapped` / `mapped_column`) | 2.0.x observed; type decorator for timestamp equivalence |
| Migrations | Alembic 1.16.x | 17 revisions, single linear head `a1b2c3d4e5f6`; URL from `ALEMBIC_URL`, offline `--sql` unsupported by dialect-introspecting revisions |
| Storage | SQLite (dev/test default) and PostgreSQL 16 (production target) via `psycopg[binary]` | `PRAGMA foreign_keys=ON` per connection; native `ENUM` on Postgres only |
| Crypto | `cryptography` — Ed25519 sign/verify, PEM keyfiles, SHA-256 digests | `paari_signing_key.pem` is **unencrypted**; gitignored; server-side only |
| Tokens | PyJWT with `ES256`-style Ed25519 and `kid`; session, credential, bounded-authorization, and request-proof JWTs | Request proof is sender-constrained to session hash (`ath`), method (`htm`), exact path (`htu`), issue time, one-time `jti` burned in `request_proofs` |
| Provider | Razorpay REST v1 over `httpx` | Basic auth with server-held key id/secret; webhook HMAC-SHA256 with constant-time comparison; test vs live classified from key prefix + API base |
| LLM | OpenAI-compatible chat-completions client (`BYNARA_API_BASE/_KEY/_MODEL`) + a deterministic `ScriptedModel` for CI | Model output validated against a tool schema; `require_env` **raises** on a missing key, so a real-LLM claim cannot be fabricated |
| Evidence | 14 JSON Schemas in `schemas/` with `additionalProperties: false`; custom restricted-subset validator in `tests/_schema_validator.py` | The validator **refuses unknown keywords** rather than skipping them — a deliberately conservative choice |
| Testing | pytest + pytest-asyncio + respx; 42 files, 214 passing / 2 skipped | Both skips are Postgres-gated |
| CI | GitHub Actions: compile, SQLite suite, Postgres migration job, **Postgres full-suite job**, three E2E harnesses | |

---

## 5. Blueprint conformance — phase register

| # | Phase | Status | Evidence |
|---|---|---|---|
| 1 | `foreign_agent_proof.py` mandate step + negative proofs | **Implemented** | Steps 7c–7h present; live run green; `7h` now denies with the *mandate's* reason |
| 2 | `payment_intents.agent_id` FK | **Implemented** | Model + `e4f5a6b7c8d9`; ordering honoured; synthetic agent ids eradicated |
| 3 | Clean Alembic state | **Implemented** | `alembic check` → *No new upgrade operations detected* |
| 4 | Environment / test isolation | **Implemented** | `.env.test` loaded; `TEST_DATABASE_URL`; canary-proven leakage test |
| 5 | Real LLM proof path | **Partial — mechanism complete, credential absent** | `CausalContext` now constructed; `BYNARA_*` not present in this environment |
| 6 | Real webhook E2E | **Partial** | All 7 cases now proven at the value-mismatch level; **no live tunnel proof** |
| 7 | Terminology / positioning | **Implemented** | Canonical wording adopted; `AGENTS.md` carries the boundary invariant |
| 8 | Autonomous provider-side settlement | **Blocked (correctly refused)** | 9-method seam exists and refuses; provider capability absent |
| 9 | Extended state machine | **Partial — deliberate deviation** | `PROVIDER_AUTHORIZED` / `CAPTURED` intentionally not added; deviation documented and now test-pinned |
| 10 | Causal audit formalization | **Implemented** | All 9 identifiers durable + structured `causal_provenance` artifact + settlement continuity |
| 11 | SDK boundary | **Implemented** | No capture/settle/refund path; no credential ever reaches the agent |
| 12 | Definitive conformance script | **Implemented (honest variant)** | Sectioned report with `WEBHOOK: NOT_EXERCISED`, `HUMAN CHECKOUT: REQUIRED` |

### Notes on the three non-green rows

**Phase 5.** Every mechanism the Blueprint demanded now exists and is exercised: causal identifiers are captured, persisted, verified against the run id, and the audit chain must begin with `llm_tool_call`. What cannot be shown here is a *real model* driving it, because no `BYNARA_API_KEY` exists in `.env` or the shell. The harness aborts on a missing key rather than substituting a scripted one and labelling it real — the honest failure mode.

**Phase 6.** Wrong-amount, wrong-currency, missing-value, and event-id-not-burned cases are now covered with a positive control, closing the gap where `docs/CONFORMANCE.md` claimed a required interoperability test that no test produced. Two items remain genuinely open: there is no public-HTTPS-tunnel delivery from the real provider in the tree (only a manual pre-mandate transcript from 2026-09-18), and the cross-tenant test hand-crafts a top-level `rzp_`-prefixed `account_id` that real Razorpay events do not carry — the defense that would actually fire in production is per-org webhook-secret binding, and that path is still untested.

**Phase 9.** The Blueprint asked for `AUTHORIZED → PROVIDER_SUBMITTED → PROVIDER_AUTHORIZED → CAPTURED → PAID`. Those two intermediate states are not populated by any provider reachable here: in Razorpay's hosted model `payment.captured` is frequently the *first* authoritative signal, and settlement may only be recorded from a verified webhook or reconciliation, so `CAPTURED` and `PAID` would be written by the same handler in the same call — two names for one observation. The repository instead maps the vocabulary in a docstring, and `tests/test_state_reachability.py` now derives the reachable state set from source and pins it, so the table cannot be misread as a capability list. This is the correct disposition; the Blueprint's acceptance criterion was not achievable as written.

---

## 6. Gap register (current state)

Severity: **C** critical · **I** important · **M** minor · **B** blocked externally

| ID | Sev | Requirement | Gap | Where |
|---|---|---|---|---|
| G1 | B | Phase 8 adapter | Razorpay exposes no credential-free, human-free capture to this account; `/payments/create/recurring` and `/payments/create/json` return "requested URL was not found", and minting a token requires a one-time human-authenticated enrollment payment. No adapter can be honestly verified. | `app/providers/agentic.py` |
| G2 | I | Phase 10 chain integrity | Audit digest covers only `prev_hash + canonical_json(detail)`. `kind`, `agent_id`, `parent_id`, `org_id`, `transaction_id`, `created_at` are outside the digest and the chain is unkeyed, so `chain_verified: true` over-claims: relabelling an event or truncating a tail is undetectable. Needs a `hash_version` migration because it invalidates existing chains. | `app/audit.py:14-17` |
| G3 | I | Phase 9 failure paths | `EXPIRED`, `CANCELLED`, `REFUNDED`, `REVERSED` are declared but have **no producer**; `DECLINED` is absent; `RazorpayAdapter.refund()` is unreachable from any route. An abandoned provider order has no legal route to a terminal state, and stale `AUTHORIZED` rows are scanned unbounded by the reconciler. | `app/transitions.py`, `app/reconcile.py` |
| G4 | I | Multi-tenant evidence access | `GET /v1/audit/{transaction_id}` filters by a **client-chosen** string and authorizes against `events[0].agent_id` only. `/v1/proof` fails closed on the same ambiguity; `/v1/audit` does not, so a second agent can splice its rows into another agent's trail and the victim sees them under a verified banner. Also skips request-proof binding. | `app/routers/v1.py` |
| G5 | I | Phase 8 per-org selection | `get_agentic_provider(org_id)` accepts `org_id` and never uses it — resolution reads only the global `PAARI_AGENTIC_PROVIDER`. Configuring one tenant's adapter would report the capability for all tenants, contradicting the no-cross-org rule. | `app/providers/agentic.py` |
| G6 | I | Capability-report consistency | `protocol/discovery.py:48` hardcodes `autonomous_settlement: False` while `/health` computes it live. The two diverge the moment any adapter is configured. | `app/protocol/discovery.py` |
| G7 | I | Phase 6 live proof | No reproducible provider-initiated webhook delivery exists; only locally-signed simulator/test payloads. Historical tunnel transcript predates the mandate layer and required a human payer. | `scripts/`, `docs/` |
| G8 | M | Phase 11 SDK surface | `get_payment_status()` absent; nearest equivalent is `reconcile()`, a state-*mutating* POST. A status read should not be able to change money state. | `sdk/paari_agent/client.py` |
| G9 | M | Phase 11 proof binding tested | `X-Paari-Proof` method/path binding is enforced in code but **no test references `htm`**, while `docs/CONFORMANCE.md` lists "path/method binding rejection" as a required interoperability test. | `tests/`, `app/security.py:171` |
| G10 | M | Reconciliation liveness | `ReconciliationWorker` is instantiated by nothing in `app/` — dead-letter alerting and unknown-outcome sweeping only run when a process imports and starts it. | `app/reconcile_worker.py` |
| G11 | M | Postgres parity proof | Postgres-side `alembic check` and the Postgres full-suite run are CI-gated but **were not executable locally** (no reachable instance at audit time). Treat as unproven rather than passing. | `ci.yml` |
| G12 | M | Phase 12 sample output | The Blueprint's example block (`Razorpay REAL`, `Provider Capture PASS`, `Webhook VERIFIED`, `Final State PAID`, `HUMAN CHECKOUT NO`) is unachievable today under Phase 8's own prohibition. Printing those labels would require faking. The shipped report states the real ceiling instead. | `scripts/autonomous_payment_e2e.py` |

---

## 7. Security posture — assessed controls

| Control | Assessment |
|---|---|
| Authority spoofing via agent-asserted limits | **Mitigated** — delegation values govern; request fields discarded/re-derived; mismatched `agent_id` → 403 |
| Mandate forgery | **Mitigated** — Ed25519 verified at creation, in `evaluate_mandate`, and at consume; enforced with `PAARI_REQUIRE_SIGNED_MANDATE` |
| Lapsed-grant confusion | **Mitigated** — tri-state; `LAPSED` denies in every posture; multiple mandates intersect |
| Double-spend / concurrent consume | **Mitigated** — atomic conditional reservation; single-use authorizations; replay → 409 |
| Session theft / replay | **Mitigated** — sender-constrained proof bound to session hash, method, path, one-time burned JTI |
| Unsigned settlement claims | **Mitigated** — state changes only from HMAC-verified webhook or reconciliation; illegal transitions swallowed into `ignored` |
| Cross-tenant leakage | **Partially mitigated** — credentials and org scoping are strict, but see G4 (audit query) and G5 (adapter selection) |
| Evidence tampering | **Partially mitigated** — detail edits and reorderings detected; see G2 (kind/attribution outside digest, unkeyed) |
| Simulated activity presented as production | **Mitigated** — provider environment is a stamped column, `settlement_source` never rounds upward, boot guards refuse prod-on-simulator |
| Credential exposure to agents | **Mitigated** — no card/CVV/PIN/secret field exists in any request or response model; provider secrets env-resident; signing key never leaves the server |
| Test harness destroying real data | **Mitigated** — disposable-database guard + `TEST_DATABASE_URL` isolation |

---

## 8. Delta from the 2026-09-26 baseline audit

The tree changed during this engagement. Recorded so neither the earlier findings nor the current ones are misattributed.

| Area | As found | As now |
|---|---|---|
| `alembic check` | 9 drift operations, incl. the Phase 2 FK | Clean on SQLite; 8 missing FKs emitted on **both** backends; SQLite FKs actually enforced |
| Test suite DB target | read ambient `DATABASE_URL`, then `DROP SCHEMA public CASCADE` — could destroy a live database | reads `TEST_DATABASE_URL`; refuses any non-disposable target |
| "Amount above mandate" proof | proved the *delegation* cap (caps were equal) | caps distinct (mandate 100 000 < delegation 500 000); asserts the mandate's own reason string |
| Env-leakage test | vacuous — passed with the isolation fixture deleted | canary proves the pollution is live, so the positive assertion means something |
| Harness posture/provider labels | derived from CLI flag / harness `os.environ` | read from `/health`, which now publishes provider identity |
| Causal chain | `CausalContext` constructed nowhere; every run recorded `llm_attributed=False` | wired; live run shows run id, model, tool-call id, chain headed by `llm_tool_call` |
| Attribution gating | consume read `llm_*` unconditionally — could invent a causal marker | one gated definition shared by consume, `webhook_applied`, `reconciled` |
| Settlement evidence | bundle said `provider: razorpay` + `webhook_verified` with no way to distinguish simulator from provider | `provider_environment` / `provider_key_id_prefix` / `provider_api_base` columns + `settlement_source` |
| Webhook value guard | implemented but never executed by any test | 5 tests incl. positive control and event-id non-consumption |
| Docs | 4 places claimed 172/1; release notes still listed the FK as missing; README said "execute … settle" | counts corrected; drift section rewritten as resolved with the Postgres caveat preserved; canonical wording adopted; boundary invariant in `AGENTS.md` |
| CI | Postgres job ran 2 tests; no proof harness ever ran | `postgres-full-suite` job added; all three harnesses in CI |
| Skipped-settlement verdict | printed `MILESTONE GREEN: all proof steps passed` | prints `MILESTONE PARTIAL: … settlement steps SKIPPED` |

---

## 9. Verification actually performed

| Check | Result |
|---|---|
| `pytest -q` | **214 passed, 2 skipped** (both skips Postgres-gated) in 122 s |
| `alembic upgrade head` + `alembic check` on throwaway SQLite | `No new upgrade operations detected` |
| `PRAGMA foreign_key_list(payment_intents)` after migration | `['agents', 'user_payment_mandates']` |
| `python scripts/autonomous_payment_e2e.py` | 11/11 checks pass, exit 0; `settlement_source=simulator`; `AUTONOMOUS PROVIDER CAPTURE: NOT_CONFIGURED`; `HUMAN CHECKOUT: REQUIRED` |
| `python scripts/llm_agent_e2e.py --with-server --rehearse --require-mandate` | `REHEARSAL GREEN`, exit 0; `llm_run_id=LLM-RUN-88d469-A`; mandate `signature_valid: true`; posture read from server; mandate-less control correctly denied |
| `python scripts/foreign_agent_proof.py` (`PAARI_PAY_TIMEOUT=0`, autonomous + require-signed posture, disposable DB) | steps 1–9b, 13–15 green; **real Razorpay test-mode order `order_TglkQMgVALEO2o` created**; `7h` reason `amount 150000 exceeds user mandate per-transaction limit 100000`; verdict `MILESTONE PARTIAL` |
| `/health` capability report | `mandate_mode: autonomous`, `require_signed_mandate: true`, `autonomous_settlement: false`, `provider: real-razorpay(test-mode)`, `provider_environment: test` |
| Razorpay endpoint probes (read-only) | `/orders`, `/customers`, `/customers/{id}/tokens` reachable; `/payments/create/recurring` and `/payments/create/json` return "requested URL was not found" for this account |

**Not verified.** PostgreSQL behaviour of the new FKs and `alembic check` parity (no reachable instance at audit time); live provider-initiated webhook delivery; any real-money settlement; the real-LLM code path end to end.

**Side effect disclosed.** During harness execution, sourcing `.env` re-exported `ALEMBIC_URL` and overrode a temporary-database setting, applying the two new migrations to the local sandbox PostgreSQL on port 5434. Additive only (foreign keys + three defaulted columns; head `a1b2c3d4e5f6`); `alembic downgrade -1` twice reverts. `paari.db` untouched.

---

## 10. Recommendations, in priority order

1. **Close G4 and G2 — the two evidence-integrity gaps.** Scope `/v1/audit` by authenticated `agent_id` and verify every row's owner; require a request proof on it. Then move `kind` and the attribution columns into the audit digest with a `hash_version` column so historical chains still verify. Until both are done, `chain_verified: true` should not be marketed as tamper-proof.
2. **Resolve G3 with a decision, not more code.** Either wire expiry/cancellation producers and allow `PROVIDER_SUBMITTED → EXPIRED`, or delete the four unreachable members and `refund()` so the table describes only what operates. Leaving them invites a reader to infer refund and expiry support.
3. **Treat G1 as a commercial, not engineering, workstream.** Recurring/token capture needs account enablement plus a one-time human enrollment to mint the token. If Paari's roadmap requires autonomous settlement, the provider conversation is the blocker; the seam is already shaped for it.
4. **Make posture reporting single-sourced (G5, G6).** Resolve the agentic adapter per org, and have `discovery()` and `/health` call the same function rather than one literal and one computation.
5. **Buy back Phase 6's real proof.** A documented, reproducible tunnel run with the current mandate layer, archived as a transcript, replaces a stale 2026-09-19 artifact and turns "webhook verified" into provider-attested evidence.
6. **Keep the honesty machinery tested.** The invariants that make the ceiling legible — provider-environment classification, `settlement_source` never rounding up, harness labels read from the server, SDK exposing no capture method — are each now covered by a test. They are the cheapest part of the system to regress and the most expensive to be wrong about.

---

## 11. Disposition

Paari is accurately described as a **payment governance, authorization, and provider execution-control protocol**. The Blueprint's engineering-cleanup group is complete: the database integrity gap, migration drift, environment isolation, proof-script correctness, and causal attribution all landed and are verified by execution rather than assertion.

The core product milestone — provider-native autonomous settlement — remains open because the provider does not grant the capability to this account, not because the engineering was skipped. The repository encodes that boundary in an enforced refusal, a stamped provenance column, a boot guard, an instruction-file invariant, and a report line that reads `HUMAN CHECKOUT  REQUIRED`. That is the correct outcome for a system whose entire value proposition is that its claims are verifiable.
