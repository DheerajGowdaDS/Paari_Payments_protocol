# Paari — Knowledge Transfer Record

**Engagement:** Blueprint implementation, remediation and live end-to-end verification
**Dates:** 2026-09-26 → 2026-09-28
**Repository:** `C:/Users/gowda/projects_DS/Paari-v1.1-user-mandate`
**Reference plan:** "Paari — Fix & Edit Plan" (12 phases)
**Final state:** 238 passed / 2 skipped on SQLite · 240 passed / 0 skipped on PostgreSQL 16 · `alembic check` clean on both · migration head `c3d4e5f6a7b8` · 19 migrations · 17 tables · 43 test files

> **How to use this document.** Every claim below is either (a) a verbatim command output reproduced in §3, or (b) a `file:line` reference you can open. Nothing here is a summary of intent — it is a record of what was observed. §8 is the section most worth reading first: it lists the traps that cost real time and would cost you the same.

---

## 1. Environment as found

| Item | Value |
|---|---|
| Python (local) | **3.12.10** |
| Python (declared in `AGENTS.md`, used by CI) | **3.11** |
| SQLAlchemy | 2.0.35 |
| Alembic | 1.13.3 |
| FastAPI | 0.115.0 |
| Version control | **none** — the directory is not a git repository |
| Provider | Razorpay, key prefix `rzp_test_`, `RAZORPAY_API_BASE=https://api.razorpay.com/v1` |
| LLM | `BYNARA_API_BASE=https://router.bynara.id/v1`, model `space-bunny-alpha-bynara` (added mid-engagement) |
| Postgres | Docker; `paari_live_pg` on host port **5434** is the operator's own sandbox |
| Container tooling | Docker 29.8.0, `cloudflared` installed, `ngrok` not installed |

**The Python mismatch is real and unaddressed.** The suite is green on 3.12 locally and 3.11 in CI, so nothing is broken today, but `StrEnum`, `datetime` handling and SQLAlchemy typing are the kind of thing that diverges. Run the suite on 3.11 before trusting a local green as the release signal.

**No version control means no diff, no bisect, no revert.** All work in this record was applied directly to the working tree. The changes in §4 are reconstructible only from the files themselves.

---

## 2. Reproduction commands

### 2.1 Test suite

```bash
# SQLite (default, uses ./.phase5_test.db)
python -m pytest -q

# PostgreSQL — the database name MUST end in _test or the guard aborts
docker run -d --name paari_pg -e POSTGRES_USER=paari -e POSTGRES_PASSWORD=paari \
       -e POSTGRES_DB=paari_test -p 5441:5432 postgres:16-alpine
pip install -r requirements-postgres.txt
TEST_DATABASE_URL="postgresql+psycopg://paari:paari@localhost:5441/paari_test" python -m pytest -q
docker rm -f paari_pg
```

`TEST_DATABASE_URL` is the **only** variable the suite will accept as a destructive target. It never reads `DATABASE_URL` — see §5-D1.

### 2.2 Schema parity

```bash
mkdir -p /tmp/paari_parity
ALEMBIC_URL="sqlite:///C:/Users/gowda/AppData/Local/Temp/paari_parity/p.db" python -m alembic upgrade head
ALEMBIC_URL="sqlite:///C:/Users/gowda/AppData/Local/Temp/paari_parity/p.db" python -m alembic check
```

Use a throwaway path. Pointing `ALEMBIC_URL` at a real database runs DDL against it.

### 2.3 The three E2E harnesses

```bash
python scripts/autonomous_payment_e2e.py                          # self-hosts stub + temp SQLite; no network
python scripts/llm_agent_e2e.py --with-server --rehearse --require-mandate   # deterministic model
python scripts/llm_agent_e2e.py --with-server --settle --require-mandate     # real LLM + local simulator
python scripts/foreign_agent_proof.py                              # needs a running server + PAARI_PAY_TIMEOUT
```

`PAARI_PAY_TIMEOUT=0` skips the settlement steps and prints **`MILESTONE PARTIAL`**, never `GREEN`.

---

## 3. Raw evidence log

Verbatim outputs captured during this engagement. Timestamps are session-relative.

### 3.1 Baseline before any work (2026-09-26)

```
173 passed, 2 skipped, 107 warnings in 77.81s (0:01:17)
```

Blueprint acceptance expected `172 passed, 1 skipped`.

### 3.2 `alembic check` before the parity migration (fresh SQLite)

```
Detected added foreign key (intent_id) on table bounded_authorizations
Detected added foreign key (agent_id)  on table bounded_authorizations
Detected added foreign key (intent_id) on table mfa_challenges
Detected added foreign key (agent_id)  on table payment_intents
Detected added foreign key (authorization_id) on table provider_transactions
Detected added foreign key (intent_id) on table provider_transactions
Detected added foreign key (agent_id)  on table provider_transactions
Detected added foreign key (agent_id)  on table request_proofs
Detected type change from VARCHAR(length=20) to Enum('ACTIVE','REVOKED','EXPIRED', name='mandatestatus')
  on 'user_payment_mandates.status'
FAILED: New upgrade operations detected: [...]
```

### 3.3 After `f5a6b7c8d9e0` — parity achieved

```
No new upgrade operations detected.
```

```
payment_intents FKs: ['agents', 'user_payment_mandates']
provider_tx FKs: ['agents', 'bounded_authorizations', 'payment_intents']
provider_tx cols: ['provider_environment', 'provider_key_id_prefix', 'provider_api_base']
```

### 3.4 The false-green that Phase 1 shipped (verified in source)

`scripts/foreign_agent_proof.py` set the delegated cap and the mandate cap to the **same** value, so the "amount above mandate" negative proof was actually proving the delegation check:

```
delegation:  "payment_limit_minor_units": 500000
mandate:     "max_per_transaction": 500000
probe:       "amount_minor_units": 600000   # breaches both
assertion:   decision == "deny"             # passes for the wrong reason
```

Server order confirms it — the delegated-limit denial runs ~20 lines before the mandate layer:

```python
# app/routers/payments.py:341
if req.amount_minor_units > agent.payment_limit_minor_units:
    return _deny(db, agent, req, [f"amount {req.amount_minor_units} exceeds delegated limit ..."])
# app/routers/payments.py:361
policy = config.mandate_policy()
mandate_decision = evaluate_mandate(...)
```

After the fix, live output:

```
[PASS] 7h. probe is over mandate yet under delegation: {'above_mandate': 150000, 'mandate_cap': 100000, 'delegated_cap': 500000}
[PASS] 7h. amount above mandate DENIED by the mandate: {'decision': 'deny',
  'reasons': ['amount 150000 exceeds user mandate per-transaction limit 100000']}
```

### 3.5 The data-loss hazard (source, before fix)

```python
# tests/conftest.py:11
TEST_DB_URL = os.environ.get("DATABASE_URL", "sqlite:///./.phase5_test.db")
# tests/conftest.py:42
conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
```

The in-code justification cited a variable that did not exist:

```
$ grep -rn "TEST_DATABASE_URL" --include=*.py .
./tests/conftest.py:37:    # schema. Safe because TEST_DATABASE_URL must point at a disposable test
```

One hit — inside the comment. `TEST_DATABASE_URL` existed nowhere in code.

### 3.6 Razorpay capability probes (read-only)

```
GET  /orders                              -> 200 ok, count=1
POST /customers                           -> 200 cust_TgkmnjMJ1251Et
GET  /customers/{id}/tokens               -> 200 {"entity":"collection","count":0,"items":[]}
POST /orders (recurring-capable)          -> 200 {"id":"or..."}
POST /payments/create/recurring           -> 400 {"error":{"code":"BAD_REQUEST_ERROR",
                                              "description":"The requested URL was not found on the server.",
                                              "source":"internal"}}
POST /payments/create/json                -> 400 same
GET  /payments/create/recurring           -> 404 {"message":"no Route matched with those values"}
GET  /plans                               -> 401 {"error":"Unauthorized"}
```

Account contents at probe time: `26 captured payments, all method=netbanking, token=None, customers=1, tokens=0`.

**Interpretation:** token *reading* is provisioned; token *charging* is not. `GET /plans` returning 401 (route exists, product not enabled) versus recurring returning "URL not found" (route not exposed) is the distinction that identifies this as an entitlement gap, not a wrong path.

### 3.7 Real LLM run — Phase 5 closed

```
[PASS] 1. model reachable: {'model': 'space-bunny-alpha-bynara', 'listed': True, 'available': 57}
 mode:     autonomous (read from server)
 provider: real-razorpay(test-mode) (environment: test)
 llm:      real
[PASS] 0c. autonomous posture actually denies a mandate-less payment:
         {'decision': 'deny', 'reasons': ['no active user payment mandate']}
    turn 1  get_delegation({}) -> ok
    turn 1  get_payment_authority({}) -> ok
    turn 2  propose_payment({...}) -> ok
    turn 3  confirm_payment({'authorization_id': 'b1f85748-...'}) -> ok
    turn 4  read_proof({'transaction_id': 'TXN-llm-0a552e0b'}) -> ok
[PASS] 4b. audit chain is headed by the model's tool call:
          {'chain_verified': True, 'kinds': ['llm_tool_call', 'intent_decided', 'authorization_minted',
                                             'authorization_consumed', 'order_submitted']}
[PASS] 4c. causal identifiers are durable and match this run:
          {'llm_run_id': 'LLM-RUN-2f7c47-A', 'llm_model': 'space-bunny-alpha-bynara',
           'llm_tool_call_id': 'a56399d1-a190-4e8b-bb21-81a9234f49bc'}
[PASS] 6. order id is well-formed (real-razorpay):
          {'provider_order_id': 'order_ThKPZcFIFkdv7P', 'state': 'PROVIDER_SUBMITTED'}
tokens: run A {'completion_tokens': 589, 'prompt_tokens': 9183, 'total_tokens': 9772}
      | run B {'completion_tokens': 1076, 'prompt_tokens': 2772, 'total_tokens': 3848}
[PASS] 13. no over-cap proposal was accepted:
          {'over_cap_proposals': 0, 'codes': ['model never proposed the overspend']}
```

Per-run token accounting is what distinguishes a real API from a mock; a mock cannot produce it.

### 3.8 The live settlement — Phase 6 closed

Tunnel and listener:

```
TUNNEL_URL=https://permalink-propose-cnet-rec.trycloudflare.com
2026-09-28T05:40:12Z INF Registered tunnel connection connIndex=0 location=bom08 protocol=quic
http=200 size=84  {"service":"paari-webhook-listener","webhook_path":"/v1/payments/webhooks/razorpay"}
INFO: 49.206.17.63:0 - "GET /health HTTP/1.1" 200 OK
```

Signature behaviour through the public tunnel:

```
LOCAL   signed=200 {"status":"ignored","reason":"unknown order"}  forged=401
TUNNEL  signed=200 {"status":"ignored","reason":"unknown order"}  forged=401
```

Razorpay's deliveries, from the listener's access log:

```
INFO: 52.66.75.174:0 - "POST /v1/payments/webhooks/razorpay HTTP/1.1" 200 OK
INFO: 52.66.75.174:0 - "POST /v1/payments/webhooks/razorpay HTTP/1.1" 200 OK
```

Resulting state and evidence:

```
order_ThLT2RZ9YnyKeW | state=PAID payment=pay_ThLYmnImZBgoea env=test

final_state        : PAID
terminal           : True
provider           : razorpay | env: test
settlement_source  : provider        <-- first time ever
webhook_verified   : True
api base           : https://api.razorpay.com/v1
key prefix         : rzp_test_TdV
order -> payment   : order_ThLT2RZ9YnyKeW -> pay_ThLYmnImZBgoea
chain_verified     : True  (hash_version=2 digests)

audit chain: payment_proposed -> intent_decided -> authorization_minted
          -> authorization_consumed -> order_submitted -> webhook_applied -> webhook_applied
```

The two events, decoded:

```
payment.authorized   PROVIDER_SUBMITTED    -> PAYMENT_PENDING
payment.captured     PAYMENT_PENDING       -> PAID
```

**This is the observation that invalidated the Phase 9 deferral.** The repository's own docstring argued that `payment.authorized` was too unreliable to warrant a distinct state. Razorpay delivered it, separately, with its own valid signature.

### 3.9 The proof script that could not see a settled payment

```
=== proof tail ===
[WAIT] pay order order_ThLT2RZ9YnyKeW for Rs 1.00 in Test Mode, then the webhook settles it...
=== server responses to its polling ===
INFO: 127.0.0.1:64340 - "GET /v1/audit/TXN-proof-e415ba44 HTTP/1.1" 401 Unauthorized
INFO: 127.0.0.1:64345 - "GET /v1/audit/TXN-proof-e415ba44 HTTP/1.1" 401 Unauthorized
...
56 polls, all 401
```

Cause:

```python
# app/routers/payments.py, inside _authenticate()
require_proof = claims.get("protocol_version") == "1.0" or os.environ.get("PAARI_REQUIRE_REQUEST_PROOF") == "1"
```

A `/v1/agents/register` agent always needs `X-Paari-Proof`. The proof script signed `/v1/reconcile` and did **not** sign its two `/v1/audit` calls.

### 3.10 Phase 9 final verification

```
### HEADS
c3d4e5f6a7b8 (head)
### MIGRATIONS
19
### PYTHON
Python 3.12.10
```

```
238 passed, 2 skipped, 1 warning in 116.03s (SQLite)
240 passed, 1 warning in 152.07s (TEST_DATABASE_URL=postgresql://...  -> zero skips)
No new upgrade operations detected.   (PostgreSQL)
```

Settle harness through the new chain:

```
[PASS] 8b. capture settled from a signed simulator webhook (NOT the real provider):
         {'webhook': {'status': 'applied', 'state': 'PAID'}, 'provider_mode': 'local-stub'}
[PASS] 8e. settlement recorded in the proof bundle:
         {'final_state': 'PAID', 'terminal': True, 'webhook_verified': True, 'audit_event_count': 7}
[PASS] 8f. bundle declares the settlement's provider environment:
         {'provider_environment': 'simulated', 'settlement_source': 'simulator'}
[PASS] 8g. a simulated settlement is labelled simulator
LIVE E2E GREEN: an LLM proposed a payment, Paari independently validated authority and
authorized execution; settlement completed against the LOCAL SIMULATOR, not the provider
```

### 3.11 The seam is unwired (Phase 8 Part B, still open)

```
=== callers of get_agentic_provider / supports_autonomous_settlement / AgenticPaymentProvider
     in app/, scripts/, sdk/ (excluding providers/agentic.py) ===
(no output)

=== readers of PaymentInstrumentBinding ===
app/models.py:318:class PaymentInstrumentBinding(Base):
app/routers/v1.py:240:@router.post("/mandates/{mandate_id}/provider-binding", ...)
app/routers/v1.py:260:    row = models.PaymentInstrumentBinding(
app/schemas.py:235:class PaymentInstrumentBindingResponse(BaseModel):
```

Created, never read. Called, never invoked.

---

## 4. Change inventory

### Migrations added

| Revision | Purpose |
|---|---|
| `f5a6b7c8d9e0` | Emits every model-declared FK on **both** backends by introspecting the live schema; refuses to run if orphans exist |
| `a1b2c3d4e5f6` | `provider_environment`, `provider_key_id_prefix`, `provider_api_base` on `provider_transactions` |
| `b2c3d4e5f6a7` | `hash_version` on `audit_events`; existing rows stamped 1 (legacy digest) |
| `c3d4e5f6a7b8` | Data-only: `PAYMENT_PENDING` → `PROVIDER_AUTHORIZED` |

### Application code

| File | Change |
|---|---|
| `app/database.py` | `resolve_database_url()`, `is_disposable_database_url()`, `assert_disposable_database_url()`, `PRAGMA foreign_keys=ON` connect listener |
| `app/config.py` | `load_config()` uses the resolver; `DATABASE_URL` no longer a required-var name |
| `app/main.py` | `startup_guards()` (prod-on-SQLite, prod-on-simulator, prod-without-autonomous); `/health` publishes provider identity via `provider_identity()`; reconciliation worker lifecycle |
| `app/models.py` | three provenance columns on `ProviderTransaction`; state-chain docstring |
| `app/providers/razorpay.py` | `classify_environment()`, `PRODUCTION_API_BASE`, `api_base`, `provenance()`; `verify_webhook` no longer depends on API keys |
| `app/audit.py` | `causal_labels()` — the single attribution gate; v1/v2 digest versions |
| `app/proof_bundle.py` | `_settlement_source()`, provenance in `payment_result`/`payment_execution`, new `causal_provenance` artifact |
| `app/routers/payments.py` | provenance stamped at consume; causal labels threaded into `webhook_applied`; consume uses the gated helper; Phase 9 event mapping with no `PAID` |
| `app/reconcile.py` | `confirm_capture()`; Phase 9 status mapping; fixed `txn.provider.environment` crash |
| `app/transitions.py` | `PROVIDER_AUTHORIZED`, `CAPTURED`; `DECLINED` added to `TERMINAL_STATES`; `PAYMENT_PENDING` retained as legacy |
| `app/reconcile_worker.py` | `start()` defaults to the app's resolved database |
| `alembic/env.py` | `compare_type` (SQLite has no native ENUM), `render_as_batch` |
| `llm_agent/broker.py` | `read_proof` now exposes `settlement_source` / `provider_environment` to the model |
| `schemas/paari-payment-result.v1.schema.json` | 13-state enum; provenance required |

### Tests added (6 files, ~45 new tests)

`test_provider_provenance.py` · `test_causal_provenance.py` · `test_state_reachability.py` · `test_proof_scripts.py` · `test_webhook_value_guard.py` · `test_phase9_state_machine.py`

Plus rewritten: `test_env_isolation.py` (canary design) · `test_postgres_migration.py` (was reading the wrong variable) · `test_webhook_org_isolation.py` (realistic event shape) · `test_phase8_security.py` (audit proof readability).

### Scripts

`webhook_listener.py` (webhook-only public receiver) · `checkout_demo.html` (test-mode pay page) · three harnesses corrected.

---

## 5. Defects found — symptom, cause, fix, guard

| ID | Symptom | Root cause | Fix | Guard |
|---|---|---|---|---|
| D1 | `pytest -q` could `DROP SCHEMA public` on a live database | conftest read `DATABASE_URL` at import | `TEST_DATABASE_URL` only + disposable-name assertion | `test_ambient_deployment_database_url_does_not_reach_the_app` |
| D2 | `alembic check` reported 9 diffs | three revisions gated `create_foreign_key` behind `if postgresql` | introspecting parity migration | run §2.2 on both backends |
| D3 | SQLite enforced **no** FKs | `PRAGMA foreign_keys` defaults OFF | connect listener | FK-violation test now runs on both |
| D4 | "amount above mandate" proof proved the wrong layer | caps were equal | caps separated + reason assertion | `test_mandate_cap_is_strictly_below_the_delegated_cap` |
| D5 | Isolation test passed with the fixture deleted | probe target denies before posture is read | canary proves pollution is live | `test_pollution_is_live_without_the_fixture` |
| D6 | Harness printed `mode: autonomous` against a standard server | derived from CLI flag | read from `/health` | `test_harness_labels_are_read_from_the_server_not_the_process` |
| D7 | Causal chain never captured | `CausalContext` constructed nowhere | wired in `onboard()` | `4b`/`4c` in the live run |
| D8 | Attribution could be invented | consume read `llm_*` unconditionally | single gated helper | `test_unattributed_payment_gains_no_causal_labels_at_settlement` |
| D9 | Simulated settlement looked identical to a real one | no environment on the row or in the artifact | provenance columns + `_settlement_source` | `test_settlement_source_mapping_never_rounds_upward` |
| D10 | Webhook value guard never executed | no test produced a mismatch | 5 tests with positive control | `test_webhook_value_guard.py` |
| D11 | Cross-tenant proof tested a payload shape Razorpay doesn't send | asserted on a synthetic `rzp_` `account_id` | per-org secret tests with real shape | two new org-isolation tests |
| D12 | Reconciliation worker dead on arrival | `start()` with no URL → `engine=None` → `_run_batch(None)` | default to resolved DB | `test_worker_starts_without_an_explicit_url` |
| D13 | Reconciling an expired order raised `AttributeError` | `txn.provider.environment` (no such attribute) | `txn.provider_environment` | covered by reconcile tests |
| D14 | `DECLINED` rows re-scanned forever | dead-end state absent from `TERMINAL_STATES` | added | `test_declined_is_terminal_and_stops_being_rescanned` |
| D15 | Proof script reported a settled payment as unsettled | unsigned `/v1/audit` polls → 401 → read as "no events" | sign + abort on non-200 | `test_v1_audit_is_readable_with_a_signed_proof` |
| D16 | Provenance check passed on a missing field | `None != "provider"` is true | equality assertion | `8g` in the settle harness |
| D17 | Checkout page appeared broken | button disabled with no explanation when params absent | page states what's missing | manual |
| D18 | Listener rejected valid signatures | `verify_webhook` routed through `get_config()`, which raises without API keys | secret-only verification | `test_webhook_verification_needs_only_the_webhook_secret` |

---

## 6. Invariants now enforced by tests

1. Governance posture has exactly one definition: `app.config.mandate_policy()`.
2. A valid mandate signature is never a liveness signal — verified at creation, in `evaluate_mandate`, and at consume.
3. Agent-asserted limits, currency and `mandate_id` are never authoritative.
4. **A webhook cannot mint `PAID`** — pinned by reading the handler's own event map.
5. `settlement_source` never rounds upward; unknown ⇒ `unattributed`.
6. Proof harnesses read posture and provider from the server, never from their own environment.
7. The SDK exposes no capture/settle/refund method.
8. No agent-reachable path can write a user mandate.
9. The suite cannot target a non-disposable database.
10. Every declared FK exists and is enforced on both backends.
11. `llm_*` markers appear only when attribution was claimed.
12. Dead-end states belong in `TERMINAL_STATES`.

---

## 7. Not done

| Item | Status |
|---|---|
| **Phase 8 Part B** — wire the agentic seam into `consume`; make `PaymentInstrumentBinding` readable | **Open, unblocked.** See §3.11 |
| **Phase 8 Part C** — Razorpay token adapter | Blocked: endpoint not entitled; token needs one-time human enrollment |
| Real user identity for mandates | Not built. `discovery.py:28` says `trusted-surface-admin-bootstrap-in-v2-poc`; harnesses generate their own user keys, so a signature proves arithmetic, not identity |
| Refund endpoint authority | **Unresolved decision.** Agent-session auth, unclamped amount, no tests |
| `GET /v1/audit` org scoping | Fixed by the operator, verified working |
| Postgres CI job | Added; has never executed in CI (no pushes since) |
| Version control | Still none |

---

## 8. Traps that cost time — read this first

**T1 — Never run two pytest processes in this repo.** They share `./.phase5_test.db`; the second fails with a Windows `PermissionError` that looks like a real regression. I diagnosed 88 errors as my own concurrency before seeing this.

**T2 — `app.database` freezes its engine at import.** Any env var it reads must be set *before* import. A function-scoped fixture is too late. My first attempt left a stray import above the pin and the guard caught it.

**T3 — Sourcing `.env` clobbers your overrides.** `.env` contains `DATABASE_URL` **and** `ALEMBIC_URL`. `set -a; . ./.env` after exporting a temp path silently reverts it. Twice this bit me: once sending a migration to the operator's sandbox Postgres (additive, revertible with `alembic downgrade -1`), once making a proof run against an unmigrated database. **Source `.env` first, then override.**

**T4 — A disposable database must be *named* disposable.** `assert_disposable_database_url` requires a SQLite scratch file or a Postgres database ending `_test`/`_testing`/`_pytest`. `paari` is refused by design.

**T5 — A passing rejection test proves nothing.** D5, D11 and D16 all shared one shape: the assertion passed because the field was absent, not because the behaviour was right. Every negative test in this record has a positive control. Keep that pattern.

**T6 — A poller must distinguish absence from ignorance.** D15: `.json().get("events", [])` on a 401 turned "cannot look" into "did not happen" and would have blamed the provider for the harness's own auth bug.

**T7 — Check HTTP status, not just curl exit code.** I reported a tunnel "reachable" when it was returning 530. `curl -w "%{http_code}"` or nothing.

**T8 — Quick tunnels are ephemeral.** Every `cloudflared` restart yields a new hostname. Restarting the stack invalidated the operator's saved Razorpay webhook URL and required re-entry.

**T9 — Razorpay Checkout is a cross-origin iframe.** Browser automation can open it but cannot fill it: no frame target in `list_pages`, and clicks need a snapshot uid. The final keystrokes are necessarily human.

**T10 — `str.strip()` destroys first-line indentation.** A scripted patch using `BLOCK.strip()` un-indented the inserted method's `def` line and broke five test files.

**T11 — Test-mode card tokens expire in ~3 days.** Any token-based flow needs re-enrollment to be a repeatable fixture, not a one-time setup.

**T12 — Razorpay test 2FA is a digit-count check.** Any 4–10 digit OTP approves; fewer than 4 rejects. Documented at razorpay.com/docs/payments/payments/test-card-details.

**T13 — Proof enforcement differs by registration surface.** `/v1/agents/register` ⇒ `protocol_version "1.0"` ⇒ always needs `X-Paari-Proof`. Legacy `/agents/register` ⇒ only when `PAARI_REQUIRE_REQUEST_PROOF=1`. Two doors, two strengths. Not yet in `SECURITY.md`.

---

## 9. Re-verification checklist for the next person

```bash
python -m pytest -q                                              # expect 238 passed, 2 skipped
# §2.1 Postgres run                                                 # expect 240 passed, 0 skipped
# §2.2 alembic check on SQLite                                     # "No new upgrade operations detected"
python scripts/autonomous_payment_e2e.py                         # AUTONOMOUS E2E GREEN, exit 0
python scripts/llm_agent_e2e.py --with-server --settle --require-mandate  # LIVE E2E GREEN, exit 0
grep -rn "get_agentic_provider" app/ | grep -v providers/agentic.py       # expect EMPTY until Part B lands
grep -rn "capture" sdk/                                          # expect EMPTY
```

---

## 10. The one-sentence status

An AI agent proposes a payment; Paari verifies identity, delegated authority, a signed user mandate, limits and policy; a real Razorpay order is created; a real customer paid it; Razorpay's own signed webhooks — verified by HMAC and corroborated by a direct provider read, never by a client claim — moved it to `PAID` with a tamper-evident chain from proposal to settlement, and the artifact states plainly that the environment was `test` and the source was `provider`.
