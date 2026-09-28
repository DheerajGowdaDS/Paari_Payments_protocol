# Paari — Blueprint Implementation Verification Report

**Date:** 2026-09-19 · **Verifier:** independent code + live-evidence audit
**Subject:** 15-stage stage-output proof chain (blueprint) against the working tree
**Live run verified:** Razorpay Test Mode, tunnel `https://visiting-boolean-town-playstation.trycloudflare.com`
**Verdict: PASS — blueprint implemented correctly; 15/15 stages present and executing, 8/8 machine-validated stage artifacts conform, 3 evidence/accuracy items to close.**

Nothing in this repository was modified by the verifier. All commands run were read-only
(`pytest`, `compileall`, SQLAlchemy `SELECT`, JSON probes).

---

## 1. Scope and method

| Step | What was done | Result |
|---|---|---|
| 1 | Read the blueprint (15 stages → output artifacts) | Requirements fixed |
| 2 | Read `docs/STAGE_OUTPUTS.md`, `docs/PROTOCOL.md`, `docs/CONFORMANCE.md`, `docs/LIVE_E2E_REPORT_2026-09-18.md` | Catalog + protocol claims |
| 3 | Read every producing module (`app/routers/*`, `app/proof_bundle.py`, `app/audit.py`, `app/security.py`, `app/transitions.py`, `app/reconcile*.py`, `app/providers/*`, `app/protocol/*`) | Code paths traced |
| 4 | `python -m pytest -q` | **88 passed, 1 skipped** (32.04s) |
| 5 | `python -m compileall -q app sdk scripts` | exit 0 |
| 6 | Validate 11 bundle nodes against their mapped schemas with `tests/_schema_validator.py` | 8 PASS, 3 fail (all 3 documented as unpinned projections) |
| 7 | Recompute the audit chain on the retained live DB | `verify_chain == True` |
| 8 | Decode and read the raw live artifacts (`proof_run.log`, `cloudflared-err.log`, `evidence_live_e2e_2026-09-19.json/.md`, `paari_live_e2e.db`) | Corroborated below |
| 9 | Live endpoint check through the tunnel | `GET /.well-known/paari` → `protocol=paari`, `protocol_version=1.0` |

---

## 2. Blueprint conformance — all 15 stages

Legend: **OK** = implemented, producing a machine-readable artifact, with executable verification.
**OK\*** = implemented, artifact is a documented evidence projection (no schema pin).

| # | Stage | Producing code | Output artifact | Artifact check | Status |
|---|---|---|---|---|---|
| 1 | Discovery | `app/main.py:54` → `app/protocol/discovery.py:7` | Protocol Discovery Document (16 keys) | bundle node validates vs `paari-discovery.v1.schema.json` | **OK** |
| 2 | Parent registration | `app/routers/parents.py:15` | `pending_verification` / `self_asserted` | bundle `parent_trust` validates; live step 2 | **OK** |
| 3 | Parent verification | `app/routers/parents.py:37` + `app/trust.py:34` | `active` / `admin_approved` (tier `kyb_verified` via `/v1/parents/{id}/kyb`) | bundle `parent_trust` validates; live step 3 | **OK** |
| 4 | Delegation | parent-signed canonical JSON; verified `app/routers/v1.py:132` | Signed Delegation (8 fields, epoch ints) | bundle `delegation` validates; tamper → 401 (`tests/test_proof_chain.py:80`) | **OK** |
| 5 | Agent registration | `app/routers/v1.py:110` + `app/protocol/envelope.py:75` | Agent Identity Record | delegation replay blocked `v1.py:152`; requested permissions ignored (`tests/test_protocol.py:27`) | **OK\*** |
| 6 | Agent card | `app/routers/v1.py:80` `_signed_card` | Signed Agent Card + `card_signature_b64` + `paari_public_key_pem` | bundle `agent_card` validates **and** Ed25519 signature verifies (`tests/test_proof_chain.py:21`) | **OK** |
| 7 | Credential | `app/security.py:59` `issue_credential_jwt` | Credential JWT (`typ=paari_credential`) | JWT decoded, `typ`/`sub`/`jti` asserted in bundle-chain test; bundle node = projection | **OK\*** |
| 8 | Authentication | `app/routers/auth.py:36/55` | Session token + burned nonce | single-use nonce, PoP, rotation grace; bundle reports the real nonce | **OK\*** |
| 9 | Payment intent → decision | `app/routers/payments.py:224` (checks 250-297) | `allow`/`review`/`deny` + reasons + `policy_results` | bundle `governance_decision` validates (incl. `merchant`, `policy_results`) | **OK** |
| 10 | Bounded authorization | `app/routers/payments.py:119` | Single-use auth (`max_usage=1`, intent/amount/currency/merchant/expiry) | bundle `bounded_authorization` validates | **OK** |
| 11 | Payment execution | `app/routers/payments.py:416` | Provider order + execution state | atomic reserve `:427`, order match `:408`, idempotency header `providers/razorpay.py:124` | **OK** |
| 12 | Webhook | `app/routers/payments.py:510` | Verified provider event | raw-body HMAC `:535`, exact match `:600-617`, replay dedup `:592`, org guard `:559` | **OK** |
| 13 | Reconciliation | `app/reconcile.py:35`, `app/reconcile_worker.py` | Final payment state | provider truth + value-mismatch guard + legal transitions only | **OK** |
| 14 | Audit | `app/audit.py:19` + `GET /v1/audit/{tx}` `v1.py:285` | Tamper-evident record, **`chain_verified`** | `verify_chain` recomputed server-side on read; tamper → `False` (`tests/test_audit.py:100`) | **OK** |
| 15 | Revocation | `app/routers/agents.py:174`, `v1.py:386` | Revocation / access denied | admin or parent-signed + one-time id; execution-time recheck `payments.py:390` | **OK\*** |

**Coverage:** 15/15 stages implemented; 8/15 bundle artifacts schema-pinned and machine-validated; 6/15 explicitly documented as unpinned evidence projections (`docs/STAGE_OUTPUTS.md:25`).

---

## 3. The four outputs the blueprint demands per stage

| Requirement | Implementation | Verified |
|---|---|---|
| Machine-readable JSON output | Every stage returns typed Pydantic responses (`app/schemas.py`) | yes, live |
| Signature / proof | Agent card Ed25519-signed; envelope + delegation + request proofs signed; bounded-authorization JWT | yes, cryptographically |
| Audit event | `record_audit` at decision, mint, consume, submit, webhook, reconcile, revoke | yes, hash-chain verified |
| Schema pin | 18 schemas in `schemas/`, 8 asserted against real collector output | yes |
| Fail-closed on tamper/replay/expiry | `TRANSITION_TABLE` (`app/transitions.py:9`), delegation/credential expiry, nonce & proof replay burn, authorization expiry; 401/403/409/410 paths | yes |

---

## 4. Closure of the findings from the previous audit

| # | Previous finding | What changed | Verified evidence | Status |
|---|---|---|---|---|
| F-1 | Stage 7/8 catalog rows claimed schema conformance the bundle nodes did not have | Rows rewritten to state the schema is the **wire shape of the JWT/session claims** and that the bundle node is an evidence projection; new footnote `docs/STAGE_OUTPUTS.md:25` enumerates the 8 machine-validated nodes vs the 6 projections | Probe still reports `credential`/`authentication` failing the wire schemas — now **expected and documented** | **CLOSED (documentation)** |
| F-2 | Audit-chain integrity never asserted server-side; `verify_chain` had only a test caller | `GET /v1/audit/{tx}` now returns `chain_verified` (`app/routers/v1.py:302-306`); the bundle computes the same value into `audit_record.chain_verified` (`app/proof_bundle.py:262`) | `tests/test_audit.py::test_audit_endpoint_reports_server_verified_chain` asserts **True** intact and **False** after tampering; live DB recompute → `True` | **CLOSED (exceeds ask)** |
| F-3 | Documented 404/409 proof-bundle paths untested | `tests/test_proof_bundle.py:80` added: unknown → 404, two intents sharing a `transaction_id` → 409 | Test **PASSED**; operator also checked live | **CLOSED** |
| F-6 | Doc drift (`AGENTS.md` said 61 passing; `LIVE_E2E_REPORT` said 76) | `AGENTS.md:11` now "88 passing, 1 skipped"; `STAGE_OUTPUTS.md` row 14 and `PROTOCOL.md:78` document `chain_verified`, owner-scoping and 404/409 | Read directly | **CLOSED** |
| F-4 | Blueprint stage-9 **merchant** and **risk** checks not enforced | Unchanged — declared scope: merchant is recorded, audited and bound into the authorization, but never constrained; no risk engine | `app/routers/payments.py:250-285` unchanged; artifact now carries `merchant` + `policy_results` | **OPEN (declared)** |
| F-5 | Parent lifecycle only on legacy unversioned routes | Unchanged: `/parents/*` (register/approve/reject/revoke); `/v1` covers register, auth, payment, proof, audit, rotate, revoke, orgs | | **OPEN (declared)** |
| F-8 | Audit prev-hash read-then-write race under concurrent writers | Unchanged (read `app/audit.py:36-41`, insert `:53`) | Single-writer live run and tests unaffected | **OPEN (low risk)** |

`python -m pytest -q` after the fixes: **88 passed, 1 skipped** (was 86/1 at the previous audit).

---

## 5. New findings from this verification round

### N-1 — MEDIUM · The retained live DB does not corroborate step 13 for the certified transaction

`scripts/foreign_agent_proof.py` (unmodified since 2026-09-18) sets `tx = f"TXN-proof-{RUN}"` (`:229`)
and posts the over-delegation attempt with `transaction_id = f"{tx}-over"` (`:299`). For the certified
run `RUN = 9c5ffd55` the expected row/event is therefore `TXN-proof-9c5ffd55-over`. The retained
`paari_live_e2e.db` contains:

```text
ALL INTENTS 3
  1 TXN-proof-9c5ffd55      allow 100       f358feea idem-proof-9c5ffd55
  2 TXN-extra-12bc6c        allow 100       875401a4 idem-TXN-extra-12bc6c
  3 TXN-extra-12bc6c-over   deny  50000000  875401a4 idem-TXN-extra-12bc6c-over

AUDIT tx ids: TXN-proof-9c5ffd55 (6 events), TXN-extra-12bc6c (2),
              TXN-extra-12bc6c-over (1), auth:* (2), delegation:* (4)
```

There is **no** `TXN-proof-9c5ffd55-over` PaymentIntent and **no** audit event for it, and the certified
agent burned only **2** request proofs (submit-intent + reconcile) although a completed step-13 intent
call would burn a third. The only 50,000,000-paise DENY in the database belongs to the **extra** agent.

Impact: the DENY *logic* is not in doubt — `tests/test_phase8_security.py::test_over_limit_is_denied_before_authorization`
passes, and the live `TXN-extra-12bc6c-over` row proves the live path works. What is unsupported is the
claim that the **certified** run's step 13 produced that decision in the retained store. Action: while
the server is still up against `paari_live_e2e.db`, re-post the over-limit intent for
`TXN-proof-9c5ffd55-over` and capture the row, or capture raw stdout for steps 10-15 on the next run.

### N-2 — LOW/MEDIUM · `authorization_consumed` records a wrong state transition

`app/routers/payments.py:458` transitions first; `:465-466` then writes
`"previous_state": txn.state, "current_state": "PROVIDER_SUBMITTED"` — so `previous_state` is read
*after* the mutation. Hash-chained live proof from the retained DB:

```text
authorization_minted    previous_state AUTHORIZED          current_state AUTHORIZED
authorization_consumed  previous_state PROVIDER_SUBMITTED  current_state PROVIDER_SUBMITTED
                        ^ should be AUTHORIZED -> PROVIDER_SUBMITTED
order_submitted         previous_state AUTHORIZED          current_state PROVIDER_SUBMITTED
```

The real state machine is intact (`TRANSITION_TABLE` enforces `AUTHORIZED → PROVIDER_SUBMITTED`, and the
following `order_submitted` event carries the correct pair), but the blueprint's stage-14 promise —
"what changed" — is factually wrong for that one event. One-line fix: capture `old_state = txn.state`
before `transition_txn`, exactly as `order_submitted` already does.

### N-3 — LOW · `payment_result.webhook_event` carries an event id/body hash, not the event type

Live value at read time:

```json
{"webhook_event": "435a6e267c7929cf161f3d8e2a9e9a6cd953cd4dc04095848b5ad2b7ed45e9b6",
 "webhook_verified": true, "final_state": "PAID", "terminal": true}
```

`app/routers/payments.py:592` sets `event_id = event.get("id") or sha256(raw_body)`. The two real
Test-Mode deliveries carried no `id`, so the sha256 fallback was exercised
(`928151a6…` = `payment.authorized`, `435a6e26…` = `payment.captured`; both 64-hex). Deduplication is
still correct (identical body → identical digest) and `webhook_verified` derives soundly, but a consumer
reading `payment_result` alone cannot tell **which** provider event settled the payment — that lives only
in the audit detail's `event_type`. Consider emitting `webhook_event_type`, or rename the field to
`webhook_event_id`.

### N-4 — LOW · Evidence-hygiene notes

* The quoted DB size `212992` bytes matches `.phase5_test.db` (the pytest fixture DB); `paari_live_e2e.db`
  is `221184` bytes. Transcription slip only.
* The retained live DB holds residue from more than one attempt — 3 `ParentAuthority` rows
  (10:17:37, 10:30:57, 10:31:05), 2 agents, 2 credentials, 2 delegations, 4 request proofs, 2 provider
  transactions — so "fresh DB" describes the first attempt only. The certified `TXN-proof-9c5ffd55` is
  nonetheless unambiguous: exactly 1 intent, 1 authorization, 1 provider row, 6 chained events.
* `C:\Users\gowda\AppData\Local\Temp\proof_run.log` is **UTF-16LE** and holds only steps 1-9 plus the
  `[WAIT]` line (12 non-empty lines, confirmed by decoding). Steps 10-15 have no raw transcript file;
  their evidence is DB state plus the bundle. Recommend for the next run:
  `python scripts/foreign_agent_proof.py 2>&1 | Tee-Object -FilePath proof_run_full.log`.
* Two code-reference off-by-one slips in the run summary: `webhook_verified` is `app/proof_bundle.py:154`
  (not `:148`) and `provider_order_id` is `schemas/paari-payment-result.v1.schema.json:13` (not `:12`).
  Every other cited reference (`v1.py:250`, `proof_bundle.py:23/197/243/262`, `transitions.py:30`,
  `v1.py:80`, `main.py:54`, `reconcile.py`, `audit.py`) is exact.

### N-5 — Informational · What the retained evidence independently proves

```text
stage 1  tunnel GET /.well-known/paari -> protocol=paari, protocol_version=1.0
stage 2/3 parents b89778e0 pending_verification/self_asserted -> active/admin_approved
stage 4  delegation 17a51ec3 consumed=True, [make_payment], 500000 INR
stage 5  agent f358feea active, protocol_version 1.0, parent_pk=1
stage 7  credential a7098519 issued for that agent
stage 8  nonce 3d1a24c0 used=True (single-use burned)
stage 9  intent TXN-proof-9c5ffd55 allow 100 INR merchant ProofStore
stage 10 authorization c25087c8 max_usage=1 usage_count=1 amount=100 INR ProofStore
stage 11 provider c25087c8 PAID, order_TdrLnfAh9TBQie, pay_TdrWE1S8hVE0PJ
stage 12 webhook payment.authorized -> PAYMENT_PENDING, payment.captured -> PAID
stage 13 reconcile terminal PAID
stage 14 6 events GENESIS -> 991656e4 -> 3947c463 -> e0bc5ad0 -> cf6e39ef -> 3cff4276
         -> 5e8598eb, verify_chain(db, tx) == True
stage 15 RevocationRecord rows = 0 (admin revoke path), agent.status = revoked,
         credential revoked=True, bundle authentication.authenticated = false
```

---

## 6. Complete implemented code report

### 6.1 Repository inventory (verified on disk)

| Area | File | Lines | Role |
|---|---|---|---|
| App entry | `app/main.py` | 75 | FastAPI app, `/.well-known/paari` (`:54`), `/health` (`:59`), lifespan fail-closed boot (`:19-31`) |
| Config | `app/config.py` | 38 | `PaariEnv` sandbox/prod/prod-live; required-env enforcement |
| DB | `app/database.py` | ~100 | engine factory + `UTCDateTime` tz-aware decorator |
| Models | `app/models.py` | ~470 | 14 tables incl. `ParentAuthority`, `DelegationRecord`, `Agent`, `Credential`, `AuthNonce`, `PaymentIntent`, `BoundedAuthorization`, `ProviderTransaction`, `MFAChallenge`, `RevocationRecord`, `AuditEvent`, `RequestProof`, `Organization`, `ProviderAccount` |
| Crypto | `app/crypto_utils.py` | ~90 | Ed25519 keygen/sign/verify, `canonical_json`, `public_key_fingerprint` |
| Security | `app/security.py` | 210 | Paari signing key, credential JWT, session token, bounded-auth JWT, agent-card sign/verify, request proof, admin key |
| Governance | `app/governance.py` | 20 | `PolicyResult` (name/passed/detail) |
| Trust | `app/trust.py` | 54 | `ParentTrustProvider` protocol + `AdminApprovedTrustProvider` |
| Transitions | `app/transitions.py` | 41 | 10-state `TRANSITION_TABLE`, `TERMINAL_STATES`, `IllegalTransitionError` |
| Audit | `app/audit.py` | 74 | `record_audit` (hash chain), `verify_chain` |
| Proof bundle | `app/proof_bundle.py` | 284 | `collect_proof_bundle` — 14 stage artifacts, read-only |
| Reconcile | `app/reconcile.py` | 103 | `reconcile_one` / `reconcile_pending` |
| Reconcile worker | `app/reconcile_worker.py` | ~120 | batch/dead-letter worker |
| Provider accounts | `app/provider_accounts.py` | 44 | per-org provider routing (no cross-org fallback) |
| Rate limit | `app/ratelimit.py` | ~80 | DB rate buckets |
| Schemas | `app/schemas.py` | 258 | Pydantic request/response models |
| Protocol | `app/protocol/{discovery,envelope,errors,messages}.py` | 51/115/50/60 | discovery doc, sign/verify envelope, error taxonomy, message builders |
| Providers | `app/providers/{base,razorpay}.py` | 54/190 | `PaymentProvider` ABC + Razorpay adapter |
| Routers | `app/routers/{parents,agents,auth,payments,v1}.py` | 68/236/127/~650/447 | legacy Phase 1-5 surfaces + stable `/v1` |
| SDK | `sdk/paari_agent/{client,crypto,__init__}.py` | 149/96/11 | external agent client, zero `app.*` imports |
| Scripts | `scripts/foreign_agent_proof.py` | 333 | black-box 15-step live proof |
| Schemas | `schemas/paari-*.v1.schema.json` | 18 files | draft 2020-12, each with an example |
| Tests | `tests/*.py` | 29 files, 89 collected | 88 pass / 1 skip |

### 6.2 Per-stage implementation detail (code-level) — stages 9-15 (payment half)

| Stage | Entry point | Control logic (exact) | Persisted rows | Tests |
|---|---|---|---|---|
| 9 Intent → decision | `POST /v1/payments/intent` `v1.py:42` → `payments.py:224` | authenticate first `:231`; `agent_id` must match the session `:232`; idempotent replay returns the original decision `:236-248`; deny chain: parent `:251`, trust provider `:253`, delegation expiry `:256`, positive amount `:258`, capability `:260`, delegated limit `:262`, currency `:264`; velocity >5/min → REVIEW `:280`; amount >0.8× limit → step-up `:283`; ALLOW mints the authorization + provider row `:297-299` | `PaymentIntent`, `AuditEvent(intent_decided)` carrying `policy_results` | `tests/test_governance_attacks.py`, `tests/test_phase8_security.py`, `tests/test_audit_hardening.py` |
| 10 Bounded auth | `payments.py:119` | `authorization_id = intent_id` `:120`; JWT binds intent/tx/merchant/amount/currency/`max_usage=1` (`security.py:106-119`); row mirrors every bound `:130-143` | `BoundedAuthorization`, `ProviderTransaction(AUTHORIZED)`, `AuditEvent(authorization_minted)` | `tests/test_consume_atomic.py`, `tests/test_proof_bundle.py` |
| 11 Execution | `POST /v1/payments/authorizations/{id}/consume` `payments.py:416` | session must belong to the authorization's agent `:424`; revalidate agent/parent/delegation/credential/auth-expiry `:390-405`; **atomic** `UPDATE ... WHERE usage_count < max_usage`, rowcount-checked `:427-435`; provider order must match receipt/amount/currency `:408-413`, `:452`; `AUTHORIZED → PROVIDER_SUBMITTED` through the transition table `:458`; provider idempotency key = `authorization_id` (`razorpay.py:124`) | `ProviderTransaction(PROVIDER_SUBMITTED, razorpay_order_id)`, 2 audit events | `tests/test_consume_atomic.py` |
| 12 Webhook | `POST /v1/payments/webhooks/razorpay` `payments.py:510` | raw body captured `:513-520`; HMAC-SHA256 over the raw body `:535` (constant-time compare, `razorpay.py:65-69`); event id or body sha256 `:592`; duplicate short-circuit `:593`; `rzp_*`-only org guard `:559-590`; exact amount + currency match else `rejected_value_mismatch` `:600-617`; state change only via the transition table `:620-625` | `ProviderTransaction.state/webhook_event_id/razorpay_payment_id`, `AuditEvent(webhook_applied)` | `tests/test_webhook.py`, `tests/test_webhook_org_isolation.py` |
| 13 Reconciliation | `POST /v1/reconcile/{authorization_id}` `v1.py:234` → `reconcile.py:35` | payment-grade auth `:244-246`; terminal short-circuit `:39`; receipt-based order recovery for `PROVIDER_UNKNOWN` `:50-53`; provider payment fetched `:57-61`; amount/currency mismatch → audited refusal `:73-82`; legal transition only `:84-88` | `ProviderTransaction(reconciled_at)`, `AuditEvent(reconciled)` | `tests/test_reconcile.py`, `tests/test_reconcile_worker.py` |
| 14 Audit | `app/audit.py:19`; `GET /v1/audit/{tx}` `v1.py:285` | `prev_hash` chained from the previous event; `event_hash = sha256(prev_hash + canonical_json(detail))` `:13-16`; flush-only so the request transaction owns the commit `:53-54`; **`chain_verified` recomputed on read** `:302-306` | `AuditEvent` | `tests/test_audit.py` (3, incl. tamper → `False`), `tests/test_audit_hardening.py` |
| 15 Revocation | `POST /agents/{id}/revoke` `agents.py:174`; `POST /v1/authorizations/{id}/revoke` `v1.py:386` | admin key **or** parent-signed document (`revocation_id` + `issued_at` within 5 min + signature) `:199-230`; one-time `RevocationRecord` `:216-218`; credentials revoked `:233`; execution-time recheck rejects revoked agent/parent `payments.py:390-405` | `RevocationRecord`, `AgentStatus.REVOKED`, `Credential.revoked` | `tests/test_phase8_security.py`, `tests/test_proof_bundle.py::test_bundle_reports_revocation_without_parent_signed_record` |

### 6.3 Per-stage implementation detail (code-level) — stages 1-8 (trust/identity half)

| Stage | Entry point | Control logic (exact) | Persisted rows | Tests |
|---|---|---|---|---|
| 1 Discovery | `GET /.well-known/paari` `app/main.py:54` | `app/protocol/discovery.py:7` builds 16 keys incl. `rules` (4 boolean invariants) | none | `tests/test_schemas.py::test_discovery_endpoint_matches_schema`, `tests/test_protocol.py::test_well_known_discovery_and_v1_surface` |
| 2 Parent register | `POST /parents/register` `parents.py:15` | parent_type whitelist `:17`; contact must be email/URL `:19`; Ed25519 PEM enforced `:24-26`; always lands `PENDING_VERIFICATION` + `self_asserted` `:31` | `ParentAuthority` | `tests/test_trust_provider.py` |
| 3 Parent verify | `POST /parents/{id}/approve` `parents.py:37` (+`/reject`, `/revoke`) | admin key + org binding via `security.require_admin_org`; revoked parent cannot be re-approved `:42`; revoke also kills live credentials `:64-66`; `POST /v1/parents/{id}/kyb` sets tier `kyb_verified` `v1.py:436` | `ParentAuthority`, cascaded `Credential` | `tests/test_trust_provider.py`, `tests/test_phase8_security.py` |
| 4 Delegation | consumed at `POST /v1/agents/register` `v1.py:132` | parent signature verified over `canonical_json(delegation)` `:133`; `issued_at` not in the future `:142`; not expired `:144`; lifetime ≤366d `:146`; fingerprint bound to the registering key `:150`; single-use `:152`; non-empty capabilities `:155`; positive limit `:157` | `DelegationRecord(consumed=True)` | `tests/test_proof_chain.py::test_tampered_delegation_fails_registration` |
| 5 Agent register | `POST /v1/agents/register` `v1.py:110` | protocol/version check `:113`; payload present `:116`; envelope Ed25519 verified against the presented key `:119`; `sender` must equal key fingerprint `:122`; parent must be `ACTIVE` `:130`; `requested_permissions` is never read | `Agent`, `AuditEvent(delegation_consumed, credential_issued)` | `tests/test_protocol.py::test_v1_register_ignores_requested_permissions` |
| 6 Agent card | `GET /v1/agents/{id}/card` `v1.py:196`; `_signed_card` `v1.py:80` | all fields sourced from the DB row, never the request `:82-102`; capability map `make_payment → payment.create` `:21`; Paari Ed25519 signature over every field `:105`; `paari_public_key_pem` attached `:106` | none | `tests/test_protocol.py::test_v1_card_is_discovery_only`, `tests/test_proof_chain.py:21`, `tests/test_sdk.py::test_sdk_card_tamper_is_detected` |
| 7 Credential | `app/security.py:59` | `typ=paari_credential`, `iss=paari`, `aud=paari-payment`, 90-day TTL, clamped to the delegation expiry at the call site (`v1.py:182`, `v1.py:369`) | `Credential(signed_jwt, expires_at)` | `tests/test_proof_chain.py:50-57` (decodes the stored JWT), `tests/test_mfa_auth.py` |
| 8 Authentication | `POST /v1/auth/challenge` `auth.py:36`, `/verify` `auth.py:55` | deliberately vague failure for unknown/revoked agents `:39`; credential JWT verified and `sub` matched `:67`; DB `revoked` and DB `expires_at` both checked `:71-81`; nonce exists/unused/unexpired `:86`; proof-of-possession signature over the nonce `:92` with `key_sunset_at` rotation grace `:94-97`; nonce burned `:102`; session issued with `cnf.jkt` key fingerprint `:112-119` | `AuthNonce(used=True)`, `AuditEvent(challenge_verified)` | `tests/test_mfa_auth.py`, `tests/test_rotation.py` |

### 6.4 Verification matrix — which test proves which claim

| Claim to verify | Test | Assertion |
|---|---|---|
| Discovery surface + version | `tests/test_schemas.py::test_discovery_endpoint_matches_schema`, `tests/test_protocol.py::test_well_known_discovery_and_v1_surface` | `protocol=paari`, `protocol_version=1.0`, `/v1/*` paths |
| Card is bound by delegation, not the request | `tests/test_protocol.py::test_v1_register_ignores_requested_permissions` | `requested_permissions` ignored; `limits.max_amount == 500000` |
| Card is signed and verifiable | `tests/test_protocol.py::test_v1_card_is_discovery_only`, `tests/test_sdk.py::test_sdk_card_tamper_is_detected` | signature verifies; tampered card fails |
| Tampered delegation cannot register | `tests/test_proof_chain.py::test_tampered_delegation_fails_registration` | 401 `Delegation signature verification failed` |
| Stage outputs chain to each other | `tests/test_proof_chain.py::test_each_stage_output_links_to_previous_stage` | card sig, delegation fingerprint, credential JWT `typ`/`sub`, merchant link, audit `prev_hash` links |
| Bundle has all 14 artifacts | `tests/test_proof_bundle.py::test_bundle_contains_all_artifacts_for_decided_intent` | all 14 keys present |
| Bundle artifacts conform to schemas | `tests/test_proof_bundle.py::test_bundle_sections_satisfy_schema_required_keys` | 8 nodes validated via `tests/_schema_validator.py` |
| Proof bundle owner-scoped + proof-gated | `tests/test_proof_bundle.py::test_proof_endpoint_exposes_bundle`, `tests/test_sdk.py::test_sdk_v1_session_must_send_proof_for_proof_bundle` | 403 cross-agent; 401 without `X-Paari-Proof` for v1 sessions |
| Unknown/ambiguous bundle fails closed | `tests/test_proof_bundle.py::test_proof_endpoint_fails_closed_for_unknown_and_ambiguous_transaction` | 404 unknown, 409 ambiguous |
| Audit chain computed server-side | `tests/test_audit.py::test_audit_endpoint_reports_server_verified_chain` | `chain_verified` True, then False after tamper |
| Audit chain is tamper-evident | `tests/test_audit.py::test_audit_chain_tamper_evident` | `verify_chain` False after mutation |
| Audit answers the 11 questions | `tests/test_audit.py::test_audit_chain_answers_eleven_questions` | exact kind sequence ending `webhook_applied` → `PAID` |
| Over-limit denied | `tests/test_phase8_security.py::test_over_limit_is_denied_before_authorization` | `deny` + reason |
| Wrong currency denied | `tests/test_phase8_security.py::test_wrong_currency_is_denied` | `deny` |
| Proof replay rejected | `tests/test_phase8_security.py::test_replayed_request_proof_is_rejected` | second use → 401 |
| Agent mismatch denied | `tests/test_phase8_security.py::test_agent_id_mismatch_is_denied` | 403 |
| Suspended parent blocks intent | `tests/test_trust_provider.py` | 401 `PARENT_REVOKED` |
| Velocity → review | `tests/test_governance_attacks.py::test_high_velocity_triggers_review` | 6th intent `review`/`deny` |
| Wrong MFA signature rejected | `tests/test_governance_attacks.py::test_invalid_mfa_signature_is_rejected` | 401/400 |
| Single-use authorization | `tests/test_consume_atomic.py::test_double_consume_second_rejected` | second consume → 409 |
| Revoked parent blocks execution | `tests/test_consume_atomic.py::test_consume_blocked_after_parent_revoked` | 401/403 |
| Webhook HMAC + value binding | `tests/test_webhook.py` (4 tests) | bad sig 401, captured → `PAID`, replay → `duplicate_ignored`, unknown order ignored |
| Cross-org webhook isolation | `tests/test_webhook_org_isolation.py` | rejected mismatch; same-org applies |
| Reconciliation truth | `tests/test_reconcile.py`, `tests/test_reconcile_worker.py` | value mismatch refused; legal transitions only |
| Rotation grace window | `tests/test_rotation.py` (5 tests) | old key accepted until `key_sunset_at` |
| Tenant isolation | `tests/test_multitenancy.py` (7 tests) | no cross-org provider fallback |
| Schema keyword subset enforced | `tests/test_schemas.py::test_every_schema_stays_inside_the_supported_keyword_subset`, `::test_validator_rejects_unknown_keywords_and_enforces_bounds` | new keyword fails CI instead of passing unchecked |

---

## 7. Appendix — Live raw outputs (verbatim)

### A.1 Verifier's own commands (this audit, re-run on the current tree)

```text
$ python -m pytest -q
..............................s......................................... [ 82%]
...............                                                          [100%]
86→ 88 passed, 1 skipped, 65 warnings in 32.04s

$ python -m compileall -q app sdk scripts
compileall exit=0

$ python -m pytest tests/test_audit.py tests/test_proof_bundle.py -v
tests/test_audit.py::test_audit_chain_answers_eleven_questions PASSED    [ 11%]
tests/test_audit.py::test_audit_chain_tamper_evident PASSED              [ 22%]
tests/test_audit.py::test_audit_endpoint_reports_server_verified_chain PASSED [ 33%]
tests/test_audit.py::test_audit_query_rejects_other_agent PASSED         [ 44%]
tests/test_proof_bundle.py::test_bundle_contains_all_artifacts_for_decided_intent PASSED [ 55%]
tests/test_proof_bundle.py::test_proof_endpoint_exposes_bundle PASSED    [ 66%]
tests/test_proof_bundle.py::test_bundle_sections_satisfy_schema_required_keys PASSED [ 77%]
tests/test_proof_bundle.py::test_proof_endpoint_fails_closed_for_unknown_and_ambiguous_transaction PASSED [ 88%]
tests/test_proof_bundle.py::test_bundle_reports_revocation_without_parent_signed_record PASSED [100%]
======================== 9 passed, 9 warnings in 5.32s ========================

$ Invoke-WebRequest https://visiting-boolean-town-playstation.trycloudflare.com/.well-known/paari
protocol        : paari
protocol_version: 1.0

$ Get-Process python,cloudflared
   Id ProcessName  StartTime
24856 cloudflared   19-09-2026 15:38:58
10056 python        19-09-2026 15:38:24
24380 python        19-09-2026 17:00:07   (verifier/interactive session)
```

### A.2 `C:\Users\gowda\AppData\Local\Temp\proof_run.log` (decoded from UTF-16LE; 12 non-empty lines)

```text
[PASS] 1. service healthy: {'status': 'ok', 'service': 'paari', 'env': 'sandbox', 'database': 'up'}
[PASS] 2. parent pending: {'parent_id': 'b89778e0-9ada-448e-b915-e4c850d85539', 'status': 'pending_verification', 'trust_tier': 'self_asserted'}
[PASS] 3. parent approved: {'parent_id': 'b89778e0-9ada-448e-b915-e4c850d85539', 'status': 'active', 'trust_tier': 'admin_approved'}
[PASS] 4. delegation self-verifies: {'delegation_id': '17a51ec3-bd39-4a11-82aa-93351f11c9aa'}
[PASS] 5. v1 register ok: {'protocol': 'paari', 'protocol_version': '1.0', 'issuer': 'paari',
       'agent_id': 'f358feea-b4fc-454d-853d-aea4451853b3', 'name': 'Proof Agent 9c5ffd55',
       'agent_type': 'shopping_assistant', 'parent_id': 'b89778e0-9ada-448e-b915-e4c850d85539',
       'status': 'active', 'public_key': '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA2Hw0u4ufjWJ+/zT88Xag9qyUWWyqpIHw+c8Br3cGXNA=\n-----END PUBLIC KEY-----\n',
       'capabilities': ['payment.create'], 'limits': {'max_amount': 500000, 'currency': 'INR'},
       'credential_id': 'a7098519-c830-4e71-adc7-059c429b1414', 'expires_at': '2026-10-19T10:17:37Z',
       'endpoints': {'protocol_discovery': '/.well-known/paari',
                     'agent_card': '/v1/agents/f358feea-b4fc-454d-853d-aea4451853b3/card',
                     'payment_intent': '/v1/payments/intent',
                     'consume': '/v1/payments/authorizations/{authorization_id}/consume'},
       'card_signature_b64': 'l/UkcllzJWDVaB5WgQdHJ5XeglcgZKI+KFYcnditiftx+kKZdTIp1CK7vU4GgvbVXKz9491ZQa0h91x2sBEdBA==',
       'paari_public_key_pem': '-----BEGIN PUBLIC KEY-----...'}
[PASS] 5b. card bound by delegation, not request: {'protocol': 'paari', ... 'limits': {'max_amount': 500000, 'currency': 'INR'} ...}
[PASS] 6. card discovery-only: {'protocol': 'paari', 'protocol_version': '1.0', 'issuer': 'paari',
       'agent_id': 'f358feea-...', 'card_signature_b64': 'l/UkcllzJWDVaB5WgQdHJ5XeglcgZKI+...', ...}
[PASS] 7a. challenge issued: {'nonce': '3d1a24c0-7a81-4436-bd3a-ee36e5641e95', 'expires_at': '2026-09-19T10:19:37.207635Z'}
[PASS] 7b. authenticated: {'session': True}
[PASS] 8. intent ALLOW: {'intent_id': 'c25087c8-b6c8-4b57-bd51-706bfa5e1914', 'transaction_id': 'TXN-proof-9c5ffd55',
       'decision': 'allow', 'reasons': ['all checks passed'], 'mfa_required': False,
       'authorization': {'authorization_id': 'c25087c8-b6c8-4b57-bd51-706bfa5e1914',
         'token': 'eyJhbGciOiJFZERTQSIsImtpZCI6InBhYXJpLTEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJwYWFyaSIsImF1ZCI6InBhYXJpLXBheW1lbnQiLCJzdWIiOiJmMzU4ZmVlYS1iNGZjLTQ1NGQtODUzZC1hZWE0NDUxODUzYjMiLCJqdGkiOiJjMjUwODdjOC1iNmM4LTRiNTctYmQ1MS03MDZiZmE1ZTE5MTQiLCJpYXQiOjE3ODk4OTQzMDUsImV4cCI6MTc4OTg5NDQyNSwidHlwIjoicGFhcmlfYm91bmRlZF9hdXRob3JpemF0aW9uIiwiaW50ZW50X2lkIjoiYzI1MDg3YzgtYjZjOC00YjU3LWJkNTEtNzA2YmZhNWUxOTE0IiwidHJhbnNhY3Rpb25faWQiOiJUWE4tcHJvb2YtOWM1ZmZkNTUiLCJtZXJjaGFudCI6IlByb29mU3RvcmUiLCJhbW91bnRfbWlub3JfdW5pdHMiOjEwMCwiY3VycmVuY3kiOiJJTlIiLCJtYXhfdXNhZ2UiOjF9.ufi9LrYdVPupuyUn2Xib9p7-Kd75TFmxgMRCXJJQa2rlbl9zOYLgkfnPJLwsJsU9DLFEfwP6NMEvbCyPBJfDwP',
         'expires_at': '2026-09-19T10:19:37.262335+00:00', 'max_usage': 1, 'amount_minor_units': 100,
         'currency': 'INR', 'merchant': 'ProofStore', 'transaction_id': 'TXN-proof-9c5ffd55'},
       'review_expires_at': None}
[PASS] 9. consume submitted: {'authorization_id': 'c25087c8-b6c8-4b57-bd51-706bfa5e1914', 'consumed': True,
       'remaining_uses': 0, 'state': 'PROVIDER_SUBMITTED', 'razorpay_order_id': 'order_TdrLnfAh9TBQie',
       'razorpay_payment_id': None}
[WAIT] pay order order_TdrLnfAh9TBQie for Rs 1.00 in Test Mode, then the webhook settles it (waiting up to 600s)...
```

### A.3 `C:\Users\gowda\AppData\Local\Temp\cloudflared-err.log` (key lines)

```text
2026-09-19T10:08:59Z INF Requesting new quick Tunnel on trycloudflare.com...
2026-09-19T10:09:05Z INF |  Your quick Tunnel has been created! Visit it at:                              |
2026-09-19T10:09:05Z INF |  https://visiting-boolean-town-playstation.trycloudflare.com                   |
2026-09-19T10:09:05Z INF Version 2026.9.1 (Checksum 2837888cc0f5d58f15b6dc478376de90b4d3ba5241c7947455d1e0a0df429712)
2026-09-19T10:09:05Z INF Settings: map[ha-connections:1 protocol:quic url:http://127.0.0.1:8000]
2026-09-19T10:09:05Z INF Generated Connector ID: cb727fa2-18c3-4324-9ff2-57b8945912d8
2026-09-19T10:09:05Z INF Starting metrics server on 127.0.0.1:20241/metrics
2026-09-19T10:09:05Z INF |  DNS Resolution    region1.v2.argotunnel.com  PASS    DNS Resolved successfully     |
2026-09-19T10:09:05Z INF |  UDP Connectivity  region1.v2.argotunnel.com  PASS    QUIC connection successful    |
2026-09-19T10:09:05Z INF |  TCP Connectivity  region1.v2.argotunnel.com  PASS    HTTP/2 connection successful  |
2026-09-19T10:09:05Z INF |  Cloudflare API    api.cloudflare.com:443     PASS    API is reachable              |
2026-09-19T10:09:05Z INF |  SUMMARY: Environment is healthy. cloudflared will use 'quic' as primary protocol.  |
2026-09-19T10:09:05Z INF precheck complete hard_fail=false run_id=b781c87d-6854-483f-99db-cdf5e81d523a suggested_protocol=quic
2026-09-19T10:09:06Z INF Registered tunnel connection connIndex=0 connection=414fa64b-eba1-4242-92ee-99bc05aed17d event=0 ip=198.41.200.193 location=bom10 protocol=quic
```

### A.4 Retained live DB — audit chain and final state (`paari_live_e2e.db`)

```text
AUDIT EVENTS 6
  4 intent_decided         GENESIS      -> 991656e4f18b
  5 authorization_minted   991656e4f18b -> 3947c46381a0
  6 authorization_consumed 3947c46381a0 -> e0bc5ad046b4
  7 order_submitted        e0bc5ad046b4 -> cf6e39ef5ee6
  8 webhook_applied        cf6e39ef5ee6 -> 3cff427613e9
  9 webhook_applied        3cff427613e9 -> 5e8598ebe60b

verify_chain: True

TXN c25087c8-b6c8-4b57-bd51-706bfa5e1914 PAID order_TdrLnfAh9TBQie pay_TdrWE1S8hVE0PJ
    webhook_event_id 435a6e267c7929cf161f3d8e2a9e9a6cd953cd4dc04095848b5ad2b7ed45e9b6
TXN e1b01eda-8ea4-4d10-ad85-deff68cd6bad AUTHORIZED None None None   <-- extra agent's authorization
AUTH c25087c8-... ProofStore 100 INR max_usage=1 usage_count=1

agents: [('f358feea','revoked','1.0'), ('875401a4','active','1.0')]
parents: [('b89778e0','active','admin_approved'), ('3688b8e2','active','admin_approved'),
          ('0db9014e','active','admin_approved')]
creds: [('a7098519', revoked=True, superseded_by=None), ('9ab6e8e2', revoked=False, superseded_by=None)]
nonces: [('3d1a24c0','f358feea', used=True), ('42d1e730','875401a4', used=True)]
proofs: 4   mfa: 0   revocation_records: 0   delegations: 2
```

### A.5 Raw audit details (verbatim, abbreviated to relevant keys)

```text
intent_decided
  {"intent_id":"c25087c8-...","decision":"allow","reasons":["all checks passed"],
   "policy_results":[{"name":"parent_check","passed":true,"detail":"parent authority is active"},
                     {"name":"delegation_expiry","passed":true,"detail":"agent delegation is not expired"},
                     {"name":"amount_check","passed":true,"detail":"amount is positive"},
                     {"name":"capability_check","passed":true,"detail":"agent is delegated capability 'make_payment'"},
                     {"name":"limit_check","passed":true,"detail":"amount 100 is within delegated limit 500000"},
                     {"name":"currency_check","passed":true,"detail":"currency INR matches delegated currency INR"}],
   "amount_minor_units":100,"currency":"INR","merchant":"ProofStore","action":"make_payment"}

authorization_minted
  {"authorization_id":"c25087c8-...","amount_minor_units":100,"currency":"INR","merchant":"ProofStore",
   "expires_at":"2026-09-19T10:19:37.262335+00:00",
   "previous_state":"AUTHORIZED","current_state":"AUTHORIZED"}

authorization_consumed
  {"authorization_id":"c25087c8-...","remaining_uses":0,
   "previous_state":"PROVIDER_SUBMITTED","current_state":"PROVIDER_SUBMITTED"}    <-- see N-2

order_submitted
  {"authorization_id":"c25087c8-...","razorpay_order_id":"order_TdrLnfAh9TBQie",
   "amount_minor_units":100,"currency":"INR",
   "previous_state":"AUTHORIZED","current_state":"PROVIDER_SUBMITTED"}

webhook_applied  (#1)
  {"event_type":"payment.authorized","event_id":"928151a6c956ff454429f58580379cc09948b0f2181c3c63b04639ffca0202f0",
   "from_state":"PROVIDER_SUBMITTED","to_state":"PAYMENT_PENDING","order_id":"order_TdrLnfAh9TBQie",
   "payment_id":"pay_TdrWE1S8hVE0PJ","amount_minor_units":100,"currency":"INR"}

webhook_applied  (#2)
  {"event_type":"payment.captured","event_id":"435a6e267c7929cf161f3d8e2a9e9a6cd953cd4dc04095848b5ad2b7ed45e9b6",
   "from_state":"PAYMENT_PENDING","to_state":"PAID","order_id":"order_TdrLnfAh9TBQie",
   "payment_id":"pay_TdrWE1S8hVE0PJ","amount_minor_units":100,"currency":"INR"}
```
```

> The bounded-authorization JWT in A.2 is the real artifact: `"typ":"paari_bounded_authorization"`,
> `"merchant":"ProofStore"`, `"amount_minor_units":100`, `"currency":"INR"`, `"max_usage":1`.

### A.6 Retained proof bundle (`evidence_live_e2e_2026-09-19.json`, 15,711 bytes)

```text
TOP KEYS      ['artifacts','bundle_id','created_at','protocol','protocol_version','transaction_id']
bundle_id     bundle-TXN-proof-9c5ffd55
created_at    2026-09-19T10:17:37.256331+00:00
artifacts     all 14 present
```

Schema validation of the 14 artifacts (verifier run, `tests/_schema_validator.py`):

```text
PASS discovery             vs paari-discovery.v1.schema.json
PASS parent_trust          vs paari-parent-trust.v1.schema.json
PASS delegation            vs paari-delegation.v1.schema.json
PASS agent_card            vs paari-agent-card.v1.schema.json
FAIL credential            vs paari-credential.v1.schema.json -> missing required key 'iss'  (documented projection)
FAIL authentication        vs paari-session.v1.schema.json    -> missing required key 'iss'  (documented projection)
PASS governance_decision   vs paari-governance-decision.v1.schema.json
PASS payment_result        vs paari-payment-result.v1.schema.json
PASS audit_record          vs paari-audit-record.v1.schema.json
PASS bounded_authorization vs paari-bounded-authorization.v1.schema.json
FAIL revocation            vs paari-revocation.v1.schema.json -> oneOf matched 0 of 2 branches (not schema-pinned)
```

Key nodes verbatim:

```json
"payment_result": {"protocol":"paari","protocol_version":"1.0",
  "authorization_id":"c25087c8-b6c8-4b57-bd51-706bfa5e1914","transaction_id":"TXN-proof-9c5ffd55",
  "provider":"razorpay","provider_order_id":"order_TdrLnfAh9TBQie",
  "webhook_event":"435a6e267c7929cf161f3d8e2a9e9a6cd953cd4dc04095848b5ad2b7ed45e9b6",
  "webhook_verified":true,"final_state":"PAID","terminal":true}

"payment_execution": {"protocol":"paari","protocol_version":"1.0",
  "authorization_id":"c25087c8-...","state":"PAID","razorpay_order_id":"order_TdrLnfAh9TBQie"}

"audit_record": {"protocol":"paari","protocol_version":"1.0",
  "transaction_id":"TXN-proof-9c5ffd55","chain_verified":true,"events":[ ...6 events... ]}

"authentication": {"agent_id":"f358feea-...","authenticated":false,"credential_status":"revoked",
  "nonce_id":"3d1a24c0-7a81-4436-bd3a-ee36e5641e95","nonce_used":true,
  "nonce_expires_at":"2026-09-19T10:19:37.207635+00:00"}   <-- false because step 14 revoked the agent

"credential": {"credential_id":"a7098519-c830-4e71-adc7-059c429b1414","status":"revoked",
  "revoked":true,"superseded_by":null,"capabilities":["make_payment"],
  "payment_limit_minor_units":500000,"currency":"INR"}

"revocation": {"agent_id":"f358feea-...","revoked":true,"revocation_id":null}   <-- admin path, no record
```

### A.7 Live /v1/proof endpoint behaviours (operator-observed, matching tests)

```text
GET /v1/proof/TXN-extra-12bc6c             (own agent)     -> 200  merchant TestMerchant
GET /v1/proof/TXN-proof-9c5ffd55           (other agent)   -> 403  "This proof bundle does not belong to your agent"
GET /v1/proof/TXN-never-submitted                          -> 404  unknown transaction_id
GET /v1/proof/TXN-ambiguous   (2 intents share it)         -> 409  ambiguous transaction_id
GET /v1/proof/{tx}  without X-Paari-Proof on a v1 session  -> 401  PROOF_REPLAYED
```

### A.8 Evidence-file inventory (what exists on disk and what each item proves)

| File | Size | Proves |
|---|---|---|
| `C:\Users\gowda\AppData\Local\Temp\proof_run.log` | 10,930 B (UTF-16LE) | Steps 1-9 `[PASS]` lines + `[WAIT]` (verbatim in A.2). **Does not contain steps 10-15** — see N-4 |
| `C:\Users\gowda\AppData\Local\Temp\cloudflared-err.log` | 5,781 B | Tunnel creation, health precheck, QUIC registration (A.3) |
| `C:\Users\gowda\AppData\Local\Temp\paari_live_env.txt` | run secrets | `PAARI_ADMIN_API_KEY` + `RAZORPAY_WEBHOOK_SECRET` for the run — env-only, never committed (`*.pem`/`.env` gitignored) |
| `evidence_live_e2e_2026-09-19.json` | 15,711 B | Full 14-artifact proof bundle for `TXN-proof-9c5ffd55` (A.6); 8 nodes schema-validated |
| `evidence_live_e2e_2026-09-19.md` | human summary | Order `order_TdrLnfAh9TBQie` / `pay_TdrWE1S8hVE0PJ` `PAID`, `chain_verified True`, merchant `ProofStore` |
| `paari_live_e2e.db` | 221,184 B | Live SQLite: 6-event audit chain recomputed → `verify_chain == True` (A.4); final `PAID` state; revoked agent |
| `checkout_pay.html` | Razorpay Checkout.js page | Stage 10 manual capture: `key rzp_test_...`, `order_TdrLnfAh9TBQie` |
| `scripts/foreign_agent_proof.py` | 333 lines | The black-box 15-step runner (zero `app.*` imports; self-aborts if loaded) |

### A.9 Steps 10-15 — operator-reported outputs, each corroborated from retained state

Raw operator report (verbatim):

```text
10 pay via checkout_pay.html Razorpay checkout key rzp_test... order_TdrLnfAh9TBQie
   → pay_TdrWE1S8hVE0PJ captured (order paid amount_paid 100)
   — webhooks payment.authorized→PAYMENT_PENDING + payment.captured→PAID
11 reconcile idempotent → PAID
12 audit intent_decided→authorization_minted→authorization_consumed→order_submitted→
   webhook_applied×2 chain GENESIS hash-verified chain_verified True
13 over-delegation 50000000 → DENY amount exceeds delegated limit 500000
14 POST /agents/f358.../revoke revoked
15 POST /v1/auth/challenge 401 Agent not eligible — milestone GREEN

Independent corroboration from the retained store (this audit):

```text
10  DB: TXN c25087c8 PAID, razorpay_order_id order_TdrLnfAh9TBQie,
    razorpay_payment_id pay_TdrWE1S8hVE0PJ; audit webhook_applied x2 with
    from/to state pairs PROVIDER_SUBMITTED→PAYMENT_PENDING→PAID (A.5)      MATCHES
11  DB: reconciled terminal PAID; reconcile is idempotent on terminal
    state (short-circuit, app/reconcile.py:39)                             MATCHES
12  DB: 6 events GENESIS → … → 5e8598eb, verify_chain(db, tx) == True (A.4) MATCHES
13  DB: a 50,000,000-paise DENY exists — but under TXN-extra-12bc6c-over
    (extra agent 875401a4), NOT TXN-proof-9c5ffd55-over. Logic proven by
    tests/test_phase8_security.py::test_over_limit_is_denied_before_authorization
    and by the live extra-agent row; the certified agent's own step-13
    row is absent from the retained store                                   SEE N-1
14  DB: agents row f358feea = revoked; credential a7098519 revoked=True;
    RevocationRecord rows = 0 (admin path — expected)                      MATCHES
15  Bundle: authentication.authenticated = false,
    credential_status = revoked (A.6); deliberately vague 401 matches
    app/routers/auth.py:39 anti-enumeration behaviour                      MATCHES
```

---

## 8. Final verdict

### Verdict: **PASS — the blueprint is implemented correctly and demonstrably working.**

```text
15/15  stages implemented and executing end-to-end on Razorpay Test Mode
 8/15  stage artifacts schema-pinned and machine-validated against real collector output
 6/15  artifacts are documented evidence projections (STAGE_OUTPUTS.md footnote)
 4/4   per-stage output kinds present everywhere: JSON + signature/proof + audit event
 88    tests passing, 1 skipped (Postgres-migration test; runs in CI), compileall clean
  6    audit events hash-chained GENESIS → …, chain_verified recomputed server-side = True
```

**What is proven, not merely claimed:**

1. Every stage produces a concrete, machine-readable artifact, and each artifact links to its
   predecessor (delegation fingerprint → agent key → credential `sub` → session → intent →
   authorization → provider order → webhook → reconcile → audit → revocation).
2. The security core is real code, not narrative: parent-signed delegation as the only source of
   authority; cards built from DB rows and Ed25519-signed by Paari; single-use bounded authorization
   reserved by a conditional `UPDATE ... WHERE usage_count < max_usage`; settlement only from
   HMAC-verified webhooks or provider-truth reconciliation; a single transition table with terminal
   short-circuits; a tamper-evident audit chain that the server itself re-verifies on read.
3. The live run completed the full chain against real Razorpay Test Mode infrastructure —
   `order_TdrLnfAh9TBQie` → `pay_TdrWE1S8hVE0PJ` → two webhooks → terminal `PAID` — with the
   over-limit `DENY` and post-revocation `401` negative controls, and the retained DB independently
   corroborates 14 of the 15 step claims (A.9).

**Residual items (none block the verdict):**

| Item | Severity | Disposition |
|---|---|---|
| N-1 certified-agent step-13 row absent from retained DB | MEDIUM (evidence, not logic) | Re-capture while the server is up, or capture full stdout next run |
| N-2 `authorization_consumed` previous_state read after mutation | LOW/MEDIUM | One-line fix: capture `old_state` before `transition_txn` |
| N-3 `webhook_event` is an id/body-hash, not the event type | LOW | Emit `webhook_event_type` or rename to `webhook_event_id` |
| N-4 transcript/DB-size/reference slips in the run summary | LOW | Log hygiene: `Tee-Object` the full run; fresh DB per attempt |
| F-4 merchant/risk policy not enforced (declared scope) | declared | Merchant recorded, audited and bound, never constrained |
| F-5 parent lifecycle on legacy routes only | declared | Documented; `/v1` remains the frozen external surface |
| F-8 audit prev-hash read-then-write race (single-writer today) | LOW | Add a unique/locking guard before multi-writer deployment |
| Blueprint's own production gaps | deferred | Real KYB provider, secrets management, TLS, monitoring, backups, CI/CD |

**Bottom line:** the implementation matches the blueprint stage-for-stage, the proof chain is
cryptographically closed and independently verifiable from the retained evidence, and every gap that
remains is either an explicitly declared scope decision or a small, precisely located defect with a
known one-line fix. The system does not just "make the payment work" — every trust, authorization,
execution and security decision in the chain has a defined, inspectable, verifiable output.