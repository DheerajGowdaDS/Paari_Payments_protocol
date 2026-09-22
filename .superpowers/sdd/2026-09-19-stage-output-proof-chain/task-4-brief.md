# Task 4 brief — Stage-output catalog docs (read this first; it is your requirements, with exact values to use verbatim)

## Where this fits
Tasks 1–3 complete and review-clean (suite at 80 passed / 1 skipped). You write `docs/STAGE_OUTPUTS.md` (15-row catalog table) and append 6 schema bullets to the `docs/PROTOCOL.md` index. Docs only; no code changes.

## Global constraints (binding)
- Every table row names an exact schema file, exact endpoint/code reference, and exact verifying test. No prose-only rows.
- Never write secrets, `.pem`, `.key`, `.db`, or `.env` content.
- NOT a git repo: do NOT run git commands.

## Steps (do exactly these)

### Step 1: Create `docs/STAGE_OUTPUTS.md` with this exact content (header + 15 rows):

```markdown
# Paari Stage Outputs (Protocol v1.0)

Every stage consumes the previous stage's output, verifies it, and emits a schema-pinned artifact. Bundle collector: `app/proof_bundle.py::collect_proof_bundle(db, transaction_id)`.

| Stage | Output artifact | Schema file | Producing endpoint / code | Verifying test |
|---|---|---|---|---|
| 1. Discovery | Protocol Discovery Document | `schemas/paari-discovery.v1.schema.json` | `GET /.well-known/paari` (`app/main.py`) | `tests/test_schemas.py::test_discovery_endpoint_matches_schema` |
| 2. Parent Registration | Parent Trust Record (`pending_verification` / `self_asserted`) | `schemas/paari-parent-trust.v1.schema.json` | `POST /parents/register` (`app/routers/parents.py`) | `tests/test_trust_provider.py` |
| 3. Parent Verification | Verified Parent Identity (`active` / `admin_approved`) | `schemas/paari-parent-trust.v1.schema.json` | `POST /parents/{parent_id}/approve` (`app/routers/parents.py`) + `app/trust.py::ParentTrustProvider` | `tests/test_trust_provider.py` |
| 4. Delegation | Signed Delegation | `schemas/paari-delegation.v1.schema.json` | Parent-signed canonical JSON, verified at `app/routers/v1.py:v1_register_agent` | `tests/test_proof_chain.py::test_tampered_delegation_fails_registration` |
| 5. Agent Registration | Agent Identity Record | `schemas/paari-envelope.v1.schema.json` | `POST /v1/agents/register` (`app/routers/v1.py:v1_register_agent`) | `tests/test_protocol.py::test_v1_register_ignores_requested_permissions` |
| 6. Agent Card | Signed Agent Card | `schemas/paari-agent-card.v1.schema.json` | `GET /v1/agents/{agent_id}/card` (`app/routers/v1.py:v1_get_card`) | `tests/test_protocol.py::test_v1_card_is_discovery_only` |
| 7. Credential | Agent Credential | `schemas/paari-credential.v1.schema.json` | Issued at registration (`app/security.py::issue_credential_jwt`) | `tests/test_proof_bundle.py` (credential section) |
| 8. Authentication | Authenticated Session / Proof | `schemas/paari-session.v1.schema.json` | `POST /v1/auth/challenge` + `POST /v1/auth/verify` (`app/routers/v1.py`) | `tests/test_mfa_auth.py` |
| 9. Payment Intent | Governance Decision (`allow` / `review` / `deny` + reasons) | `schemas/paari-payment-intent.v1.schema.json` + `schemas/paari-governance-decision.v1.schema.json` | `POST /v1/payments/intent` (`app/routers/v1.py:v1_payment_intent`) | `tests/test_governance_attacks.py` |
| 10. Bounded Authorization | Single-use Authorization | `schemas/paari-bounded-authorization.v1.schema.json` | Minted on ALLOW (`app/routers/payments.py`) | `tests/test_consume_atomic.py` |
| 11. Payment Execution | Provider Order / Execution Result | `schemas/paari-consume.v1.schema.json` | `POST /v1/payments/authorizations/{authorization_id}/consume` | `tests/test_consume_atomic.py` |
| 12. Webhook | Verified Payment Event | `schemas/paari-webhook.v1.schema.json` | `POST /v1/payments/webhooks/razorpay` (HMAC over raw body) | `tests/test_webhook.py` + `tests/test_webhook_org_isolation.py` |
| 13. Reconciliation | Final Payment State | `schemas/paari-reconcile.v1.schema.json` + `schemas/paari-payment-result.v1.schema.json` | `POST /v1/reconcile/{authorization_id}` (`app/reconcile.py`, `app/reconcile_worker.py`) | `tests/test_reconcile.py` + `tests/test_reconcile_worker.py` |
| 14. Audit | Tamper-evident Audit Record | `schemas/paari-audit-record.v1.schema.json` | `app/audit.py::record_audit` + `GET /v1/audit/{transaction_id}` | `tests/test_audit_hardening.py` + chain-link loop in `tests/test_proof_chain.py` |
| 15. Revocation | Revocation Result / Access Denied | `schemas/paari-revocation.v1.schema.json` | `POST /v1/authorizations/{authorization_id}/revoke` + `POST /agents/{agent_id}/revoke` | `tests/test_phase8_security.py` |
```

Before writing, spot-check any TWO rows you doubt against the cited code file (read-only) and fix the row if the code disagrees — never invent paths.

### Step 2: Update `docs/PROTOCOL.md` — append these 6 bullets after the Revocation line of the JSON Schemas index, same format:

```markdown
- Parent Trust: `schemas/paari-parent-trust.v1.schema.json`
- Delegation: `schemas/paari-delegation.v1.schema.json`
- Governance Decision: `schemas/paari-governance-decision.v1.schema.json`
- Payment Result: `schemas/paari-payment-result.v1.schema.json`
- Audit Record: `schemas/paari-audit-record.v1.schema.json`
- Proof Bundle: `schemas/paari-proof-bundle.v1.schema.json`
```

### Step 3: Verify
Run: `pytest -q`
Expected: 80 passed, 1 skipped, docs complete.

## Report contract
Write your full report to `.superpowers/sdd/2026-09-19-stage-output-proof-chain/task-4-report.md`. Reply with only: status (DONE / DONE_WITH_CONCERNS / NEEDS_CONTEXT / BLOCKED), the test summary line, and any concerns.
