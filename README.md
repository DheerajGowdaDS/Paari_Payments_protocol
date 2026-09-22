# Paari — Agentic Payment Protocol v1.0

Paari is a trust and governance layer between **any AI agent** and payment infrastructure. The agent never receives standing payment authority. Paari verifies who the agent is, who authorized it, what it is allowed to do, and whether a specific payment should execute.

```text
Any AI Agent
    |
    v
Parent Authority + Signed Delegation
    |
    v
Paari Agent Identity / Card / Credential
    |
    v
Proof-of-Possession Authentication
    |
    v
Payment Intent
    |
    v
Governance: identity -> authority -> capability -> limits -> currency -> risk -> MFA
    |
    +---- ALLOW ----> Single-use Bounded Authorization
    |
    +---- REVIEW ---> Parent-signed step-up approval
    |
    +---- DENY -----> No provider authorization
    |
    v
Provider Execution (Razorpay adapter)
    |
    v
Verified Webhook / Reconciliation
    |
    v
PAID / FAILED / UNKNOWN + Hash-chained Audit
```

## Core security model

### 1. Agent Trust

```text
Parent Authority
  -> verified trust tier
  -> parent-signed delegation
  -> agent public-key binding
  -> Paari Agent Card
  -> Paari credential
```

The parent delegation is authoritative for capabilities, payment limit, currency, and expiry. Agent-requested permissions are never trusted. Agent and parent private keys stay with their owners.

### 2. Agent Authentication

An agent proves possession of its private key through challenge/response. Paari issues a short-lived session bound to the authenticated credential and key fingerprint.

For protected v1 payment requests, Paari also requires a sender-constrained `Paari-Proof-JWT` bound to:

- the authenticated session token hash
- the agent identity
- HTTP method and exact path
- issue time
- a one-time proof JTI

Preferred HTTP form:

```http
Authorization: Bearer <session-token>
X-Paari-Proof: <Paari-Proof-JWT>
```

The reference implementation still accepts the legacy JSON `session_token` field for compatibility; new clients should use the Authorization header. Session tokens must never appear in URLs.

### 3. Payment Governance

Every payment intent is evaluated independently:

1. Agent identity and credential status
2. Parent authority status
3. Delegation validity
4. Requested capability
5. Per-transaction amount limit
6. Delegated currency
7. Velocity/risk rules
8. Step-up requirement
9. Idempotency and transaction state

The result is exactly one of:

- `ALLOW` — Paari may mint bounded payment authorization.
- `REVIEW` — step-up/dual-control approval required.
- `DENY` — no provider authorization is created.

### 4. Bounded Payment Authorization

An authorization is short-lived and bound to:

```text
agent
transaction
merchant
amount
currency
expiry
single-use
```

Authorization usage is reserved atomically in the database. The provider request uses the authorization ID as its provider-side idempotency key.

### 5. Provider Execution & Settlement

The provider layer is abstracted through `PaymentProvider`. Razorpay is the current provider implementation.

Paari only moves payment state from the provider boundary after authenticated provider truth:

```text
AUTHORIZED
  -> PROVIDER_SUBMITTED
  -> PAYMENT_PENDING
  -> PAID / FAILED / PROVIDER_UNKNOWN
```

`PROVIDER_UNKNOWN` is reconciled against provider state rather than guessed. `PAID` is terminal for the payment itself.

Webhook processing:

- verifies the raw request body with Razorpay HMAC
- derives a deterministic replay key when the provider payload has no event ID
- rejects provider amount/currency mismatches
- ignores duplicate events
- applies only legal transaction-state transitions

### 6. Audit & Accountability

Money-state and governance events are written to an append-only SHA-256 hash chain. Audit entries include the governance decision, reasons, authorization, provider submission, webhook/reconciliation state changes, and security actions.

### 7. Multi-tenancy

Organizations are first-class tenants. Tenant-scoped rows carry `org_id`; foreign keys prevent orphaned ownership. Non-default organizations use explicitly configured provider accounts and credentials. Paari must never silently fall back to another organization's payment credentials.

## Versioned protocol surface

The public protocol is defined in `docs/PROTOCOL.md` and the JSON schemas under `schemas/`.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/.well-known/paari` | Discover Paari v1 protocol capabilities and endpoints |
| POST | `/v1/agents/register` | Register an external agent with a signed parent delegation |
| GET | `/v1/agents/{agent_id}/card` | Fetch the Paari-signed Agent Card |
| POST | `/v1/auth/challenge` | Request agent key-possession challenge |
| POST | `/v1/auth/verify` | Verify challenge and issue short-lived session |
| POST | `/v1/payments/intent` | Submit a governed payment intent |
| POST | `/v1/payments/authorizations/{authorization_id}/consume` | Execute a single-use bounded authorization |
| POST | `/v1/payments/webhooks/razorpay` | Verified Razorpay settlement events |
| POST | `/v1/reconcile/{authorization_id}` | Reconcile provider truth after ambiguous/lost events |
| GET | `/v1/audit/{transaction_id}` | Retrieve owner-scoped audit trail |
| GET | `/v1/proof/{transaction_id}` | Retrieve the owner-scoped stage-output proof bundle (read-only) |
| POST | `/v1/agents/{agent_id}/rotate-key` | Rotate agent key with a fresh parent delegation |
| POST | `/v1/authorizations/{authorization_id}/revoke` | Revoke unused bounded authorization |
| POST | `/v1/parents/{parent_id}/rotate-key` | Rotate parent key (admin controlled) |
| POST | `/v1/parents/{parent_id}/kyb` | Record the external KYB verification reference |

Unversioned routes are retained as legacy compatibility surfaces. New external integrations should use `/v1`.

## Protocol objects

- **Parent Authority** — trusted delegator.
- **Delegation** — parent-signed grant for one agent public-key fingerprint, capabilities, limit, currency, and expiry.
- **Agent Card** — signed discovery/identity object; it does not itself grant payment authority.
- **Credential** — Paari-signed agent identity credential.
- **Session** — short-lived authenticated agent session.
- **Paari-Proof-JWT** — sender-constrained proof for protected HTTP requests.
- **Payment Intent** — requested money action.
- **Governance Decision** — ALLOW / REVIEW / DENY.
- **Bounded Authorization** — single-use authorization for one provider execution.
- **Provider Transaction** — authoritative Paari execution/settlement state.

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
export PAARI_ADMIN_API_KEY='change-me'
alembic upgrade head
uvicorn app.main:app --reload
```

Default development storage is SQLite. Production should use PostgreSQL.

### Required payment secrets

```bash
RAZORPAY_KEY_ID
RAZORPAY_KEY_SECRET
RAZORPAY_WEBHOOK_SECRET
PAARI_ADMIN_API_KEY
PAARI_SIGNING_KEY_PATH
DATABASE_URL
```

When `PAARI_LIVE=1`, Paari refuses to boot without the webhook secret and admin credential. Provider credentials are server-side only.

## External-agent proof

`scripts/foreign_agent_proof.py` is intentionally written without importing `app.*`. It uses its own Ed25519 key pair and HTTP client to exercise the public protocol surface, proving that an independent client can:

```text
register -> authenticate -> request payment -> pass governance
-> receive bounded authorization -> execute via Razorpay Test Mode
-> settle via webhook/reconciliation -> verify audit -> prove revocation
```

The current source tree has **88 passing automated tests, 1 skipped** (the skipped test exercises a PostgreSQL migration and runs in CI against a live service). Phase 7 adds the reference external-agent SDK and trust-provider abstraction; Phase 8 adds foreign-agent SDK conformance and adversarial security tests. The test suite covers protocol envelopes, migrations, provider abstraction, transaction transitions, reconciliation, audit chaining, rotation, hardening, multi-tenancy, MFA, atomic consume, stage-output proof bundles, and Razorpay webhook behavior.

## Security limitations outside the reference implementation

Paari's reference implementation intentionally leaves several production deployment concerns to the operator:

- real KYB/identity-provider integration for parent authorities
- KMS/HSM-backed Paari signing key management
- permanent HTTPS deployment and hardened webhook ingress
- production PostgreSQL operations and automated migration CI
- centralized secrets management
- production monitoring, alerting, backups, incident response, and disaster recovery

These are deployment/security operations, not reasons to give an AI agent standing payment credentials.

## Project status

Phase 1–5 established the trust, authentication, governance, bounded authorization, and real Razorpay execution path. Phase 6 adds the versioned protocol, external-agent onboarding, reconciliation, multi-tenancy, provider abstraction, hash-chained audit, rate limiting, key rotation, revocation propagation, and sender-constrained request proofs.

Phase 7–8 now provide the reference external-agent SDK, parent-trust abstraction, production boot guardrails, protocol conformance contract, CI workflow, and adversarial tests. The remaining production work is deployment-specific: real KYB provider integration, HSM/KMS key custody, stable HTTPS infrastructure, provider-specific operational credentials, monitoring, backups, incident response, and independent external-agent certification.
