# Paari — Agentic Payment Protocol v1.2

Paari is a trust and governance layer between **any AI agent** and payment infrastructure. The agent never receives standing payment authority. Paari verifies who the agent is, who authorized it, what it is allowed to do, and whether a specific payment should execute.

> **What Paari does today.** Paari enables an AI agent to *propose* a payment while Paari verifies identity, delegated authority, the user mandate, limits and transaction policy before issuing a single-use bounded authorization. The protocol now has a complete **provider-native autonomous settlement path** (`PROVIDER_SUBMITTED -> PROVIDER_AUTHORIZED -> CAPTURED -> PAID`) and an explicit reference provider for no-human-checkout conformance testing. A real-money deployment still requires a payment provider to expose and enable a server-to-server mandate/token debit contract; Paari never treats a normal checkout order as autonomous settlement. The agent proposes; Paari independently validates authority and authorizes execution.

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

### 5. Provider-native autonomous settlement

Paari separates **protocol capability** from **provider entitlement**. The provider-facing `AgenticPaymentProvider` interface supports:

```text
validate mandate/instrument reference
        ↓
authorize one payment under bounded authorization
        ↓
capture provider-authorized payment
        ↓
direct provider read corroborates capture
        ↓
PAID
```

`app/providers/reference_autonomous.py` is a deterministic in-memory conformance
provider. It proves the protocol path without moving real money and is the default
for `scripts/autonomous_payment_e2e.py`. `RazorpayAgenticProvider` is the real
provider adapter seam: it is **fail-closed** until the deployment supplies the
provider's exact documented mandate/debit paths and an explicit capability
attestation. If that capability is unavailable, `PAARI_MODE=autonomous` never
fallbacks to an ordinary human-checkout order.

### 6. Provider Execution & Settlement

The provider layer is abstracted through `PaymentProvider`. Razorpay is the current provider implementation.

Paari only moves payment state from the provider boundary after authenticated provider truth:

```text
AUTHORIZED
  -> PROVIDER_SUBMITTED
  -> PROVIDER_AUTHORIZED      provider holds an authorisation, money not captured
  -> CAPTURED                 provider announced a capture, not yet corroborated
  -> PAID                     capture confirmed by a direct provider read
  or FAILED / DECLINED / EXPIRED / CANCELLED / PROVIDER_UNKNOWN
  and after PAID: REFUNDED / REVERSED
```

`PAID` requires two independent provider signals, not one. A signature-verified
webhook moves the row to `CAPTURED`; it becomes `PAID` only when
`app.reconcile.confirm_capture` corroborates the capture against the provider's
own API, with amount and currency matching the bounded authorization exactly. If
that read cannot be made, the row stays `CAPTURED` — a non-terminal state the
reconciliation worker keeps visiting — rather than being marked settled on a
single inbound message. The webhook handler has no path to `PAID` at all, and
`tests/test_phase9_state_machine.py` enforces that by reading the handler's own
event mapping.

`PROVIDER_UNKNOWN` is reconciled against provider state rather than guessed. `PAID` is terminal for the payment itself.

Webhook processing:

- verifies the raw request body with Razorpay HMAC
- derives a deterministic replay key when the provider payload has no event ID
- rejects provider amount/currency mismatches
- ignores duplicate events
- applies only legal transaction-state transitions

### 7. Audit & Accountability

Money-state and governance events are written to an append-only SHA-256 hash chain. Audit entries include the governance decision, reasons, authorization, provider submission, webhook/reconciliation state changes, and security actions.

### 8. Multi-tenancy

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
register -> authenticate -> read active user mandate -> propose payment
-> pass governance -> receive bounded authorization
-> consume through the configured provider path -> verify audit -> prove revocation
```

When a provider-native agentic adapter is configured, the consume step can end at
`PAID` with no browser checkout. When only ordinary Razorpay Test-Mode orders are
available, the proof correctly stops at `PROVIDER_SUBMITTED`; it does not call that
autonomous payment.

Run `python -m pytest -q` for the current suite. The repository also includes
`tests/test_razorpay_agentic.py` and autonomous-state regression tests for the
provider-native path.

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

## Paari v2 extension: user payment authority

The current codebase adds a provider-neutral **User Payment Mandate** layer on
top of parent delegation. A mandate is a cryptographically signed
authorization artifact: the canonical signed payload covers user/agent binding,
per-transaction, hourly, daily, per-merchant and per-category limits, currency,
optional merchant/category allowlists, review threshold and validity window. A
mandate's Ed25519 signature is verified **in the authorization path** (payment
intent) and again at execution time (consume) — a valid signature does not make
an expired mandate valid, and a mandate whose stored row was altered no longer
verifies.

Mandate resolution is a tri-state:

```text
NONE    - this agent never had a mandate; only PAARI_MODE=autonomous denies
LAPSED  - a mandate existed but is expired / revoked / out of window
          -> DENY in every mode (a lapsed grant is not an absent grant)
ACTIVE  - evaluate every active mandate; the tightest one governs
```

Spending windows are **rolling** (not calendar-boundary based) and clamped to
the mandate's own validity start. The active mandate is resolved server-side
and cannot be chosen by the LLM/client.

Governance posture is defined once, in `app.config.mandate_policy()`:

```text
PAARI_MODE=standard     (default) mandate enforced when one exists
PAARI_MODE=autonomous             an active mandate is REQUIRED
PAARI_REQUIRE_USER_MANDATE=1      legacy alias for autonomous
PAARI_REQUIRE_SIGNED_MANDATE=1    an unsigned mandate is refused
```

An unrecognised `PAARI_MODE` is rejected rather than downgraded, and the active
posture is reported on `GET /health` alongside `autonomous_settlement`.

### Autonomous settlement contract

The consume path now has a strict provider-native autonomous branch:
`PROVIDER_SUBMITTED → PROVIDER_AUTHORIZED → CAPTURED → PAID`. It does **not**
create an ordinary checkout order first, and `PAARI_MODE=autonomous` fails closed
when no provider-native adapter is capable. The adapter must validate a provider
mandate/instrument reference, authorize the exact bounded payment, report capture,
and allow an independent provider read to corroborate amount/currency/status.

`app/providers/reference_autonomous.py` provides a deterministic protocol-only
implementation for conformance and development; it moves no real money.
`app/providers/razorpay_agentic.py` is the production adapter seam and refuses to
claim autonomous capability until the real account is explicitly provisioned with
the provider's documented server-to-server mandate/debit contract.

`scripts/autonomous_payment_e2e.py --provider reference` therefore demonstrates a
complete autonomous **protocol** flow ending in `PAID` without human checkout.
`scripts/autonomous_payment_e2e.py --provider real-razorpay` is the live-provider
proof and fails closed when the account lacks the required provider capability.
The real-LLM variant is `scripts/llm_agent_e2e.py --with-server --require-mandate`.

### Causal audit attribution

`llm_run_id`, `llm_model`, `llm_tool_call_id` and `llm_tool_name` are
**client-asserted trace labels**, never conversation content or secrets. Paari
proves that the authenticated agent submitted them (they ride on the
sender-constrained `Paari-Proof-JWT`); it does not and cannot prove that a model
produced them, because the identifiers originate from the LLM. The
`llm_tool_call` audit event is written **only** when attribution was actually
claimed, and `PaymentIntent.llm_attributed` records the claim; payments with no
causal ids are marked `payment_proposed` instead.


## Clean release security note

This release archive intentionally excludes `.env`, private signing keys, local database files, Git history, checkout pages containing provider key identifiers, and runtime caches. Start in sandbox mode and supply credentials through environment variables or a secret manager.
