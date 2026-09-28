> **Historical phase note (superseded by the v1.2 provider-native settlement work):** this document records the original v2 boundary. The current implementation adds the `AgenticPaymentProvider` execution path and the reference autonomous conformance provider; see `docs/PROVIDER_AUTONOMOUS_SETTLEMENT.md`.

# Paari v2 Extension — User Payment Authority and Autonomous Settlement Boundary

## Purpose

This release adds the next authorization layer required for agentic payments:

```text
User / Trusted Surface
        ↓
User Payment Mandate
        ↓
Parent Delegation
        ↓
Agent Authentication
        ↓
Payment Governance
        ↓
Single-use Bounded Authorization
        ↓
Provider Execution
```

The user mandate is intentionally separate from parent delegation and from the
single-payment authorization.

## What is implemented in this release

### UserPaymentMandate

A mandate contains:

- user_id
- agent_id
- per-transaction limit
- daily spending limit
- currency
- optional allowed merchants
- optional allowed categories
- optional review threshold
- validity window
- status / revocation
- an external approval_reference for the trusted-surface consent record

The server resolves the active mandate. The client/LLM cannot select an
arbitrary mandate_id.

### Governance integration

When an active mandate exists, Paari evaluates it together with the existing
agent delegation checks. With `PAARI_REQUIRE_USER_MANDATE=1`, an autonomous
payment is denied unless an active user mandate exists.

The following are enforced:

- per-transaction amount
- daily budget
- currency
- merchant allowlist
- category allowlist
- review threshold
- mandate expiry/revocation

### Execution-time revalidation

A bounded authorization that was issued under a user mandate is checked again
at consume time. Revoking the mandate therefore blocks a previously minted,
not-yet-consumed authorization.

### Provider binding

`PaymentInstrumentBinding` stores only provider-issued references. It does not
store raw card numbers, CVV, UPI PINs, bank passwords or similar payment
credentials.

## Intentional provider boundary

This release does **not** fake autonomous capture.

The existing RazorpayAdapter still creates a real Razorpay order and relies on
provider checkout / webhook settlement for the full payment lifecycle.

`app.providers.agentic.AgenticPaymentProvider` is a provider-neutral interface
for a future provider-native agentic payment capability. An adapter should be
implemented only when the payment provider supplies a documented API/sandbox
for a user-consented, provider-recognized payment mandate or tokenized
instrument.

Therefore the current claims remain:

- real LLM → Paari governance → real Razorpay Test-Mode order: supported;
- full real PAID settlement without human checkout: **not claimed by this
  release**;
- local `--settle` remains an explicit provider simulator for state-machine
  testing only.

## LLM integration

The broker now exposes a separate `get_payment_authority` tool. The model can
read the active user mandate but never receives private keys, provider secrets,
webhook secrets or raw payment credentials.

The model still proposes actions. Paari remains the authoritative security
boundary.

## E2E option

The LLM harness supports:

```bash
python scripts/llm_agent_e2e.py --with-server --require-mandate
```

This creates a sandbox trusted-surface mandate through the admin bootstrap
boundary, then requires the mandate during payment governance. The E2E remains
honest about the provider boundary: with real Razorpay credentials it proves
real order creation; `--settle` uses the local simulator.

## Production work still required

- replace the trusted-surface/admin bootstrap with real end-user authentication
  and cryptographic consent/mandate issuance;
- integrate a documented provider-native agentic payment capability;
- bind/revoke provider mandates through the provider adapter;
- add KMS/HSM-backed secret management, TLS, observability, backups and CI/CD;
- integrate real KYB / organizational trust providers;
- complete external interoperability/conformance testing.
