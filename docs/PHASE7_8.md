# Paari Phase 7–8 — Production Protocol & Interoperability

## Phase 7 — Production protocol and security

### 7.1 Protocol freeze
Paari Protocol v1.0 is a versioned wire contract. Implementations MUST use
`protocol=paari` and `version=1.0`, canonical UTF-8 JSON, pinned Ed25519/EdDSA
algorithms, explicit expiration, and fail-closed errors. Unsupported versions
must be rejected; no silent downgrade.

The normative entrypoint is `docs/PROTOCOL.md`, with JSON schemas under
`schemas/` and discovery at `/.well-known/paari`.

### 7.2 External Agent SDK
`sdk/paari_agent/` is a dependency-light reference client with no imports from
Paari server modules. It implements discovery, signed onboarding envelopes,
Agent Card verification, challenge/response authentication, sender-constrained
request proofs, payment intents, authorization consume, reconciliation, and
revocation.

### 7.3 Trust and KYB abstraction
`app/trust.py` defines a `ParentTrustProvider` boundary. The reference
implementation uses the Paari-admin trust control. A deployment can replace it
with a real KYB/business-registry/enterprise-IdP provider without changing the
protocol. Parent state remains fail-closed for delegation and payment.

### 7.4 Payment security invariants
Provider account routing is organization-bound; non-default tenants never fall
back to default provider credentials. Provider orders/payments are checked
against the exact bounded authorization amount, currency, receipt/order and
owning organization. Authorizations are atomically single-use and trust is
revalidated at execution time.

### 7.5 Key and credential lifecycle
Agent rotation requires a fresh parent-signed delegation bound to the new
public-key fingerprint. Paari credentials are revoked/superseded on rotation.
Parent key changes require authenticated Paari administration. Production keys
must be supplied via a secret manager/environment and never committed to the
repository.

### 7.6 Audit and evidence
Security-relevant facts are append-only and hash chained. Decision events carry
reasons and transaction/provider state transitions carry explicit before/after
values. Audit access uses an Authorization header; credentials are never placed
in URLs.

### 7.7 Reconciliation
Provider-unknown outcomes are not guessed. Reconciliation queries provider
truth by authorization receipt/order, verifies amount/currency, applies only a
legal state transition, and records an audit event. Production deployments
should run the reconciler continuously and alert on long-lived UNKNOWN states.

## Phase 8 — Interoperability and adversarial validation

### 8.1 Foreign-agent conformance
A foreign agent must use only the public protocol contract and standard crypto/
HTTP libraries. It must be able to discover Paari, register, authenticate,
submit a payment intent, consume a bounded authorization, and reconcile a
payment without importing server internals.

### 8.2 Attack suite
Conformance tests cover or should cover: forged delegation, over-delegation,
wrong key, wrong agent/session, replayed request proof, expired credential,
revoked parent/agent, authorization replay/double consume, amount/currency
mismatch, cross-organization access, webhook replay, invalid signature, and
provider-account fallback attempts.

### 8.3 Sandbox and production separation
Use separate database, credentials, webhook secrets, signing keys and provider
accounts for sandbox and production. A production boot must fail closed when
required secrets are missing.

## Release gate
A Paari v1 release is considered protocol-ready when an independent agent can
complete the black-box conformance flow using only the published discovery,
protocol specification, schemas, and SDK, and the adversarial suite demonstrates
that trust revocation, replay, over-delegation, value tampering and tenant
confusion cannot result in provider execution.
