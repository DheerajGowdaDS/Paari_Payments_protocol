# Paari Protocol v1.0 — Hardening Release Notes

## Release goal

This release hardens Paari from a Phase 6 reference implementation into a cleaner protocol surface for independent AI-agent clients. The Razorpay provider remains the execution adapter; Paari remains the trust, governance, authorization, settlement-verification, and audit control plane.

## Protocol finalized

- Versioned `/.well-known/paari` discovery document.
- Versioned `/v1` lifecycle for registration, authentication, payment intent, step-up MFA, bounded-authorization consumption, reconciliation, audit, rotation and revocation.
- `PaariEnvelope` v1.0 with canonical JSON + Ed25519 signatures, bounded lifetime, receiver validation, and fail-closed versioning.
- Signed, versioned Agent Card. Card data is discovery only; it is not spending authority.
- Complete v1 message constructor set in `app/protocol/messages.py`.
- JSON schemas for envelope, Agent Card, and Payment Intent.
- External-agent proof script uses only HTTP + cryptography and does not import Paari application modules.

## Payment security hardened

- Sender-constrained `Paari-Proof-JWT` for protected v1 requests.
- Preferred session transport is `Authorization: Bearer <session-token>`; legacy body field remains only for compatibility.
- Proof binds the session token hash, agent identity, HTTP method, exact path, timestamp, and one-time JTI.
- Agent/credential/parent/delegation trust is revalidated at execution time.
- Bounded Authorization is exact-transaction, short-lived, and single-use.
- Single-use consumption is atomic at the database boundary.
- Razorpay submission uses the authorization ID as the provider idempotency key.
- Provider response must match authorization receipt, amount, and currency before the provider transaction advances.
- Webhooks use raw-body HMAC verification, replay protection, legal state transitions, and amount/currency binding.
- Missed/ambiguous provider outcomes use `PROVIDER_UNKNOWN` plus reconciliation rather than guessed success.
- Parent/agent/credential/authorization revocation blocks further provider execution.
- Tenant provider routing cannot silently fall back from a non-default organization to another organization's credentials.

## Evidence and reliability

- Central transaction transition table prevents illegal state changes and PAID regressions.
- Audit events are hash-chained and include decision reasons and pre/post state for money-state transitions.
- Shared rate limiting is database-backed for multi-worker deployments.
- Alembic owns schema creation; import-time `create_all` is not used.
- Runtime secret scanning excludes private keys, local databases, and environment files from the release artifact.

## Validation

Current local validation:

```text
Python compilation: PASS
JSON schema parsing: PASS
Null-byte source scan: PASS
Automated tests: 48 passed
Warnings: 37 (Alembic path-separator deprecation warning and existing test DB warnings)
```

The environment used for this validation did not run a new live Razorpay Test-Mode transaction. The prior Phase 6 live proof remains the evidence for real Test-Mode provider execution; this release primarily hardens and finalizes the protocol/security surface around that path.

## Production items outside this release

- Real KYB/KYC integration for parent authorities.
- KMS/HSM-backed Paari signing-key lifecycle.
- Permanent HTTPS deployment and production webhook ingress.
- PostgreSQL operational controls, backups, restore and disaster recovery.
- Production monitoring/alerting and incident-response processes.
- Additional providers and their provider-specific webhook/reconciliation implementations.
