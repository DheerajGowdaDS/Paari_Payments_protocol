# Paari Agentic Payment Protocol v1.0

Paari is the trust and governance layer between an AI agent and payment infrastructure. A Paari-verified agent never receives standing payment authority; each money movement is separately governed and bound to a short-lived, single-use authorization.

> Per-operation examples: [protocol-examples.md](protocol-examples.md)

## Trust chain

```text
Parent Authority
  -> signed Delegation
  -> Agent public key binding
  -> Paari Agent Card + Credential
  -> challenge / proof-of-possession
  -> sender-constrained Session
  -> Payment Intent
  -> Governance
  -> Bounded Authorization
  -> Provider Execution
  -> Webhook / Reconciliation
  -> Audit
```

## Security objects

**Parent Authority** — verified organization/developer/platform/agent allowed to delegate payment capability.

**Delegation** — parent-signed canonical JSON binding one agent public-key fingerprint to exact capabilities, amount limit, currency and expiry. Agent-requested permissions are never authority.

**Agent Card** — signed discovery/identity object. It is not a payment credential and does not itself grant spending authority.

**Credential** — Paari-signed, short-lived/revocable identity credential.

**Session** — short-lived authentication result after proof-of-possession of the agent key.

**Paari-Proof-JWT** — per-request sender-constrained proof. It binds the session token hash, agent ID, HTTP method/path, issue time and a unique JTI. Implementations should follow the same goals as OAuth DPoP: possession of the private key is demonstrated for each protected request. See RFC 9449. 

**Payment Intent** — requested money action.

**Bounded Authorization** — the only artifact that authorizes provider execution. It is bound to one agent, transaction, merchant, amount and currency, and is single-use and short-lived.

## Message envelope

Control-plane protocol documents use the signed `PaariEnvelope`. Protected payment HTTP endpoints use JSON request bodies plus a sender-constrained `Paari-Proof-JWT`; they do not rely on an unsigned bearer request body.

A `PaariEnvelope` is: 

```json
{
  "protocol": "paari",
  "version": "1.0",
  "type": "payment.intent",
  "message_id": "uuid",
  "sender": "agent-id",
  "receiver": "paari",
  "issued_at": 1750000000,
  "expires_at": 1750000120,
  "payload": {},
  "signature": "base64-ed25519"
}
```

The signature covers the canonical UTF-8 JSON of every field except `signature`. Implementations MUST reject unsupported versions, stale/future envelopes outside clock skew, wrong receivers, and invalid signatures.

## Protected HTTP requests

For v1 payment, consume, MFA-challenge, reconciliation, and authorization-revocation requests, the preferred credential transport is:

```http
Authorization: Bearer <Paari session token>
X-Paari-Proof: <Paari-Proof-JWT>
```

The request proof is bound to the exact HTTP method and path and to the session token hash. The JSON `session_token` field remains accepted by the reference implementation for backwards compatibility, but new clients SHOULD use the Authorization header. If both are supplied, they MUST match. Session tokens MUST NOT be placed in URLs.

The v1 payment lifecycle includes `/v1/payments/intent`, `/v1/payments/mfa/challenge`, `/v1/payments/mfa/verify`, `/v1/payments/authorizations/{authorization_id}/consume`, `/v1/reconcile/{authorization_id}`, and `/v1/authorizations/{authorization_id}/revoke`.

Evidence retrieval is read-only and never changes state: `GET /v1/audit/{transaction_id}` returns the hash-chained audit trail together with `chain_verified`, Paari's own recomputation of every link (a `false` there means stored evidence no longer verifies); `GET /v1/proof/{transaction_id}` returns the stage-output proof bundle (all artifacts defined in `docs/STAGE_OUTPUTS.md`), whose `audit_record` node carries the same `chain_verified` result. Both are owner-scoped: a caller whose session does not own the transaction receives `403`, an unknown or ambiguous `transaction_id` receives `404`/`409`. `GET /v1/proof/{transaction_id}` carries payment-grade authentication: for sessions onboarded under protocol v1.0 it additionally requires `X-Paari-Proof` bound to the exact method and path, whereas the audit trail requires only the bearer session.

## Payment decision

Paari returns exactly one governance outcome:

* `allow` — a bounded authorization may be minted.
* `review` — step-up / external approval is required.
* `deny` — no provider execution is allowed.

## Provider settlement

Provider webhooks are verified over the **raw request body** with HMAC. The provider-reported order, amount and currency must match the stored bounded authorization before the transaction can become `PAID`. Provider reconciliation is the recovery path for missed webhooks.

## Multi-tenancy

Every tenant-scoped object carries `org_id`. Provider credentials are tenant-specific and are never stored in the database; the database stores only a provider-account routing label. A non-default tenant must not silently fall back to the default provider credentials.

## Normative security requirements

1. Agent and parent private keys MUST stay with their owners.
2. Delegated capabilities and limits MUST come from signed parent authority.
3. JWT implementations MUST pin accepted algorithms and validate issuer, audience and token type in addition to signature/expiry. This follows JWT BCP guidance in RFC 8725.
4. Protected payment requests SHOULD use a sender-constrained request proof; Paari v1 uses `Paari-Proof-JWT` for this purpose.
5. Payment authorization MUST be single-use and atomically reserved.
6. Provider calls MUST be idempotent by authorization ID.
7. Settlement MUST be provider-confirmed; client claims never settle money.
8. Webhook amount/currency/order MUST be checked against the exact authorization bounds.
9. Revocation MUST invalidate outstanding payment authority at execution time.
10. Audit evidence MUST include decision reasons and state transition before/after values.
11. Cross-organization data and provider accounts MUST be isolated.
12. Unsupported protocol versions MUST fail closed; no silent downgrade.

## Agent Card and discovery

A Paari installation publishes its protocol descriptor at `/.well-known/paari`. The response advertises protocol version, registration, authentication and payment endpoints, algorithms and Paari's public verification key. External clients SHOULD use the `/v1/...` endpoints; legacy unversioned endpoints are compatibility surfaces only.

The canonical v1 Agent Card is available at `/v1/agents/{agent_id}/card` and is Paari-signed. Its endpoint references use the versioned `/v1/...` surface. Its capabilities and limits are descriptive discovery claims; the authoritative spending permission remains the parent-signed Delegation and the per-transaction Bounded Authorization. The JSON schema is `schemas/paari-agent-card.v1.schema.json`.

## JSON Schemas

- Agent Card: `schemas/paari-agent-card.v1.schema.json`
- Envelope: `schemas/paari-envelope.v1.schema.json`
- Payment Intent: `schemas/paari-payment-intent.v1.schema.json`
- Credential: `schemas/paari-credential.v1.schema.json`
- Session: `schemas/paari-session.v1.schema.json`
- Bounded Authorization: `schemas/paari-bounded-authorization.v1.schema.json`
- Consume: `schemas/paari-consume.v1.schema.json`
- MFA: `schemas/paari-mfa.v1.schema.json`
- Reconcile: `schemas/paari-reconcile.v1.schema.json`
- Webhook: `schemas/paari-webhook.v1.schema.json`
- Revocation: `schemas/paari-revocation.v1.schema.json`
- Discovery: `schemas/paari-discovery.v1.schema.json`
- Parent Trust: `schemas/paari-parent-trust.v1.schema.json`
- Delegation: `schemas/paari-delegation.v1.schema.json`
- Governance Decision: `schemas/paari-governance-decision.v1.schema.json`
- Payment Result: `schemas/paari-payment-result.v1.schema.json`
- Audit Record: `schemas/paari-audit-record.v1.schema.json`
- Proof Bundle: `schemas/paari-proof-bundle.v1.schema.json`

## Interoperability

An external agent needs only the published protocol descriptor, its own Ed25519 key pair, a parent-signed delegation, and the HTTP client needed to call Paari. It must not import Paari's application modules.
