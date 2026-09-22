# Paari Security Model v1.0

## Security objective

Paari is a trust and governance control plane between an AI agent and a payment provider. An agent never receives standing payment authority. Money movement requires a current identity, valid delegated authority, governance approval, and a bounded, short-lived, single-use authorization.

## Trust model

```text
Parent Authority
  -> signed delegation
  -> agent public-key binding
  -> Paari Agent Card + Credential
  -> proof-of-possession session
  -> sender-constrained Paari-Proof-JWT
  -> payment intent
  -> governance
  -> bounded authorization
  -> provider execution
```

### Roots and secrets

- Agent private keys stay with the agent.
- Parent private keys stay with the parent authority.
- Paari's signing key is server-side and must be stored in managed secret/KMS/HSM infrastructure in production.
- Razorpay credentials and webhook secrets are server-side only and are never accepted from clients.

## Payment security invariants

1. **Authority provenance:** capabilities, limit, currency, and delegation expiry come from a valid parent-signed delegation; agent-requested permissions are never authoritative.
2. **Sender binding:** v1 protected requests require a Paari-Proof-JWT signed by the registered agent key and bound to the session token, HTTP method, exact path, timestamp, and one-time JTI. New clients SHOULD transport the session as `Authorization: Bearer`; session tokens MUST NOT be placed in URLs.
3. **Authentication freshness:** session, credential, agent, parent, and delegation status are revalidated at payment execution time.
4. **Bounded execution:** provider execution is restricted to a single-use authorization bound to agent, transaction, merchant, amount, and currency.
5. **Atomic consumption:** authorization usage is reserved with a conditional database update; check-then-set is not used.
6. **Idempotent provider submission:** the provider request uses authorization ID as the provider-side idempotency key.
7. **Provider truth:** client claims never settle a transaction. Settlement requires a verified provider response or reconciliation against provider truth.
8. **Webhook integrity:** raw-body HMAC verification is mandatory; event replay is deduplicated; provider order/amount/currency must match the bounded authorization before settlement.
9. **State integrity:** every ProviderTransaction transition passes through the central transition table; terminal `PAID` does not regress.
10. **Revocation propagation:** revoked credentials, agents, parents, expired delegations, and revoked authorizations are rejected at execution time.
11. **Tenant isolation:** data and provider credentials are organization-scoped; non-default tenants never silently fall back to another organization's provider account.
12. **Auditability:** governance decisions, authorization, provider submission, webhook/reconciliation state changes, and security events are recorded in the append-only hash chain.
13. **Fail closed:** missing provider secrets or provider ambiguity do not produce a synthetic success. Unknown provider outcomes become `PROVIDER_UNKNOWN` and require reconciliation.

## Threats covered

| Threat | Paari control |
|---|---|
| Fake/impersonated agent | Parent-signed delegation + key binding + proof-of-possession |
| Forged delegation | Parent Ed25519 signature verification |
| Agent privilege escalation | Requested capabilities ignored; only delegated capabilities apply |
| Token theft | Short-lived sessions + sender-constrained proof |
| Request replay | Nonce burn + proof JTI replay store + bounded authorization single-use |
| Amount tampering | Authorization binding + provider amount/currency checks |
| Webhook spoofing | Raw-body HMAC verification |
| Duplicate provider submission | Provider idempotency key + ProviderTransaction uniqueness |
| Cross-tenant access | `org_id` ownership + tenant provider routing |
| Revoked agent spending | Execution-time trust revalidation + authorization revoke |
| Missed webhook | Provider reconciliation |
| State regression | Central transition table |
| Audit tampering | SHA-256 hash chain |
| Provider timeout ambiguity | `PROVIDER_UNKNOWN` + reconciliation |

## Governance outcomes

- **ALLOW:** bounded authorization may be minted.
- **REVIEW:** payment is held until the configured step-up/dual-control approval is satisfied.
- **DENY:** no provider authorization is created.

## Step-up model

The current protocol uses parent-authority cryptographic approval for payment intents that require step-up. This is a dual-control mechanism between the agent key and the parent authority key. It is not an SMS/OTP human MFA product; interactive user WebAuthn or equivalent can be added as a separate high-assurance factor later.

## Protocol security

Paari v1 is versioned and fail-closed on unsupported protocol versions. Control-plane objects use canonical JSON + Ed25519 signatures. Protected payment endpoints additionally use `Paari-Proof-JWT` sender binding. See `docs/PROTOCOL.md` and the JSON schemas under `schemas/`.

## Production requirements still external to the reference implementation

- Real KYB/identity provider integration for parent authorities.
- KMS/HSM-backed Paari signing keys with operational key rotation.
- Permanent HTTPS domain and hardened webhook ingress.
- PostgreSQL in production with CI migration testing.
- Secrets manager rather than process-local configuration for high-value credentials.
- Operational monitoring, alerting, incident response, backup, restore, and disaster recovery.
