# Paari Protocol v1.0 — Request/Response Examples

> Per-operation examples for the Paari v1 surface. All protected payment endpoints require `Authorization: Bearer <session>` and `X-Paari-Proof`.

---

## 1. Discover protocol

```http
GET /.well-known/paari
```

```json
{
  "protocol": "paari",
  "protocol_version": "1.0",
  "issuer": "paari",
  "service": "agentic-payment",
  "base_url": "https://paari.example",
  "discovery": {"well_known": "https://paari.example/.well-known/paari"},
  "agent_registration": "https://paari.example/v1/agents/register",
  "agent_card": "https://paari.example/v1/agents/{agent_id}/card",
  "authentication": {
    "challenge": "https://paari.example/v1/auth/challenge",
    "verify": "https://paari.example/v1/auth/verify"
  },
  "payment": {
    "intent": "https://paari.example/v1/payments/intent",
    "consume": "https://paari.example/v1/payments/authorizations/{authorization_id}/consume",
    "mfa_challenge": "https://paari.example/v1/payments/mfa/challenge",
    "mfa_verify": "https://paari.example/v1/payments/mfa/verify",
    "reconcile": "https://paari.example/v1/reconcile/{authorization_id}",
    "webhook": "https://paari.example/v1/payments/webhooks/razorpay"
  },
  "security": {
    "credential_type": "JWT-EdDSA",
    "request_proof": "Paari-Proof-JWT",
    "proof_binding": "agent-public-key",
    "mfa": "parent-authority-signature"
  },
  "algorithms": {"agent_keys": ["Ed25519"], "paari_signatures": ["Ed25519"]},
  "provider_boundary": {"execution": "Paari-controlled", "providers": ["razorpay"]},
  "conformance": {
    "spec": "https://paari.example/docs/PROTOCOL.md",
    "tests": "https://paari.example/docs/CONFORMANCE.md",
    "sdk": "sdk/paari_agent"
  },
  "paari_public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
  "rules": {
    "private_keys_never_sent_to_paari": true,
    "agent_authority_comes_from_signed_delegation": true,
    "payment_authorization_is_single_use": true,
    "settlement_requires_provider_verification": true
  }
}
```

---

## 2. Register agent

```http
POST /v1/agents/register
Content-Type: application/json

{
  "envelope": {
    "protocol": "paari",
    "version": "1.0",
    "type": "agent.register",
    "message_id": "uuid",
    "sender": "agent-fingerprint",
    "receiver": "paari",
    "issued_at": 1726680000,
    "expires_at": 1726680120,
    "payload": {
      "name": "Shopping Assistant",
      "agent_type": "assistant",
      "purpose": "buy groceries",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
      "delegation": {
        "delegation_id": "deleg-123",
        "parent_id": "parent-456",
        "agent_public_key_fingerprint": "sha256-hex",
        "granted_capabilities": ["make_payment"],
        "payment_limit_minor_units": 500000,
        "currency": "INR",
        "issued_at": 1726680000,
        "expires_at": 1758216000
      }
    },
    "signature": "base64-ed25519"
  }
}
```

```json
{
  "agent_card": {
    "protocol": "paari",
    "protocol_version": "1.0",
    "issuer": "paari",
    "agent_id": "agent-789",
    "name": "Shopping Assistant",
    "agent_type": "assistant",
    "parent_id": "parent-456",
    "status": "active",
    "public_key": "-----BEGIN PUBLIC KEY-----\n...",
    "capabilities": ["payment.create"],
    "limits": {"max_amount": 500000, "currency": "INR"},
    "credential_id": "cred-abc",
    "expires_at": "2026-09-18T10:00:00Z",
    "endpoints": {
      "protocol_discovery": "/.well-known/paari",
      "agent_card": "/v1/agents/agent-789/card",
      "payment_intent": "/v1/payments/intent",
      "consume": "/v1/payments/authorizations/{authorization_id}/consume"
    },
    "card_signature_b64": "base64-signature",
    "paari_public_key_pem": "-----BEGIN PUBLIC KEY-----\n..."
  },
  "credential_jwt": "eyJhbGciOiJFZERTQSIsInR5cCI6Ik...",
  "credential_expires_at": "2026-09-18T10:00:00Z"
}
```

---

## 3. Challenge / Verify

```http
POST /v1/auth/challenge
Content-Type: application/json

{
  "agent_id": "agent-789"
}
```

```json
{
  "nonce": "nonce-abc-123",
  "expires_at": "2026-09-18T10:02:00Z"
}
```

```http
POST /v1/auth/verify
Content-Type: application/json
Authorization: Bearer <credential_jwt>

{
  "agent_id": "agent-789",
  "nonce": "nonce-abc-123",
  "signature_b64": "base64-ed25519",
  "credential_jwt": "eyJhbGciOiJFZERTQSIsInR5cCI6Ik..."
}
```

```json
{
  "authenticated": true,
  "session_token": "eyJhbGciOiJFZERTQSIsInR5cCI6Ik...",
  "expires_at": "2026-09-18T10:15:00Z",
  "granted_capabilities": ["payment.create"],
  "payment_limit_minor_units": 500000
}
```

---

## 4. Payment Intent — ALLOW

```http
POST /v1/payments/intent
Content-Type: application/json
Authorization: Bearer <session_token>
X-Paari-Proof: <Paari-Proof-JWT>

{
  "agent_id": "agent-789",
  "transaction_id": "TXN-001",
  "idempotency_key": "idem-TXN-001",
  "merchant": "Acme Store",
  "amount_minor_units": 1000,
  "currency": "INR",
  "action": "make_payment",
  "purpose": "groceries"
}
```

```json
{
  "intent_id": "intent-123",
  "decision": "allow",
  "reasons": ["all checks passed"],
  "mfa_required": false,
  "authorization": {
    "authorization_id": "auth-123",
    "token": "eyJhbGciOiJFZERTQSIsInR5cCI6Ik...",
    "expires_at": "2026-09-18T10:05:00Z",
    "max_usage": 1,
    "amount_minor_units": 1000,
    "currency": "INR",
    "merchant": "Acme Store",
    "transaction_id": "TXN-001"
  },
  "review_expires_at": null
}
```

---

## 5. Payment Intent — REVIEW

```json
{
  "intent_id": "intent-456",
  "decision": "review",
  "reasons": ["amount close to delegated limit - step-up approval required"],
  "mfa_required": true,
  "authorization": null,
  "review_expires_at": "2026-09-18T10:10:00Z"
}
```

---

## 6. MFA Challenge / Verify

```http
POST /v1/payments/mfa/challenge
Content-Type: application/json
Authorization: Bearer <session_token>
X-Paari-Proof: <Paari-Proof-JWT>

{
  "intent_id": "intent-456",
  "session_token": "<session_token>"
}
```

```json
{
  "challenge_id": "challenge-789",
  "intent_id": "intent-456",
  "nonce": "nonce-mfa-123",
  "context_to_sign": "{\"purpose\":\"paari_mfa_step_up\",\"challenge_id\":\"challenge-789\",\"intent_id\":\"intent-456\",\"agent_id\":\"agent-789\",\"transaction_id\":\"TXN-002\",\"merchant\":\"Acme Store\",\"amount_minor_units\":480000,\"currency\":\"INR\",\"nonce\":\"nonce-mfa-123\"}",
  "expires_at": "2026-09-18T10:10:00Z"
}
```

```http
POST /v1/payments/mfa/verify
Content-Type: application/json

{
  "intent_id": "intent-456",
  "challenge_id": "challenge-789",
  "parent_signature_b64": "base64-ed25519"
}
```

```json
{
  "intent_id": "intent-456",
  "decision": "allow",
  "reasons": ["all checks passed", "step-up approval verified via parent-authority signature"],
  "mfa_required": true,
  "authorization": {
    "authorization_id": "auth-456",
    "token": "eyJhbGciOiJFZERTQSIsInR5cCI6Ik...",
    "expires_at": "2026-09-18T10:07:00Z",
    "max_usage": 1,
    "amount_minor_units": 480000,
    "currency": "INR",
    "merchant": "Acme Store",
    "transaction_id": "TXN-002"
  },
  "review_expires_at": null
}
```

---

## 7. Consume Authorization

```http
POST /v1/payments/authorizations/auth-123/consume
Content-Type: application/json
Authorization: Bearer <session_token>
X-Paari-Proof: <Paari-Proof-JWT>

{
  "session_token": "<session_token>"
}
```

```json
{
  "authorization_id": "auth-123",
  "consumed": true,
  "remaining_uses": 0,
  "state": "PAYMENT_PENDING",
  "razorpay_order_id": "order_abc123",
  "razorpay_payment_id": null
}
```

---

## 8. Webhook

```http
POST /v1/payments/webhooks/razorpay
Content-Type: application/json
X-Razorpay-Signature: <hmac-sha256>

{
  "event": "payment.captured",
  "payload": {
    "payment": {
      "entity": {
        "id": "pay_abc123",
        "order_id": "order_abc123",
        "amount": 1000,
        "currency": "INR",
        "status": "captured"
      }
    }
  },
  "id": "evt_webhook_123"
}
```

```json
{
  "status": "applied",
  "state": "PAID"
}
```

---

## 9. Reconcile

```http
POST /v1/reconcile/auth-123
Content-Type: application/json
Authorization: Bearer <session_token>
X-Paari-Proof: <Paari-Proof-JWT>

{
  "session_token": "<session_token>"
}
```

```json
{
  "status": "reconciled",
  "state": "PAID"
}
```

---

## 10. Revoke Authorization

```http
POST /v1/authorizations/auth-123/revoke
Content-Type: application/json
Authorization: Bearer <session_token>
X-Paari-Proof: <Paari-Proof-JWT>

{
  "session_token": "<session_token>"
}
```

```json
{
  "authorization_id": "auth-123",
  "revoked": true
}
```

---

## 11. Rotate Agent Key

```http
POST /v1/agents/agent-789/rotate-key
Content-Type: application/json
X-Admin-Api-Key: <admin_key>

{
  "new_public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
  "delegation": {
    "delegation_id": "deleg-rot-123",
    "parent_id": "parent-456",
    "agent_public_key_fingerprint": "new-sha256-hex",
    "granted_capabilities": ["make_payment"],
    "payment_limit_minor_units": 500000,
    "currency": "INR",
    "issued_at": 1726680000,
    "expires_at": 1758216000
  },
  "delegation_signature_b64": "base64-ed25519"
}
```

```json
{
  "agent_id": "agent-789",
  "credential_jwt": "eyJhbGciOiJFZERTQSIsInR5cCI6Ik...",
  "credential_expires_at": "2026-09-18T10:00:00Z",
  "key_sunset_at": "2026-09-19T10:00:00Z"
}
```

---

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
