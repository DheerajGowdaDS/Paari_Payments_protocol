# Paari Protocol v1.0 Conformance

A conforming external agent MUST:

1. Discover `GET /.well-known/paari` and select `protocol_version: 1.0`.
2. Own an Ed25519 key pair; never send the private key to Paari.
3. Obtain a parent-signed delegation bound to the exact public-key fingerprint.
4. Send a signed `agent.register` envelope to `/v1/agents/register`.
5. Verify the Paari-signed Agent Card before storing it as trusted metadata.
6. Authenticate with challenge/response and retain the short-lived session token.
7. Send payment requests with `Authorization: Bearer <session>` and `X-Paari-Proof`.
8. Use a unique idempotency key per payment intent.
9. Execute only a Paari-issued single-use Bounded Authorization.
10. Treat `ALLOW`, `REVIEW`, and `DENY` as normative outcomes.
11. Never infer settlement from the agent/client response; settlement requires provider-confirmed webhook or reconciliation.
12. Treat revocation, replay, expiry, value mismatch, cross-tenant access, and unsupported versions as fail-closed errors.
13. Treat `GET /v1/proof/{transaction_id}` as read-only evidence: it never settles a payment, and a conforming client MUST present the same sender-constrained `X-Paari-Proof` it uses for payment requests when its session was onboarded under protocol v1.0.

## Required interoperability tests

- valid registration and authentication
- signed-card verification
- wrong-key rejection
- expired credential/session rejection
- request-proof replay rejection
- path/method binding rejection
- over-limit and wrong-currency denial
- bounded-authorization double-consume rejection
- parent/agent revocation blocking
- webhook signature/value mismatch rejection
- webhook replay idempotency
- provider-unknown reconciliation
- cross-organization isolation
- proof-bundle retrieval: owner-scoped, and rejected without a request proof for a v1 session
