# Paari Agentic Payment Protocol v1.0 — Release Notes

## Phase 7
- Added an independent external-agent SDK under `sdk/paari_agent/`.
- Added a parent-trust provider abstraction for future real KYB/registry/IdP integration.
- Hardened live boot: PostgreSQL, provider credentials, webhook secret, admin key and persistent signing-key path are required.
- Added CI workflow and development/PostgreSQL dependency sets.
- Added protocol conformance documentation.

## Phase 8
- Added foreign-agent SDK conformance tests.
- Added adversarial tests for over-delegation/limits, wrong currency, proof replay and identity mismatch.
- Added a standalone foreign-agent SDK example.
- Updated protocol discovery to advertise the spec, conformance contract and SDK.

## Validation
- 56 automated tests passing.
- `compileall` clean for server, SDK, examples and scripts.
- All protocol JSON schemas parse successfully.

## Scope note
This release is a production-oriented protocol prototype. Real KYB vendor integration, KMS/HSM custody, stable HTTPS infrastructure, provider-account operations, monitoring and incident-response controls remain deployment responsibilities.
