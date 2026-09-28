# Paari v1.2 — Provider-Native Autonomous Settlement

## What changed

This release completes the **protocol-level autonomous settlement path** while
preserving a strict distinction between conformance simulation and real money:

```text
signed user mandate
  -> agent delegation + authentication
  -> governance
  -> bounded single-use authorization
  -> provider-native authorization
  -> provider capture
  -> direct provider read corroboration
  -> PAID
```

### Implemented

- Provider-native `AgenticPaymentProvider` execution path.
- Autonomous mode fails closed when no capable provider adapter is configured.
- No fallback from autonomous mode to a normal human-checkout order.
- Active provider mandate/instrument binding is revalidated at execution time.
- Inactive/expired provider references are never selected automatically.
- Provider capture endpoints are never guessed; exact provider paths must be configured.
- Explicit provider capability attestation is required before a Razorpay adapter reports autonomous capability.
- Capture-result handling distinguishes captured, pending, explicit failure and unknown outcomes.
- Payment proof now exposes a generic `provider_payment_id` in addition to legacy Razorpay order fields.
- `/health` reports the configured agentic provider and agentic provider environment.
- Added `ReferenceAutonomousProvider` for deterministic, no-human-checkout protocol conformance. It is simulated and moves no real money.
- Reworked `scripts/autonomous_payment_e2e.py`:
  - `--provider reference` proves the full autonomous protocol path to `PAID` without human checkout.
  - `--provider real-razorpay` requires a real provider-native contract and fails closed otherwise.
- Clean release packaging removes private signing keys, local databases, logs and Python caches.
- Alembic schema check passes on a fresh SQLite migration database.

## Important limitation

A provider cannot be made to expose an undocumented server-to-server debit/capture
capability by changing Paari code alone. The real Razorpay deployment therefore
remains provider-entitlement dependent. A normal Razorpay `/orders` flow is not
considered autonomous payment because it still requires checkout completion.

## Verification

Reference autonomous conformance run:

```text
MANDATE             Ed25519 signed + active
GOVERNANCE          ALLOW
AUTHORIZATION       single-use bounded
SETTLEMENT SOURCE   simulator
FINAL STATE         PAID
HUMAN CHECKOUT      NO
AUTONOMOUS PAYMENT PROTOCOL E2E GREEN
```

The reference run proves protocol behavior, not real-world money movement.
For real-money validation, configure the provider-native contract and run:

```bash
python scripts/autonomous_payment_e2e.py --provider real-razorpay
```
