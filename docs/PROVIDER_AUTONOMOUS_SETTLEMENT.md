# Paari Provider-Native Autonomous Settlement

## Goal

This extension makes the **Paari protocol path** capable of completing a
payment without a browser checkout or human capture step when the underlying
payment provider exposes a user-consented, provider-recognized mandate or
payment instrument.

The security boundary is:

```text
User / Trusted Surface
        |
        v
Signed User Payment Mandate
        |
        v
Parent Delegation + Agent Identity
        |
        v
Paari Governance
        |
        v
Single-use Bounded Authorization
        |
        v
Provider-native mandate / token reference
        |
        +--> authorize exact payment
        |
        +--> capture / provider settlement
        |
        +--> direct provider read corroborates amount + currency + captured
        |
        v
PAID
```

## Protocol contract

`app.providers.agentic.AgenticPaymentProvider` defines the provider-native
operations:

- `create_or_bind_mandate`
- `validate_mandate`
- `authorize_payment`
- `capture_payment`
- `get_payment`
- `verify_webhook`
- `revoke_mandate`
- `supports_autonomous_settlement`

The agent never receives raw card numbers, CVV, UPI PINs, bank passwords,
provider secrets, or Paari private signing keys. Only provider-issued
references may be stored in `PaymentInstrumentBinding`.

## Fail-closed behavior

When `PAARI_MODE=autonomous`:

1. A valid active signed user mandate is required.
2. The provider binding must be active and inside its validity window.
3. The provider-native adapter must explicitly report autonomous capability.
4. Paari does **not** create a normal checkout order as a fallback.
5. Provider payment state must be corroborated before Paari emits `PAID`.
6. A timeout or ambiguous provider response becomes `PROVIDER_UNKNOWN` and is
   reconciled later.
7. A known provider rejection is recorded as a failure/decline, never `PAID`.
8. Provider endpoints are never guessed from naming conventions.

## Reference conformance provider

`app/providers/reference_autonomous.py` is an intentionally in-memory provider.
It executes the full autonomous protocol state machine and reaches `PAID` without
human intervention, but it moves **no real money**.

Run:

```bash
python scripts/autonomous_payment_e2e.py --provider reference
```

Expected final section:

```text
SETTLEMENT SOURCE   simulator
FINAL STATE         PAID
HUMAN CHECKOUT      NO

AUTONOMOUS PAYMENT PROTOCOL E2E GREEN
```

The result proves the Paari protocol state machine, authorization boundaries,
replay protection, audit chain, and no-human-checkout execution path. It does
not prove that a real payment provider moved money.

## Real provider adapter

`app/providers/razorpay_agentic.py` is the concrete provider seam for Razorpay.
It is intentionally conservative:

```text
RAZORPAY_KEY_ID
RAZORPAY_KEY_SECRET
RAZORPAY_AGENTIC_CAPABILITY_CONFIRMED=1
RAZORPAY_AGENTIC_AUTHORIZE_PATH=<exact documented path>
RAZORPAY_AGENTIC_PAYMENT_PATH=<exact documented payment-read path>
```

Tokenized recurring mode also requires an exact documented token-list path.
A capture path must be explicitly supplied when the provider contract does not
auto-capture:

```text
RAZORPAY_AGENTIC_TOKEN_LIST_PATH=<exact documented path>
RAZORPAY_AGENTIC_CAPTURE_PATH=<exact documented capture path>
```

The adapter refuses to claim autonomous capability when these requirements are
not satisfied. A normal Razorpay `/orders` checkout flow is never interpreted as
provider-native autonomous settlement.

Run:

```bash
python scripts/autonomous_payment_e2e.py --provider real-razorpay
```

This mode is expected to fail closed until the real account has the required
provider-native mandate/debit capability and exact documented endpoints.

## State machine

```text
AUTHORIZED
    |
    v
PROVIDER_SUBMITTED
    |
    v
PROVIDER_AUTHORIZED
    |
    v
CAPTURED
    |
    +--> direct provider read corroborates --> PAID
    |
    +--> ambiguous provider state -------> PROVIDER_UNKNOWN
    |
    +--> provider rejection --------------> FAILED / DECLINED
```

`PAID` is a Paari conclusion, not merely a client claim. The provider response
must match the exact amount and currency authorized by Paari.

## Evidence

The payment proof bundle includes:

- `provider_environment`
- `provider_api_base`
- `provider_payment_id`
- `provider_order_id` when applicable
- `settlement_source`
- final payment state
- the hash-verified audit chain

For the reference provider, `settlement_source=simulator`. For a genuine
provider-backed result, the recorded environment must be `test` or `live` and
the settlement source is `provider`.

## Real-LLM path

The protocol conformance harness is deterministic. The real model execution
path remains separate:

```bash
python scripts/llm_agent_e2e.py --with-server --require-mandate
```

The model is outside the cryptographic trust boundary. Paari remains the
authority that verifies the signed mandate, delegated agent identity, limits,
and bounded authorization before the provider-native execution path is called.
