# Paari v1.1 extension — User Payment Authority

## Added

- `UserPaymentMandate` model and Alembic migration.
- Per-transaction and daily mandate limits.
- Currency, merchant and category constraints.
- Review threshold and validity/revocation checks.
- Server-derived mandate binding on `PaymentIntent` and `BoundedAuthorization`.
- Execution-time mandate revalidation.
- Provider reference-only `PaymentInstrumentBinding` model.
- Provider-neutral `AgenticPaymentProvider` interface.
- LLM `get_payment_authority` tool.
- Proof-bundle user-mandate evidence artifact.
- `--require-mandate` E2E harness option.
- Clean `.env.example` without credentials.

## Deliberate non-change

The existing Razorpay adapter still implements the real Test-Mode order and
checkout/webhook path. This release does **not** fabricate or claim autonomous
capture. A provider-native agentic settlement adapter requires the provider's
actual documented API/sandbox capability.

## Validation

- `pytest -q -p no:warnings` → **138 passed, 1 skipped**.
- `python scripts/llm_agent_e2e.py --rehearse --with-server --require-mandate` →
  mandate bootstrap, authority read, governance and audit proof passed; real
  provider submission was skipped because this was rehearsal mode.
