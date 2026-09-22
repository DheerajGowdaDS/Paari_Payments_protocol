# Fix report — Final-review findings, single wave (F1–F11)

All fixes applied exactly per `task-5-fix-brief.md`. Sources read before editing:
`app/transitions.py` (TRANSITION_TABLE keys + `TERMINAL_STATES`, line 30),
`app/models.py` (`ParentStatus` enum lines 53–58, `trust_tier` column/comment lines 128–131),
all cited schemas in `schemas/`.

## Per-fix references

- **F1** `schemas/paari-payment-result.v1.schema.json:16` — `final_state` is now
  `{"enum": ["AUTHORIZED", "PROVIDER_SUBMITTED", "PAYMENT_PENDING", "PROVIDER_UNKNOWN", "FAILED", "PAID", "REFUNDED", "REVERSED", "EXPIRED", "CANCELLED"]}`
  (all 10 `TRANSITION_TABLE` keys from `app/transitions.py:9-27`); example
  `final_state` `SETTLED` → `PAID` (line 30); `terminal` kept boolean with
  description `Derived by the collector from the canonical terminal set; never set independently` (line 17).
- **F2** `schemas/paari-parent-trust.v1.schema.json:11-12` — `status` enum set to
  the canonical `ParentStatus` values from `app/models.py:53-58`
  (`pending_verification`, `active`, `rejected`, `suspended`, `revoked`);
  `trust_tier` enum set to the canonical tiers from `app/models.py:128-131`
  (`self_asserted`, `admin_approved`, `kyb_verified`); example updated to
  `status: pending_verification, trust_tier: self_asserted` (lines 20–21).
- **F3** `app/proof_bundle.py:173-174` — delegation `issued_at`/`expires_at`
  emitted as `int(...timestamp())` epoch seconds (canonical signing form),
  matching the delegation schema's `{"type": "integer"}`.
- **F4** `app/proof_bundle.py:44-45` —
  `if delegation is None: raise ValueError(f"unknown delegation for agent {agent.agent_id}")`,
  matching the existing `unknown transaction_id` / `unknown agent` ValueError style.
- **F5** `app/proof_bundle.py:47-55` — credential lookup `.one()` replaced with
  `.order_by(Credential.issued_at.desc()).first()` + explicit None check raising
  `ValueError(f"unknown credential for agent ...")` (rotation leaves multiple rows via `superseded_by`).
- **F6** `app/proof_bundle.py:21-32` — `transaction_id` matches counted via `.all()`:
  0 → `ValueError("unknown transaction_id: ...")`; > 1 →
  `ValueError(f"ambiguous transaction_id: {transaction_id}")` (only
  `(agent_id, idempotency_key)` is unique per `app/models.py:267-269`). Never silently picks first.
- **F7** `app/proof_bundle.py` — DB-available required keys added:
  - delegation: `parent_id` from `parent.parent_id` (line 168);
  - governance_decision: `agent_id`, `transaction_id`, `mfa_required` (lines 234–238);
  - bounded_authorization: `agent_id`, `merchant`, `amount_minor_units`, `currency`,
    `expires_at` (isoformat string — bounded-auth schema uses `{"type": "string", "format": "date-time"}`), `max_usage` (lines 125–133);
  - payment_result: `authorization_id`, `transaction_id`, `provider` (`"razorpay"`),
    `provider_order_id` (lines 147–150);
  - agent_card: `issuer`, `name`, `agent_type`, `parent_id`, `status`, `public_key`,
    `capabilities`, `limits` (`max_amount`/`currency`), `expires_at` (lines 180–201);
  - credential: `capabilities`, `payment_limit_minor_units`, `currency` from the Agent row (lines 212–214);
  - audit inner events: `actor` (from `agent_id`), `transaction_id`,
    `reasons` (from `detail.get("reasons", [])`) (lines 104–113);
  - audit_record: top-level `transaction_id` (line 245).
  - NOT invented (no DB source at collection time, left absent): card `endpoints`,
    `card_signature_b64`, `paari_public_key_pem`; credential-JWT claims (`iss`/`aud`/`sub`/`jti`/`iat`/`exp`/`typ`)
    for the status-shaped credential section — see concerns.
- **F8** nullable-where-honest relaxations (only these):
  - `schemas/paari-delegation.v1.schema.json:18` — `signature_b64` →
    `{"type": ["string", "null"], "minLength": 1}` with description
    `Null in stored/bundled records: Paari verifies the parent signature at registration and does not retain it.`
  - `schemas/paari-payment-result.v1.schema.json:14` — `webhook_event` →
    `{"type": ["string", "null"], "minLength": 1}` with description
    `Null until the first provider webhook arrives.`
  - `schemas/paari-proof-bundle.v1.schema.json:26-28` — `bounded_authorization`,
    `payment_execution`, `payment_result` artifact slots → `{"type": ["object", "null"]}`
    (null on DENY/REVIEW intents with no authorization). Examples kept covering the keys.
- **F9** `schemas/paari-audit-record.v1.schema.json` (full rewrite) — top-level required is now
  `["protocol", "protocol_version", "transaction_id", "events"]`; `events` items carry
  `event_id`, `event_type`, `actor`, `previous_state`, `current_state`, `reasons`,
  `prev_hash`, `event_hash` (plus optional `transaction_id`), with `previous_state`/`current_state`
  nullable-tolerant (`["string", "null"]`); example is a two-event chain where the second
  event's `prev_hash` (`9f2c4a1b77aa55ee01d3c4b5a6f70899`) equals the first's `event_hash`.
- **F10** `app/proof_bundle.py:11,154` — `terminal = provider_txn.state in TERMINAL_STATES`
  imported from `app.transitions` (canonical constant at `app/transitions.py:30`); no hardcoded tuple.
- **F11** `tests/test_proof_bundle.py:27-55` — enforcement test
  `test_bundle_sections_satisfy_schema_required_keys` appended verbatim.

## Test outputs

- Targeted: `pytest tests/test_proof_bundle.py tests/test_proof_chain.py tests/test_schemas.py -v`
  → **8 passed** (incl. the new enforcement test).
- Full: `pytest -q` → **81 passed, 1 skipped** (was 80 passed / 1 skipped; +1 new test, all green).

## Concerns (brief governs; flagged, not improvised)

1. `provider_order_id` has no null allowance (F8 only relaxes `webhook_event`), but a freshly
   minted ALLOW intent has `razorpay_order_id=None` until provider submission — the collector emits
   the key with a null value (presence asserted by F11; strict type validation would fail pre-webhook/submission).
2. `agent_card`/`credential`/`authentication`/`discovery` bundle sections remain best-effort:
   card `endpoints`/`card_signature_b64`/`paari_public_key_pem` and JWT-claim-shaped credential keys
   are fundamentally unavailable at collection time, so those sections do not strictly validate
   (no F8 relaxation covers them). F11 does not assert on them.
3. Audit `events` items keep `kind`/`detail` extras alongside the F9 shape; the items schema does not
   set `additionalProperties: false`, so extras are schema-legal.
