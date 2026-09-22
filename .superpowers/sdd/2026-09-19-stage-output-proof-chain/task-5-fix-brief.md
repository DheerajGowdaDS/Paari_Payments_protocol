# Fix brief — Final-review findings, single wave (read first; requirements verbatim)

## Where this fits
Tasks 1–4 complete, suite 80 passed / 1 skipped. The final review returned Fix-required: the collector's output must actually satisfy the schemas, plus guards and enum truth. You apply ALL fixes below, add one enforcement test, and keep the suite green. No new dependencies, no git commands, no secrets.

## Fix list (all MUST be done)

### F1. `schemas/paari-payment-result.v1.schema.json`
Read `app/transitions.py` (transition table + terminal states constant). Set `final_state` to an enum of the canonical state keys; replace the example value `SETTLED` with `PAID`; keep `terminal` boolean but add `"description": "Derived by the collector from the canonical terminal set; never set independently"`.

### F2. `schemas/paari-parent-trust.v1.schema.json`
Read `app/models.py` ParentStatus enum + trust_tier column/comment. Set `status` enum to the canonical values (must include `pending_verification` and `rejected`, not just active/suspended/revoked) and `trust_tier` enum to the canonical tiers (must include `self_asserted` and `admin_approved`). Update the example to `status: pending_verification, trust_tier: self_asserted`.

### F3. `app/proof_bundle.py` — delegation timestamps
Emit `issued_at`/`expires_at` as int epoch seconds (canonical signing form), not `.isoformat()` strings.

### F4. `app/proof_bundle.py` — delegation None guard
`if delegation is None: raise ValueError("unknown delegation for agent ...")` matching the existing ValueError style for intent/agent.

### F5. `app/proof_bundle.py` — credential selection
Replace `.one()` with `.order_by(issued_at.desc()).first()` + explicit None check raising ValueError (rotation leaves multiple rows via `superseded_by`).

### F6. `app/proof_bundle.py` — transaction_id collision
`transaction_id` is not unique (only `(agent_id, idempotency_key)` is). Count matches: if > 1, raise `ValueError("ambiguous transaction_id ...")`. Never silently pick first.

### F7. `app/proof_bundle.py` — complete all DB-available required keys
Add every required key the database actually holds (all columns verified to exist):
- delegation: add `parent_id` (from `parent.parent_id`).
- governance_decision: add `agent_id`, `transaction_id`, `mfa_required`.
- bounded_authorization: add `agent_id`, `merchant`, `amount_minor_units`, `currency`, `expires_at` (isoformat string is fine here — bounded-auth schema uses string timestamps; CHECK the schema first), `max_usage`.
- payment_result: add `authorization_id`, `transaction_id`, `provider` (`"razorpay"`), `provider_order_id`.
- credential/agent_card/authentication/discovery: read `schemas/paari-credential/agent-card/session/discovery.v1.schema.json` required lists and add every required key available from the Agent/Credential/parent rows (e.g. card: status, public_key, capabilities, limits, expiry). For any required key fundamentally unavailable at collection time, do NOT invent data — handle per F8.
- audit inner events: add `actor` (from `agent_id`), `transaction_id`, `reasons` (from `detail.get("reasons", [])`).

### F8. Nullable-where-honest schema relaxations (only these; update descriptions + keep examples covering the keys)
- `paari-delegation.v1.schema.json`: `signature_b64` → `type: ["string", "null"]`, description "Null in stored/bundled records: Paari verifies the parent signature at registration and does not retain it."
- `paari-payment-result.v1.schema.json`: `webhook_event` → `type: ["string", "null"]`, description "Null until the first provider webhook arrives."
- `paari-proof-bundle.v1.schema.json`: `bounded_authorization`, `payment_execution`, `payment_result` artifact slots → `type: ["object", "null"]` (null on DENY/REVIEW intents with no authorization).

### F9. `schemas/paari-audit-record.v1.schema.json` — chain shape
The collector emits one record with an `events` list but the schema describes a single event. Change required to `["protocol", "protocol_version", "transaction_id", "events"]` where `events` items carry the single-event shape (`event_id`, `event_type`, `actor`, `previous_state`, `current_state`, `reasons`, `prev_hash`, `event_hash`; all nullable-state-tolerant). Update the example to a two-event chain where the second event's `prev_hash` equals the first's `event_hash`.

### F10. Terminal derivation
Read the canonical terminal constant in `app/transitions.py` and use it: `terminal = state in <THAT_CONSTANT>`. Do not hardcode `("PAID", "FAILED")`.

### F11. Enforcement test — append to `tests/test_proof_bundle.py` verbatim:

```python
def test_bundle_sections_satisfy_schema_required_keys(paari_client):
    import json
    import pathlib
    from tests.conftest import make_intent
    from app.proof_bundle import collect_proof_bundle
    ctx = paari_client
    intent = make_intent(ctx, amount=100)
    db = ctx.Session()
    try:
        bundle = collect_proof_bundle(db, intent["transaction_id"])
    finally:
        db.close()
    schema_dir = pathlib.Path("schemas")
    section_to_schema = {
        "parent_trust": "paari-parent-trust.v1.schema.json",
        "delegation": "paari-delegation.v1.schema.json",
        "governance_decision": "paari-governance-decision.v1.schema.json",
        "payment_result": "paari-payment-result.v1.schema.json",
        "audit_record": "paari-audit-record.v1.schema.json",
    }
    for section, schema_name in section_to_schema.items():
        schema = json.loads((schema_dir / schema_name).read_text())
        node = bundle["artifacts"][section]
        assert node is not None, f"{section} unexpectedly null"
        for key in schema["required"]:
            assert key in node, f"{section} missing required key {key}"
```

(If `make_intent` amount=100 yields a provider row with no webhook yet, `webhook_event` will be None — allowed by F8; presence is what's asserted.)

## Verify
Run: `pytest tests/test_proof_bundle.py tests/test_proof_chain.py tests/test_schemas.py -v`, then `pytest -q`. Expected: full suite green (80 + 1 new = 81 passed, 1 skipped).

## Report contract
Append your fix report to `.superpowers/sdd/2026-09-19-stage-output-proof-chain/task-5-fix-report.md` (per-fix file:line references + test outputs). Reply with only: status (DONE / DONE_WITH_CONCERNS / NEEDS_CONTEXT / BLOCKED), the test summary line, and any concerns.
