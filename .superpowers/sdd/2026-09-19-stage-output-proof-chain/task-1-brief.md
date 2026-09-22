# Task 1 brief — Stage-artifact JSON schemas (read this first; it is your requirements, with exact values to use verbatim)

## Where this fits
Paari is a trust/governance layer between AI agents and payments (FastAPI + SQLAlchemy, Python 3.11). The blueprint requires every protocol stage to emit a schema-pinned, machine-readable artifact. 12 schemas already exist in `schemas/`; you add the 6 missing stage-artifact schemas plus a conformance test. No endpoint or protocol changes.

## Global constraints (binding)
- Python 3.11, no new third-party dependencies (stdlib `json` only).
- New schemas live in `schemas/`, named exactly as listed, draft 2020-12, with `examples`, matching the pattern in `schemas/paari-discovery.v1.schema.json` (read it first: `$schema`, `$id`, `title`, `required`, `properties`, `additionalProperties: false`, `examples`).
- Full suite must stay green (baseline: 76 passed, 1 skipped). Run with `pytest -q`.
- Never write secrets, `.pem`, `.key`, `.db`, or `.env` content into new files.
- This working tree is NOT a git repo: do NOT run git commands. Implement, test, self-review, report.

## Steps (TDD, do exactly these)

### Step 1: Write the failing test — append to `tests/test_schemas.py`:

```python
STAGE_SCHEMAS = [
    "paari-parent-trust.v1.schema.json",
    "paari-delegation.v1.schema.json",
    "paari-governance-decision.v1.schema.json",
    "paari-payment-result.v1.schema.json",
    "paari-audit-record.v1.schema.json",
    "paari-proof-bundle.v1.schema.json",
]

def test_stage_artifact_schemas_exist_with_required_and_example():
    for name in STAGE_SCHEMAS:
        path = SCHEMA_DIR / name
        assert path.exists(), f"missing schema {name}"
        data = json.loads(path.read_text())
        assert data["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert isinstance(data["required"], list) and len(data["required"]) > 0
        assert "examples" in data and len(data["examples"]) > 0
        example = data["examples"][0]
        for key in data["required"]:
            assert key in example, f"{name} example missing required key {key}"
```

(`SCHEMA_DIR` and `json` are already imported/defined in that file.)

### Step 2: Run test to verify it fails
Run: `pytest tests/test_schemas.py::test_stage_artifact_schemas_exist_with_required_and_example -v`
Expected: FAIL with "missing schema paari-parent-trust.v1.schema.json"

### Step 3: Write the six schema files in `schemas/`, following the discovery-schema pattern. Full content for the governance-decision schema:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://paari.example/schemas/paari-governance-decision.v1.schema.json",
  "title": "Paari Governance Decision v1.0",
  "type": "object",
  "required": ["protocol", "protocol_version", "intent_id", "agent_id", "transaction_id", "decision", "reasons", "policy_results", "mfa_required"],
  "properties": {
    "protocol": {"const": "paari"},
    "protocol_version": {"const": "1.0"},
    "intent_id": {"type": "string", "minLength": 1},
    "agent_id": {"type": "string", "minLength": 1},
    "transaction_id": {"type": "string", "minLength": 1},
    "decision": {"enum": ["allow", "review", "deny"]},
    "reasons": {"type": "array", "items": {"type": "string"}},
    "policy_results": {"type": "array", "items": {"type": "object", "required": ["name", "passed"], "properties": {"name": {"type": "string"}, "passed": {"type": "boolean"}, "detail": {"type": "string"}}}},
    "mfa_required": {"type": "boolean"}
  },
  "additionalProperties": false,
  "examples": [
    {
      "protocol": "paari",
      "protocol_version": "1.0",
      "intent_id": "intent-9f2c",
      "agent_id": "agent-7d1a",
      "transaction_id": "TXN-proof-f45a2f45",
      "decision": "allow",
      "reasons": ["all checks passed"],
      "policy_results": [{"name": "delegation_active", "passed": true, "detail": ""}],
      "mfa_required": false
    }
  ]
}
```

The other five schemas use the same shape with these `required` key lists (define matching `properties` + one `examples[0]` covering every required key):
- `paari-parent-trust.v1.schema.json`, title "Paari Parent Trust Record v1.0", `$id` `https://paari.example/schemas/paari-parent-trust.v1.schema.json`, required: `["protocol", "protocol_version", "parent_id", "status", "trust_tier"]`
- `paari-delegation.v1.schema.json`, title "Paari Signed Delegation v1.0", required: `["protocol", "protocol_version", "delegation_id", "parent_id", "agent_public_key_fingerprint", "granted_capabilities", "payment_limit_minor_units", "currency", "issued_at", "expires_at", "signature_b64"]`
- `paari-payment-result.v1.schema.json`, title "Paari Payment Result v1.0", required: `["protocol", "protocol_version", "authorization_id", "transaction_id", "provider", "provider_order_id", "webhook_event", "webhook_verified", "final_state", "terminal"]`
- `paari-audit-record.v1.schema.json`, title "Paari Audit Record v1.0", required: `["protocol", "protocol_version", "event_id", "event_type", "transaction_id", "actor", "previous_state", "current_state", "reasons", "prev_hash", "event_hash"]`
- `paari-proof-bundle.v1.schema.json`, title "Paari Proof Bundle v1.0", required: `["protocol", "protocol_version", "bundle_id", "transaction_id", "created_at", "artifacts"]`, where `artifacts` is an object requiring the 14 keys: `discovery, parent_trust, delegation, agent_identity, agent_card, credential, authentication, payment_intent, governance_decision, bounded_authorization, payment_execution, payment_result, audit_record, revocation`.

### Step 4: Run tests to verify they pass
Run: `pytest tests/test_schemas.py -v`
Expected: all PASS.

### Step 5: Run full suite for no regressions
Run: `pytest -q`
Expected: 76 passed, 1 skipped.

## Report contract
Write your full report to `.superpowers/sdd/2026-09-19-stage-output-proof-chain/task-1-report.md` (what you did, test commands + outputs, self-review findings). Reply with only: status (DONE / DONE_WITH_CONCERNS / NEEDS_CONTEXT / BLOCKED), the test summary line, and any concerns.
