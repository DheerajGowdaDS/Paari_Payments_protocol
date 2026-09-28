# Stage-Output Proof Chain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every one of the 15 protocol stages emit a schema-pinned, machine-readable artifact, add a collector that assembles all artifacts into one verifiable proof bundle, and add tests proving each stage verifies the previous stage's output.

**Architecture:** No protocol or endpoint changes. We add 6 JSON schemas alongside the existing 12, one pure collector module (`app/proof_bundle.py`) that reads DB rows and assembles the bundle, one chain-verification test module, and one docs catalog. Everything is verified offline with the existing `paari_client` fixture (isolated SQLite via Alembic).

**Tech Stack:** Python 3.11, FastAPI TestClient, SQLAlchemy session, stdlib `json` only for schema checks (no new dependencies).

## Global Constraints

- Python 3.11, no new third-party dependencies.
- New schemas live in `schemas/`, named `paari-<artifact>.v1.schema.json`, draft 2020-12, with `examples`, matching the existing pattern in `schemas/paari-discovery.v1.schema.json`.
- Tests run with `pytest -q`; full suite must stay green (baseline: 76 passed, 1 skipped).
- Never write secrets, `.pem`, `.key`, `.db`, or `.env` content into new files.
- Session tokens travel in `Authorization: Bearer` header in new tests, never in URLs.
- This working tree is not a git repo: implementers do NOT commit; they implement, test, self-review, and report. Coordination tracks progress in the SDD ledger.

---

## File structure

- Create: `schemas/paari-parent-trust.v1.schema.json` — Stage 2/3 output (parent record + trust tier).
- Create: `schemas/paari-delegation.v1.schema.json` — Stage 4 output (signed delegation).
- Create: `schemas/paari-governance-decision.v1.schema.json` — Stage 9 output (ALLOW/REVIEW/DENY + reasons + policy results).
- Create: `schemas/paari-payment-result.v1.schema.json` — Stage 11/12/13 output (order, webhook event, final state).
- Create: `schemas/paari-audit-record.v1.schema.json` — Stage 14 output (event with prev/current state + hash link).
- Create: `schemas/paari-proof-bundle.v1.schema.json` — the 14-artifact bundle envelope.
- Create: `app/proof_bundle.py` — `collect_proof_bundle(db, transaction_id) -> dict`, pure DB-read collector.
- Create: `tests/test_proof_bundle.py` — bundle structure tests.
- Create: `tests/test_proof_chain.py` — cross-stage verification tests.
- Modify: `tests/test_schemas.py` — extend coverage to new schemas + live-output conformance checks.
- Create: `docs/STAGE_OUTPUTS.md` — stage → schema → endpoint → verifier catalog.
- Modify: `docs/PROTOCOL.md` — append 6 new schemas to the JSON Schemas index list.

---

### Task 1: Stage-artifact JSON schemas

**Files:**
- Create: `schemas/paari-parent-trust.v1.schema.json`
- Create: `schemas/paari-delegation.v1.schema.json`
- Create: `schemas/paari-governance-decision.v1.schema.json`
- Create: `schemas/paari-payment-result.v1.schema.json`
- Create: `schemas/paari-audit-record.v1.schema.json`
- Create: `schemas/paari-proof-bundle.v1.schema.json`
- Modify: `tests/test_schemas.py`
- Test: `tests/test_schemas.py`

**Interfaces:**
- Consumes: existing schema pattern from `schemas/paari-discovery.v1.schema.json` (`$schema`, `$id`, `title`, `required`, `properties`, `additionalProperties: false`, `examples`).
- Produces: six schema files whose `required` key lists are consumed by Task 2 (`app/proof_bundle.py` validates each bundle section against its schema's `required` list) and Task 3 (chain tests assert live outputs carry those keys).

- [ ] **Step 1: Write the failing test** — append to `tests/test_schemas.py`:

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

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_schemas.py::test_stage_artifact_schemas_exist_with_required_and_example -v`
Expected: FAIL with "missing schema paari-parent-trust.v1.schema.json"

- [ ] **Step 3: Write the six schema files** — one per artifact, following the discovery-schema pattern. Governance decision (the most valuable one) looks like this; the other five follow the same shape with their own `required` keys:

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

The other five schemas and their `required` keys:
  - `paari-parent-trust`: `["protocol", "protocol_version", "parent_id", "status", "trust_tier"]`
  - `paari-delegation`: `["protocol", "protocol_version", "delegation_id", "parent_id", "agent_public_key_fingerprint", "granted_capabilities", "payment_limit_minor_units", "currency", "issued_at", "expires_at", "signature_b64"]` (mirrors the delegation dict built in `tests/conftest.py:33-41`)
  - `paari-payment-result`: `["protocol", "protocol_version", "authorization_id", "transaction_id", "provider", "provider_order_id", "webhook_event", "webhook_verified", "final_state", "terminal"]`
  - `paari-audit-record`: `["protocol", "protocol_version", "event_id", "event_type", "transaction_id", "actor", "previous_state", "current_state", "reasons", "prev_hash", "event_hash"]`
  - `paari-proof-bundle`: `["protocol", "protocol_version", "bundle_id", "transaction_id", "created_at", "artifacts"]` where `artifacts` requires the 14 keys: `discovery, parent_trust, delegation, agent_identity, agent_card, credential, authentication, payment_intent, governance_decision, bounded_authorization, payment_execution, payment_result, audit_record, revocation`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_schemas.py -v`
Expected: all PASS (existing 3 tests + new test, auto-covering all 18 schema files via the existing glob tests).

- [ ] **Step 5: Run full suite for no regressions**

Run: `pytest -q`
Expected: 76 passed, 1 skipped (unchanged baseline).

---

### Task 2: Proof-bundle collector

**Files:**
- Create: `app/proof_bundle.py`
- Create: `tests/test_proof_bundle.py`
- Test: `tests/test_proof_bundle.py`

**Interfaces:**
- Consumes: `app/models.py` rows (`ParentAuthority`, `DelegationRecord`, `Agent`, `Credential`, `PaymentIntent`, `BoundedAuthorization`, `ProviderTransaction`, `AuditEvent`, `RevocationRecord`); schema `required` lists from Task 1; existing `paari_client` + `make_intent` helpers from `tests/conftest.py`.
- Produces: `collect_proof_bundle(db: Session, transaction_id: str) -> dict` returning a bundle matching `paari-proof-bundle.v1.schema.json`; consumed by Task 3 chain tests and Task 4 docs.

- [ ] **Step 1: Write the failing test** — create `tests/test_proof_bundle.py`:

```python
from tests.conftest import make_intent
from app.proof_bundle import collect_proof_bundle


def test_bundle_contains_all_artifacts_for_decided_intent(paari_client):
    ctx = paari_client
    intent = make_intent(ctx, amount=100)
    db = ctx.Session()
    try:
        bundle = collect_proof_bundle(db, intent["transaction_id"])
    finally:
        db.close()
    assert bundle["protocol"] == "paari"
    assert bundle["protocol_version"] == "1.0"
    expected = ["discovery", "parent_trust", "delegation", "agent_identity",
                "agent_card", "credential", "authentication", "payment_intent",
                "governance_decision", "bounded_authorization",
                "payment_execution", "payment_result", "audit_record",
                "revocation"]
    for key in expected:
        assert key in bundle["artifacts"], f"bundle missing {key}"
    assert bundle["artifacts"]["governance_decision"]["decision"] == intent["decision"]
    assert bundle["artifacts"]["agent_identity"]["agent_id"] == ctx.agent_id
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_proof_bundle.py -v`
Expected: FAIL with "No module named 'app.proof_bundle'" (or collection error on import).

- [ ] **Step 3: Write minimal implementation** — create `app/proof_bundle.py` (read-only: queries DB rows, returns plain dicts, never mutates state). Before writing, read `app/models.py` fully and use the exact column/attribute names for `ParentAuthority` (status, trust tier), `DelegationRecord` (fingerprint, capabilities, limits, currency, timestamps, signature), `Agent`, `Credential`, `PaymentIntent` (decision, reasons, policy results, MFA flags), `BoundedAuthorization`, `ProviderTransaction` (order id, state, webhook fields), `AuditEvent` (from/to state, hashes), `RevocationRecord`. The test failure will pinpoint any name mismatch — fix names to match `app/models.py`, never the test's expectations.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_proof_bundle.py -v`
Expected: PASS. If FAIL on attribute names, fix names to match `app/models.py` (read-only check), re-run.

- [ ] **Step 5: Run full suite for no regressions**

Run: `pytest -q`
Expected: 77 passed, 1 skipped.

---

### Task 3: Cross-stage verification tests

**Files:**
- Create: `tests/test_proof_chain.py`
- Test: `tests/test_proof_chain.py`

**Interfaces:**
- Consumes: `collect_proof_bundle` from Task 2; `paari_client` + `make_intent` from `tests/conftest.py`; live v1 endpoints from `app/routers/v1.py`.
- Produces: failing-closed proof that each stage verifies the previous stage's output (tamper → deny, replay → deny, revoke → block).

- [ ] **Step 1: Write the failing tests** — create `tests/test_proof_chain.py`:

```python
from tests.conftest import make_intent
from app.proof_bundle import collect_proof_bundle


def test_each_stage_output_links_to_previous_stage(paari_client):
    ctx = paari_client
    intent = make_intent(ctx, amount=100)
    db = ctx.Session()
    try:
        bundle = collect_proof_bundle(db, intent["transaction_id"])
    finally:
        db.close()
    a = bundle["artifacts"]
    assert a["agent_card"]["credential_id"] == a["credential"]["credential_id"]
    assert a["credential"]["agent_id"] == a["agent_identity"]["agent_id"]
    assert a["governance_decision"]["intent_id"] == a["payment_intent"]["intent_id"]
    assert a["bounded_authorization"]["transaction_id"] == intent["transaction_id"]
    events = a["audit_record"]["events"]
    assert events[0]["event_type"] == "intent_decided"
    for prev, cur in zip(events, events[1:]):
        assert cur["prev_hash"] == prev["event_hash"]


def test_tampered_delegation_fails_registration(paari_client):
    from app import crypto_utils
    ctx = paari_client
    agent_private, agent_public = crypto_utils.generate_agent_keypair()
    delegation = {
        "delegation_id": "tampered-1",
        "parent_id": ctx.parent_id,
        "agent_public_key_fingerprint": "00" * 32,
        "granted_capabilities": ["make_payment"],
        "payment_limit_minor_units": 500000,
        "currency": "INR",
        "issued_at": 1750000000,
        "expires_at": 1750000120,
    }
    sig = crypto_utils.sign_with_private_key(ctx.parent_private,
                                             crypto_utils.canonical_json(delegation))
    delegation["payment_limit_minor_units"] = 999999999
    r = ctx.client.post("/v1/agents/register", json={
        "agent_id": "tampered-agent-1",
        "public_key_pem": agent_public,
        "delegation": delegation,
        "delegation_signature_b64": sig,
    })
    assert r.status_code in (400, 401, 422)
```

Before writing, read `app/routers/v1.py:v1_register_agent` and `app/schemas.py:V1AgentRegistrationRequest` (or equivalent) and use the exact request field names — the test above shows intent; field names MUST match the server.

- [ ] **Step 2: Run tests to verify behavior**

Run: `pytest tests/test_proof_chain.py -v`
Expected: second test PASSES already (server rejects tampered delegation — proves stage 5 verifies stage 4 output); first test FAILS only if bundle links are wrong — fix `app/proof_bundle.py` field mapping, not the test.

- [ ] **Step 3: Fix any link mismatches in the collector** (only if Step 2 fails on the first test; change `app/proof_bundle.py` field names to match real endpoint/model values, then re-run).

- [ ] **Step 4: Run full suite for no regressions**

Run: `pytest -q`
Expected: 79 passed, 1 skipped.

---

### Task 4: Stage-output catalog docs

**Files:**
- Create: `docs/STAGE_OUTPUTS.md`
- Modify: `docs/PROTOCOL.md` (append 6 schemas to the JSON Schemas index)
- Test: `pytest tests/test_schemas.py -q` (glob tests auto-cover the 6 new files)

**Interfaces:**
- Consumes: schema filenames from Task 1, `collect_proof_bundle` signature from Task 2, chain-test names from Task 3.

- [ ] **Step 1: Write `docs/STAGE_OUTPUTS.md`** — a 15-row table: Stage | Output artifact | Schema file | Producing endpoint/code | Verifying test. Every row must name an exact file and test; no prose-only rows. Example rows:

```markdown
| 9. Governance Decision | ALLOW/REVIEW/DENY + reasons + policy_results | `schemas/paari-governance-decision.v1.schema.json` | `POST /v1/payments/intent` (`app/routers/v1.py:v1_payment_intent`) | `tests/test_proof_chain.py::test_each_stage_output_links_to_previous_stage` |
| 14. Audit | hash-chained events with previous/current state | `schemas/paari-audit-record.v1.schema.json` | `app/audit.py` + `GET /v1/audit/{transaction_id}` | `tests/test_audit_hardening.py` + chain-link loop in `tests/test_proof_chain.py` |
```

(all 15 rows required, same format).

- [ ] **Step 2: Update `docs/PROTOCOL.md` schema index** — append the 6 new schema bullets after the Revocation line, same `- Name: \`path\`` format.

- [ ] **Step 3: Verify docs + suite**

Run: `pytest -q`
Expected: 79 passed, 1 skipped, docs complete.
