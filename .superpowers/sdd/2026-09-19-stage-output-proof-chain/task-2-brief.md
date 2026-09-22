# Task 2 brief — Proof-bundle collector (read this first; it is your requirements, with exact values to use verbatim)

## Where this fits
Task 1 (complete, review-clean) added 6 schemas in `schemas/`. You now add `app/proof_bundle.py` with `collect_proof_bundle(db, transaction_id) -> dict`, a pure read-only collector assembling the 14 stage artifacts for one transaction, plus `tests/test_proof_bundle.py`.

## Global constraints (binding)
- Python 3.11, no new third-party dependencies.
- Read-only collector: SQLAlchemy queries only, never mutates state.
- Full suite must stay green (baseline now: 77 passed, 1 skipped).
- Never write secrets, `.pem`, `.key`, `.db`, or `.env` content.
- NOT a git repo: do NOT run git commands. Implement, test, self-review, report.

## Exact model facts (verified from `app/models.py`, `app/routers/payments.py:178-221`, `app/audit.py:19-49`, `app/schemas.py:196-203`)
- `ParentAuthority`: `parent_id`, `status` (enum → use `.value`), `trust_tier` (plain column).
- `Agent`: `agent_id`, `public_key_pem`, `status` (enum → `.value`), `delegation_id`; parent via relationship `agent.parent.parent_id`.
- `DelegationRecord`: query with `.filter_by(delegation_id=agent.delegation_id)`; columns `delegation_id`, `agent_public_key_fingerprint`, `granted_capabilities`, `payment_limit_minor_units`, `currency`, `issued_at`, `expires_at`. There is NO signature column (Paari verifies the parent signature at registration and does not retain it): emit `"signature_b64": None` with a code comment saying exactly that.
- `Credential`: `credential_id`, `issued_at`, `expires_at`, `revoked` (bool), `superseded_by` (nullable); NO `agent_id`/`status` columns. Query via the relationship: `db.query(models.Credential).join(models.Agent, models.Credential.agent_pk == models.Agent.id).filter(models.Agent.agent_id == agent.agent_id).one()`. Derive status: `"revoked"` if `revoked` else (`"superseded"` if `superseded_by` else `"active"`).
- `PaymentIntent`: `intent_id`, `agent_id`, `transaction_id`, `decision` (enum → `.value`), `reasons` (list), `mfa_required` (bool). There is NO `policy_results` column: read it from the `intent_decided` audit event's `detail["policy_results"]` (written at `app/routers/payments.py:212-216`).
- `BoundedAuthorization`: query `.filter_by(intent_id=intent.intent_id).one_or_none()`; columns `authorization_id`, `transaction_id`.
- `ProviderTransaction`: query `.filter_by(authorization_id=...).one_or_none()`; `state` is a PLAIN STRING (not enum — no `.value`); `razorpay_order_id`; NO webhook-verified/event columns except `webhook_event_id`. Emit `webhook_event` = `webhook_event_id`, `webhook_verified` = `webhook_event_id is not None`, `final_state` = `state`, `terminal` = `state in ("PAID", "FAILED")`.
- `AuditEvent`: `.filter_by(transaction_id=...).order_by(models.AuditEvent.id)`; columns `kind` (this IS the event type), `detail` (dict; state transitions hide in BOTH `from_state`/`to_state` and `previous_state`/`current_state` key styles — normalize with `detail.get("current_state", detail.get("to_state"))` and same for previous), `prev_hash`, `event_hash`. There are NO `event_type`/`from_state` columns. Emit `event_id` = `str(e.id)`.
- `RevocationRecord`: `.filter_by(agent_id=agent.agent_id).one_or_none()`; revoked = is not None.
- `make_intent(ctx, amount)` (in `tests/conftest.py`) posts to legacy `/payments/intent` and returns `r.json()` which INCLUDES `decision` (`app/schemas.py:196-203`), plus `transaction_id` (echoed from request).

## Steps (TDD, do exactly these)

### Step 1: Write the failing test — create `tests/test_proof_bundle.py` verbatim:

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

### Step 2: Run test to verify it fails
Run: `pytest tests/test_proof_bundle.py -v`
Expected: FAIL with import/collection error on `app.proof_bundle`.

### Step 3: Create `app/proof_bundle.py` implementing `collect_proof_bundle(db: Session, transaction_id: str) -> dict` returning `{"protocol": "paari", "protocol_version": "1.0", "bundle_id": f"bundle-{transaction_id}", "transaction_id": ..., "created_at": intent.created_at.isoformat(), "artifacts": {...}}` with all 14 keys above, each section carrying `protocol`/`protocol_version` plus the fields mapped from the exact columns in this brief. `bounded_authorization`, `payment_execution`, `payment_result` are `None` when no authorization/provider row exists (fresh intent has neither). `authentication` is `{"protocol": "paari", "protocol_version": "1.0", "agent_id": ..., "authenticated": True}` (the fixture authenticates before intent). `agent_card` carries `agent_id` + `credential_id`.

### Step 4: Run test to verify it passes
Run: `pytest tests/test_proof_bundle.py -v`
Expected: PASS. On attribute errors, fix names to match `app/models.py`, never the test.

### Step 5: Run full suite
Run: `pytest -q`
Expected: 78 passed, 1 skipped.

## Report contract
Write your full report to `.superpowers/sdd/2026-09-19-stage-output-proof-chain/task-2-report.md`. Reply with only: status (DONE / DONE_WITH_CONCERNS / NEEDS_CONTEXT / BLOCKED), the test summary line, and any concerns.
