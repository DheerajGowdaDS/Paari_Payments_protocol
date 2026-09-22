# Task 3 brief — Cross-stage verification tests (read this first; it is your requirements, with exact values to use verbatim)

## Where this fits
Tasks 1–2 complete (6 schemas review-clean; `app/proof_bundle.py::collect_proof_bundle(db, transaction_id) -> dict` review-clean, suite at 78 passed / 1 skipped). You add `tests/test_proof_chain.py` proving each stage verifies the previous stage's output.

## Global constraints (binding)
- Python 3.11, no new third-party dependencies.
- Session tokens in `Authorization: Bearer` header if needed; never in URLs. (These tests need no session tokens.)
- Full suite must stay green.
- Never write secrets, `.pem`, `.key`, `.db`, or `.env` content.
- NOT a git repo: do NOT run git commands. Implement, test, self-review, report.

## Exact server contract (verified from `app/routers/v1.py:110-153`, `tests/test_protocol.py:27-51`)
- `POST /v1/agents/register` takes `{"envelope": envelope}` where the envelope is built EXACTLY like this:
```python
from app import crypto_utils
from app.protocol.envelope import sign_envelope
envelope = sign_envelope(agent_private, "agent.register", {"sender": crypto_utils.public_key_fingerprint(agent_public), "receiver": "paari"}, payload, ttl_seconds=300)
```
  with `payload = {"name": ..., "agent_type": "shopping_assistant", "purpose": ..., "public_key_pem": agent_public, "delegation": delegation, "delegation_signature_b64": sig}`.
- Delegation dict shape (exact keys): `delegation_id` (unique per test — use `uuid.uuid4()`), `parent_id` (= `ctx.parent_id` from fixture), `agent_public_key_fingerprint` (= `crypto_utils.public_key_fingerprint(agent_public)`), `granted_capabilities` (`["make_payment"]`), `payment_limit_minor_units`, `currency` (`"INR"`), `issued_at`/`expires_at` (int epoch seconds, expiry within 366 days).
- Parent signature: `sig = crypto_utils.sign_with_private_key(ctx.parent_private, crypto_utils.canonical_json(delegation))`.
- A tampered delegation (signed-then-modified) is rejected with status **401** and detail **"Delegation signature verification failed"** (`app/routers/v1.py:132-134`).
- `make_intent(ctx, amount)` from `tests/conftest.py` returns the legacy intent JSON including `decision` and `transaction_id` (added in Task 2).

## Steps (TDD, do exactly these)

### Step 1: Create `tests/test_proof_chain.py` verbatim:

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
    import uuid
    from datetime import datetime, timedelta, timezone
    from app import crypto_utils
    from app.protocol.envelope import sign_envelope
    ctx = paari_client
    agent_private, agent_public = crypto_utils.generate_agent_keypair()
    now = datetime.now(timezone.utc)
    delegation = {
        "delegation_id": str(uuid.uuid4()),
        "parent_id": ctx.parent_id,
        "agent_public_key_fingerprint": crypto_utils.public_key_fingerprint(agent_public),
        "granted_capabilities": ["make_payment"],
        "payment_limit_minor_units": 500000,
        "currency": "INR",
        "issued_at": int(now.timestamp()),
        "expires_at": int((now + timedelta(days=30)).timestamp()),
    }
    sig = crypto_utils.sign_with_private_key(
        ctx.parent_private, crypto_utils.canonical_json(delegation))
    delegation["payment_limit_minor_units"] = 999999999
    payload = {"name": "Tampered Agent", "agent_type": "shopping_assistant",
               "purpose": "chain test", "public_key_pem": agent_public,
               "delegation": delegation, "delegation_signature_b64": sig}
    envelope = sign_envelope(agent_private, "agent.register",
                             {"sender": crypto_utils.public_key_fingerprint(agent_public),
                              "receiver": "paari"}, payload, ttl_seconds=300)
    r = ctx.client.post("/v1/agents/register", json={"envelope": envelope})
    assert r.status_code == 401, r.text
    assert r.json()["detail"] == "Delegation signature verification failed"
```

### Step 2: Run tests
Run: `pytest tests/test_proof_chain.py -v`
Expected: both PASS (tamper test proves stage 5 verifies stage 4 output). If the first test fails on a link assertion, the defect is in `app/proof_bundle.py` field mapping — fix the collector minimally (read-only mapping change, no behavior change), never weaken the test. If `events[0]` is not `intent_decided`, inspect the actual first event via a quick failing-output print and fix the test's expectation ONLY if the earlier event legitimately belongs to the same transaction (e.g. registration audit under a different transaction_id must NOT match — those use `delegation:` prefixed ids and must be excluded).

### Step 3: Run full suite
Run: `pytest -q`
Expected: 80 passed, 1 skipped.

## Report contract
Write your full report to `.superpowers/sdd/2026-09-19-stage-output-proof-chain/task-3-report.md`. Reply with only: status (DONE / DONE_WITH_CONCERNS / NEEDS_CONTEXT / BLOCKED), the test summary line, and any concerns.
