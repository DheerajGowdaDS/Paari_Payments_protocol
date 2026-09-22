# Task 3 report — Cross-stage verification tests

## Status: DONE

## What was done (followed task-3-brief.md exactly)
1. Created `tests/test_proof_chain.py` verbatim from the brief (Step 1): two tests —
   `test_each_stage_output_links_to_previous_stage` (stage-link assertions over
   `collect_proof_bundle`) and `test_tampered_delegation_fails_registration`
   (signed-then-modified delegation → 401 `"Delegation signature verification failed"`).
2. Confirmed the envelope/delegation pattern against `tests/test_protocol.py:27-51`
   (identical `sign_envelope(agent_private, "agent.register", ...)` shape and delegation
   keys). No disagreement with the brief; brief governed.
3. Ran `pytest tests/test_proof_chain.py -v`: first run 1 failed / 1 passed.
   Failure was `KeyError: 'agent_id'` on `a["credential"]["agent_id"]` — per the brief's
   Step 2 rule this was a collector mapping gap, so the test was left untouched and
   `app/proof_bundle.py` was fixed minimally (read-only mapping additions only):
   - `credential` artifact: added `"agent_id": agent.agent_id`
   - `governance_decision` artifact: added `"intent_id": intent.intent_id`
   - each `audit_record` event: added `"event_type": e.kind` as an alias alongside
     the existing `"kind"` key (no existing keys renamed/removed)
4. Re-ran target file: 2 passed. `events[0]["event_type"] == "intent_decided"` held on
   first try, so no expectation change was needed (no registration-audit contamination:
   those use `delegation:`-prefixed ids and are excluded by the transaction filter).
5. Ran full suite: 80 passed, 1 skipped (matches brief expectation). Ran
   `python -m compileall -q app sdk scripts`: clean.

## Test summary
- `pytest tests/test_proof_chain.py -v` → 2 passed
- `pytest -q` → 80 passed, 1 skipped
- `python -m compileall -q app sdk scripts` → clean

## Files changed
- `tests/test_proof_chain.py` (new, verbatim from brief)
- `app/proof_bundle.py` (3 additive mapping lines only; no behavior change)

## Concerns
- Minor: three link keys the new test requires (`credential.agent_id`,
  `governance_decision.intent_id`, `audit event event_type`) were absent from the
  Task 2 collector, so downstream proof-bundle consumers/schemas should adopt these
  key names as canonical (the old `kind` key was kept for backward compatibility).
  No test was weakened; full suite is green.
