# Task 2 report — Proof-bundle collector

## Status: DONE_WITH_CONCERNS (brief/code mismatch found and fixed; suite green)

## TDD log
1. Created `tests/test_proof_bundle.py` verbatim from the brief.
2. Ran `pytest tests/test_proof_bundle.py -v` → RED as expected:
   `ModuleNotFoundError: No module named 'app.proof_bundle'` (collection error).
3. Created `app/proof_bundle.py` with `collect_proof_bundle(db, transaction_id) -> dict`
   (read-only; `db.query` only, no add/commit/flush/delete).
4. Re-ran target test → FAILED with `KeyError: 'transaction_id'` on
   `intent["transaction_id"]` (test line 10, before collector code runs).
   Root cause: `make_intent` returns `POST /payments/intent` JSON, and
   `PaymentIntentResponse` (`app/schemas.py:196-203`) had NO `transaction_id`
   field, so the verbatim test could never pass. Brief §"Exact model facts"
   claimed the response "INCLUDES decision ... plus transaction_id (echoed
   from request)" — contradicted by code. Per "code and brief disagree, brief
   governs" + "never the test", fixed production code, not the test.
5. Minimal production fix (backward-compatible, defaulted field):
   - `app/schemas.py`: added `transaction_id: str = ""` to `PaymentIntentResponse`.
   - `app/routers/payments.py`: populated `transaction_id` at all 5
     `PaymentIntentResponse(...)` construction sites (idempotent-replay uses
     `existing.transaction_id`; REVIEW/ALLOW/DENY/MFA-verify use
     `intent.transaction_id`). v1 `/v1/payments/intent` delegates to the same
     function, so it inherits the fix.
6. Re-ran target test → PASS.
7. Full suite → green. `python -m compileall -q app sdk scripts` → OK.

## Test summary
- `pytest tests/test_proof_bundle.py -v`: **1 passed**.
- `pytest -q`: **78 passed, 1 skipped** (matches brief expectation of 78 passed, 1 skipped; baseline was 77 passed, 1 skipped).

## Files changed
- `tests/test_proof_bundle.py` (new, verbatim from brief).
- `app/proof_bundle.py` (new): returns `{"protocol": "paari",
  "protocol_version": "1.0", "bundle_id": f"bundle-{transaction_id}",
  "transaction_id": ..., "created_at": intent.created_at.isoformat(),
  "artifacts": {...14 keys...}}`. Each section carries
  `protocol`/`protocol_version` plus brief-mapped fields:
  parent (`parent_id`, `status.value`, `trust_tier`); agent (`agent_id`,
  `public_key_pem`, `status.value`, `delegation_id`, `agent.parent.parent_id`);
  delegation (all 7 columns + `"signature_b64": None` with comment "Paari
  verifies the parent signature at registration and does not retain it");
  credential via the exact brief join, derived status
  revoked/superseded/active; intent fields + `policy_results` from the
  `intent_decided` audit detail; auth/provider via `one_or_none()` with
  `bounded_authorization`/`payment_execution`/`payment_result` = `None` when
  absent; provider mapping (`webhook_event` = `webhook_event_id`,
  `webhook_verified` = is-not-None, `final_state` = `state`,
  `terminal` = in PAID/FAILED); audit events ordered by id with
  `event_id=str(e.id)`, `kind`/`detail`/`prev_hash`/`event_hash`, and
  previous/current normalized across both key styles; revocation
  (`revoked` = record is not None); `authentication` =
  `{agent_id, authenticated: True}`; `agent_card` = `{agent_id, credential_id}`.
- `app/schemas.py`, `app/routers/payments.py`: `transaction_id` echo fix above.

## Concerns / flags for integrators
1. **Brief vs code mismatch (flagged per instructions):** brief stated the
   intent response echoes `transaction_id`; it did not. Fixed by adding an
   echoed `transaction_id` field rather than editing the verbatim test. This
   slightly exceeds "collector plus test" scope but was required for the
   verbatim test to pass; it is additive/backward-compatible
   (`transaction_id` defaults to `""`, existing tests unaffected).
2. **Brief parenthetical vs ALLOW path:** brief says fresh intents have no
   auth/provider rows (all three sections `None`). Amount=100 is ALLOW, which
   DOES mint auth + provider rows, so the passing test exercises the
   non-None path. The `None` path is still implemented per spec but is only
   reachable on DENY/REVIEW intents — consider a follow-up test for a DENY
   intent asserting the three `None`s.
3. **Schema strictness note:** `schemas/paari-proof-bundle.v1.schema.json`
   types every artifact as `object`, so `None` for the three absent-row
   sections would not validate; kept `None` because the brief mandates it.
   If strict validation is needed later, use `{}` or omit instead.
4. No new dependencies; no secrets/`.pem`/`.db`/`.env` written; no git
   commands run (not a git repo).
