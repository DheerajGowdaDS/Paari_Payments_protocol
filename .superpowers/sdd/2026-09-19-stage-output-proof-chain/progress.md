# SDD ledger — plan: docs/superpowers/plans/2026-09-19-stage-output-proof-chain.md
Task 1: complete (review clean; 4 deferred minors folded into final review)
Task 2: complete (review clean; additive PaymentIntentResponse.transaction_id echo; 3 deferred minors folded into final review)
Task 3: complete (review clean; collector link-alias fix verified; 1 deferred minor folded into final review)
Task 4: complete (review clean, no findings)
Final review: Fix-required → single fix wave F1-F11, all ADDRESSED, no new breakage, suite 81 passed / 1 skipped (independently verified).
Parked rulings (real but non-load-bearing, follow-ups):
- provider_order_id non-nullable vs null pre-submission: unreachable (payment_result exists only with a provider row, which carries the order id); stands.
- bounded_authorization bundle node carries protocol/protocol_version extras vs schema additionalProperties:false: bundle envelope-keys by design; follow-up is to add them to the schema or strip them.
- card/credential/auth/discovery bundle sections are DB projections, not full wire shapes: normative per-stage shapes live in the wire schemas asserted at endpoints; full pinning is a follow-up.
- T1 minors (bundle {} example slots, parent-trust/delegation conventions): stand as documented; audit-record chain shape now normative per F9.
SUITE: 81 passed, 1 skipped. No git repo: no commits; change set is the working tree.

## Post-delivery re-audit (same day) — corrections to the rulings above

- Ruling "provider_order_id non-nullable ... unreachable" was WRONG and is now superseded:
  `app/routers/payments.py:298` mints the `AUTHORIZED` provider row at intent time with
  `razorpay_order_id = None`, so the normal ALLOW path violated its own schema. Fixed by making
  `provider_order_id` `["string","null"]` in `schemas/paari-payment-result.v1.schema.json`.
- Ruling "bounded_authorization bundle node carries protocol/protocol_version extras" resolved by
  stripping `_base()` from that node rather than loosening the schema.
- "Validates against the schemas" was key-presence only; `tests/_schema_validator.py` is now a real
  subset validator (type/const/enum/pattern/minLength/maxLength/minimum/format/required/properties/
  additionalProperties/items/oneOf). It raises on any keyword it does not implement, and
  `tests/test_schemas.py::test_every_schema_stays_inside_the_supported_keyword_subset` walks all 18
  shipped schemas so a future `anyOf`/`not`/`$ref` fails CI instead of passing unchecked.
- Stage verification is now cryptographic (card Ed25519 signature, delegation key fingerprint,
  credential JWT `typ`/`sub`), replacing three self-comparisons that could not fail.
- `GET /v1/proof/{transaction_id}` added and propagated to `docs/PROTOCOL.md`, `README.md`, the
  discovery document + schema, `docs/CONFORMANCE.md` item 13 and `sdk/paari_agent/client.py`.

## Deferred by ruling — merchant and risk governance (NOT a cleanup item)

The blueprint's stage-9 check list includes **Merchant** and **Risk**. Neither is enforced:
`app/routers/payments.py:249-285` checks parent status, trust provider, delegation expiry, positive
amount, capability, delegated limit, currency, velocity and the 0.8x-limit step-up ratio — nothing
else. `merchant` is carried and audited but never constrained, and there is no risk-scoring seam.

Enforcing either is a feature decision, not hygiene: a merchant policy has to become part of the
parent-signed `DelegationDocument` (so both signing sides change, plus an Alembic migration and new
conformance cases), and risk scoring needs a real signal source. Leaving them unenforced is
deliberate. Do not read `docs/STAGE_OUTPUTS.md` stage 9 as claiming a merchant check exists; the
chain only proves the merchant that was *recorded* at decision time equals the one in the minted
authorization (`tests/test_proof_chain.py`).

SUITE after re-audit fixes: 86 passed, 1 skipped; `python -m compileall -q app sdk scripts` clean.

## Second-opinion audit (external report, same day) — F-1/F-2/F-3 closed

Its three new findings were each verified before acting: F-1 (rows 7/8 cited a test that did not
validate those nodes), F-2 (`verify_chain` had exactly one real caller — a test), F-3 (documented
404/409 paths untested). Confirmed all three.

- **F-1** `docs/STAGE_OUTPUTS.md` rows 7, 8 and 15 no longer imply bundle-node conformance: each now
  says the named schema is the *wire* shape and that the `credential`/`authentication` node is an
  evidence projection deliberately unpinned. A new footnote lists exactly which 8 of 14 nodes are
  machine-validated and which 6 are not.
- **F-2** Paari now checks its own evidence: `verify_chain()` is called by
  `GET /v1/audit/{transaction_id}` and by the collector's `audit_record` node, both returning
  `chain_verified` (added to `paari-audit-record.v1.schema.json` required + example). Tests:
  `tests/test_audit.py::test_audit_endpoint_reports_server_verified_chain` asserts True on an intact
  chain and False after a stored event is tampered with. Also de-vacuumed
  `tests/test_failure_recovery.py::test_audit_chain_remains_intact_after_failure`, which previously
  asserted only that the imported function `is not None`.
- **F-3** `tests/test_proof_bundle.py::test_proof_endpoint_fails_closed_for_unknown_and_ambiguous_transaction`
  covers the documented 404 and 409 paths (two intents sharing a `transaction_id`).
- Docs drift: `AGENTS.md` said "61 passing"; it now says 88 passing / 1 skipped and names the skip
  reason (Postgres migration test, exercised in CI with a live service).

Still open from that report, unfixed by choice: F-4 merchant/risk (ledgered above), F-5 parent
lifecycle on legacy routes, F-7 `policy_results` not on the intent response, F-8 audit
read-then-write race under concurrent writers on one `transaction_id`.

SUITE after F-1/F-2/F-3: 88 passed, 1 skipped; `python -m compileall -q app sdk scripts` clean.

