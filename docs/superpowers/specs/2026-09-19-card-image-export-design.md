# Card Image Export — Design

> Live E2E visual cards for the 15 Stage Outputs. PNGs on disk from live proof bundle.

**Goal:** Export 15 PNG images (one per `docs/STAGE_OUTPUTS.md` row) from the live bundle `TXN-proof-9c5ffd55` (`order_TdrLnfAh9TBQie` / `pay_TdrWE1S8hVE0PJ`) for slide/doc use, with no UI regression.

**Architecture:** CLI `scripts/export_cards.py` loads bundle via `app.proof_bundle.collect_proof_bundle(db, tx)` (fallback to `evidence_live_e2e_2026-09-19.json`), renders 15 HTML cards via Jinja2 (`scripts/templates/card_base.html` + `cards.css`, Paari indigo/white), writes `exports/cards/html/stage-*.html`, then Playwright screenshots each to `exports/cards/png/stage-*.png` at 1200x750 @2x. Read-only, no secrets, no DB writes.

**Tech Stack:** Python 3.11, Jinja2, Playwright chromium, `app.proof_bundle`, `tests/_schema_validator` shape reference, `paari_live_e2e.db`.

## Components

- `scripts/export_cards.py` — argparse `--tx` `--json` `--out`, bundle load, hash truncation, signature_b64 null guard, Jinja render, Playwright screenshot with fallback message if playwright missing.
- `scripts/templates/card_base.html` — base layout: header (Paari + Stage N badge + title), body grid, footer (bundle_id, chain_verified, QR stub), monospaced hashes.
- `scripts/templates/cards.css` — indigo-600/white, rounded-2xl, shadow-xl, stage accent.
- Stage mapping (uses `docs/STAGE_OUTPUTS.md:7-24`):
  1 Discovery `artifacts.discovery` (well-known, base_url, paari_public_key_pem head)
  2 Parent Trust pending `parent_id b89778e0... trust_tier self_asserted`
  3 Parent Trust verified `active/admin_approved` + `ParentTrustProvider`
  4 Delegation `delegation_id 17a51ec3...` canonical JSON + fingerprint
  5 Agent Identity `f358feea...` delegation_id parent_id
  6 Agent Card `agent_card` signed `card_signature_b64 12ch…` limits `max_amount 500000 INR`
  7 Credential `credential_id a7098519...` status
  8 Authentication nonce `3d1a24c0...` used true → revoked false
  9 Intent/Governance `decision allow` merchant `ProofStore` `100` policy_results
  10 Bounded Authorization `authorization_id c25087c8...` single-use
  11 Payment Execution `razorpay_order_id order_TdrLnfAh9TBQie` `PROVIDER_SUBMITTED→PAID`
  12 Webhook verified `payment.captured` `webhook_event 435a6e...`
  13 Reconciliation `final_state PAID` `terminal true`
  14 Audit `chain_verified true` events `intent_decided … webhook_applied x2` + tamper-evident
  15 Revocation `revoked true` `revocation_id None` + `401` blocked

## Data Flow

Load → `collect_proof_bundle` (or JSON) → sanitize (`None` → `—`, `signature_b64` null) → truncate hashes to 12 for card, full in `title` hover → render HTML per stage → Playwright `page.setViewport({width:1200,height:750,deviceScaleFactor:2})` → `screenshot(path)` → verify `ls png/*.png` count 15.

## Error Handling

- `ValueError: ambiguous/unknown transaction_id` → exit 2 with hint `use --json evidence_live_e2e_2026-09-19.json or audit 409`.
- Missing Playwright → warn and leave HTML for manual screenshot; print `pip install playwright && playwright install chromium`.
- Missing DB → fallback to JSON file if present else exit.

## Testing

- No pytest change; manual `ls exports/cards/png/stage-*.png` =15 and open 3 sample PNGs.
- Visual check via `frontend-design` skill aesthetics: badge contrast, hash legibility, signature truncate.

## Constraints

- Exports under `exports/` gitignored except `exports/cards/README.md`.
- No secrets in cards (only fingerprints, truncated sigs, public keys).
- Python 3.11, no new DB tables, no linter assumption.
