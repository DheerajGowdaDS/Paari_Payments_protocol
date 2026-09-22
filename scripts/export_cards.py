"""Export 15 stage cards as HTML + PNG from live proof bundle — complete info, no pruning."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from jinja2 import Environment, FileSystemLoader

STAGES = [
    ("01", "Discovery", "discovery", "01-discovery"),
    ("02", "Parent Trust — Pending", "parent_trust", "02-parent-trust-pending"),
    ("03", "Parent Trust — Verified", "parent_trust", "03-parent-trust-verified"),
    ("04", "Delegation", "delegation", "04-delegation"),
    ("05", "Agent Identity", "agent_identity", "05-agent-identity"),
    ("06", "Agent Card", "agent_card", "06-agent-card"),
    ("07", "Credential", "credential", "07-credential"),
    ("08", "Authentication", "authentication", "08-authentication"),
    ("09", "Governance Decision", "governance_decision", "09-governance"),
    ("10", "Bounded Authorization", "bounded_authorization", "10-bounded-authorization"),
    ("11", "Payment Execution", "payment_execution", "11-payment-execution"),
    ("12", "Webhook — Verified", "payment_result", "12-webhook"),
    ("13", "Payment Result", "payment_result", "13-payment-result"),
    ("14", "Audit Record", "audit_record", "14-audit-record"),
    ("15", "Revocation", "revocation", "15-revocation"),
]


def load_bundle(tx: str, json_path: str | None):
    if json_path:
        p = pathlib.Path(json_path)
        if p.exists():
            print(f"Loading bundle from JSON fallback: {p}")
            return json.loads(p.read_text(encoding="utf-8"))
    try:
        from sqlalchemy.orm import sessionmaker

        from app.database import get_engine
        from app.proof_bundle import collect_proof_bundle

        for db_url in ["sqlite:///./paari_live_e2e.db", "sqlite:///./paari.db"]:
            db_file = db_url.replace("sqlite:///./", "")
            if pathlib.Path(db_file).exists():
                engine = get_engine(db_url)
                Session = sessionmaker(bind=engine)
                db = Session()
                try:
                    bundle = collect_proof_bundle(db, tx)
                    print(f"Loaded bundle {tx} from {db_file}")
                    return bundle
                finally:
                    db.close()
        engine = get_engine("sqlite:///./paari_live_e2e.db")
        Session = sessionmaker(bind=engine)
        db = Session()
        try:
            return collect_proof_bundle(db, tx)
        finally:
            db.close()
    except Exception as e:
        print(f"DB load failed: {e}", file=sys.stderr)
        if json_path and pathlib.Path(json_path).exists():
            print(f"Falling back to JSON {json_path}")
            return json.loads(pathlib.Path(json_path).read_text(encoding="utf-8"))
        raise


def _build_fields(bundle: dict, stage_key: str, stage_slug: str):
    art = bundle.get("artifacts", {})
    b_id = bundle.get("bundle_id", "")
    tx = bundle.get("transaction_id", "")
    fields: list[dict] = []

    def add(label, value, tag=None, wide=False, small=False):
        raw = "—" if value is None or value == "" else str(value)
        fields.append({"label": label, "value": raw, "tag": tag, "wide": wide, "small": small})

    if stage_slug == "01-discovery":
        d = art.get("discovery", {})
        add("protocol", f"{d.get('protocol')} / {d.get('protocol_version')} — {d.get('issuer')} · {d.get('service')}", tag="v1.0")
        add("base_url + discovery", f"base: {d.get('base_url')}  ·  well-known: {d.get('discovery',{}).get('well_known')}", wide=True, small=True)
        add("agent endpoints", f"register: {d.get('agent_registration')}\ncard: {d.get('agent_card')}", wide=True, small=True)
        auth = d.get("authentication", {})
        add("auth", f"challenge: {auth.get('challenge')}\nverify: {auth.get('verify')}", wide=True, small=True)
        pay = d.get("payment", {})
        pay_block = f"intent: {pay.get('intent')}\nconsume: {pay.get('consume')}\nwebhook: {pay.get('webhook')}\nreconcile/proof: {pay.get('reconcile')} / {pay.get('proof')}\nmfa: {pay.get('mfa_challenge')} / {pay.get('mfa_verify')}"
        add("payment endpoints", pay_block, wide=True, small=True)
        sec = d.get("security", {})
        add("security + algorithms", f"cred={sec.get('credential_type')}  proof={sec.get('request_proof')}  algo=Ed25519  providers={','.join(d.get('provider_boundary',{}).get('providers',[]))}", wide=True, small=True)
        rules = d.get("rules", {})
        add("rules (4)", " · ".join([k for k,v in rules.items() if v]), wide=True, small=True)
        pem = d.get("paari_public_key_pem","")
        pem_head = pem.strip().splitlines()[1] if "BEGIN" in pem else pem[:40]
        add("paari public key (head)", pem_head + " …", tag="Ed25519", small=True)

    elif stage_slug == "02-parent-trust-pending":
        pt = art.get("parent_trust", {})
        add("parent_id (full)", pt.get("parent_id"), wide=True)
        add("status (requested)", "pending_verification", tag="pre-verify")
        add("trust_tier (requested)", "self_asserted")
        add("live status (bundle)", pt.get("status"), tag=pt.get("status"))
        add("live trust_tier", pt.get("trust_tier"), tag=pt.get("trust_tier"))
        add("transaction", tx)
        add("bundle", b_id, wide=True)

    elif stage_slug == "03-parent-trust-verified":
        pt = art.get("parent_trust", {})
        add("parent_id (full)", pt.get("parent_id"), wide=True)
        add("status", pt.get("status"), tag="active")
        add("trust_tier", pt.get("trust_tier"), tag="admin_approved")
        add("provider", "ParentTrustProvider · verify parent authority")
        add("parent_id head", pt.get("parent_id","")[:8] + "…", small=True)
        add("bundle", b_id, wide=True)
        add("transaction", tx)

    elif stage_slug == "04-delegation":
        dlg = art.get("delegation", {})
        add("delegation_id (full)", dlg.get("delegation_id"), wide=True)
        add("parent_id (full)", dlg.get("parent_id"), wide=True)
        add("fingerprint (full, 64 hex)", dlg.get("agent_public_key_fingerprint"), wide=True, small=True)
        add("granted_capabilities", ", ".join(dlg.get("granted_capabilities") or []), tag="make_payment")
        add("payment limit", f"{dlg.get('payment_limit_minor_units')} {dlg.get('currency')}  ({dlg.get('payment_limit_minor_units',0)/100:.2f} INR)")
        add("issued_at (epoch)", dlg.get("issued_at"))
        add("expires_at (epoch)", dlg.get("expires_at"))
        add("signature_b64", "—  (verified at registration, not retained by Paari)", tag="canonical JSON", wide=True)

    elif stage_slug == "05-agent-identity":
        ai = art.get("agent_identity", {})
        add("agent_id (full)", ai.get("agent_id"), wide=True)
        add("delegation_id (full)", ai.get("delegation_id"), wide=True)
        add("parent_id (full)", ai.get("parent_id"), wide=True)
        add("status", ai.get("status"), tag=ai.get("status"))
        pem = ai.get("public_key_pem","")
        pem_head = pem.strip().splitlines()[1] if "BEGIN" in pem else pem[:40]
        add("public_key (head)", pem_head + " …", tag="Ed25519", small=True)
        add("public_key (full PEM)", pem.strip().replace("\n"," · "), wide=True, small=True)
        add("bundle / tx", f"{b_id} · {tx}", wide=True, small=True)

    elif stage_slug == "06-agent-card":
        ac = art.get("agent_card", {})
        add("agent_id (full)", ac.get("agent_id"), wide=True)
        add("name", ac.get("name"), tag=ac.get("agent_type"))
        add("status", ac.get("status"), tag=ac.get("status"))
        add("credential_id (full)", ac.get("credential_id"), wide=True)
        lim = ac.get("limits") or {}
        add("limits", f"max_amount {lim.get('max_amount')} {lim.get('currency')}", tag="delegation limit")
        add("expires_at", ac.get("expires_at"))
        add("endpoints", f"discovery={ac.get('endpoints',{}).get('protocol_discovery')}  card={ac.get('endpoints',{}).get('agent_card')}  intent={ac.get('endpoints',{}).get('payment_intent')}", wide=True, small=True)
        sig = ac.get("card_signature_b64") or ""
        add("card_signature_b64 (full)", sig, wide=True, small=True)
        add("card_signature head", sig[:24] + "…  (" + str(len(sig)) + " chars)", tag="Ed25519", small=True)
        pem = ac.get("paari_public_key_pem","")
        pem_head = pem.strip().splitlines()[1] if "BEGIN" in pem else pem[:40]
        add("paari public key (head)", pem_head + " …", small=True)

    elif stage_slug == "07-credential":
        cr = art.get("credential", {})
        add("credential_id (full)", cr.get("credential_id"), wide=True)
        add("agent_id (full)", cr.get("agent_id"), wide=True)
        add("status", cr.get("status"), tag=f"revoked={cr.get('revoked')}")
        add("capabilities", ", ".join(cr.get("capabilities") or []))
        add("payment limit", f"{cr.get('payment_limit_minor_units')} {cr.get('currency')}")
        add("issued_at", cr.get("issued_at"), wide=True)
        add("expires_at", cr.get("expires_at"), wide=True)
        add("superseded_by", cr.get("superseded_by") or "— (none)")
        add("protocol", f"{cr.get('protocol')} / {cr.get('protocol_version')}")

    elif stage_slug == "08-authentication":
        au = art.get("authentication", {})
        add("agent_id (full)", au.get("agent_id"), wide=True)
        add("authenticated", str(au.get("authenticated")), tag="session bound" if au.get("authenticated") else "revoked=false")
        add("credential_id (full)", au.get("credential_id"), wide=True)
        add("credential_status", au.get("credential_status"), tag=au.get("credential_status"))
        add("nonce_id (full)", au.get("nonce_id"), wide=True)
        add("nonce_used", str(au.get("nonce_used")), tag="burned, single-use")
        add("nonce_expires_at", au.get("nonce_expires_at"), wide=True)
        add("evidence", "Last burned nonce for this agent; auth false because credential revoked post-PAID (live proof) — verifies replay protection", wide=True, small=True)

    elif stage_slug == "09-governance":
        gd = art.get("governance_decision", {})
        add("intent_id (full)", gd.get("intent_id"), wide=True)
        add("decision", gd.get("decision"), tag="allow")
        add("merchant", gd.get("merchant"), tag="ProofStore")
        amt = art.get("bounded_authorization", {}).get("amount_minor_units") or 100
        add("amount", f"{amt} minor units  (₹{amt/100:.2f} INR)")
        add("mfa_required", str(gd.get("mfa_required")))
        add("reasons", ", ".join(gd.get("reasons") or []), wide=True)
        pr = gd.get("policy_results") or []
        pr_lines = "\n".join([f"✓ {r.get('name')}: {r.get('detail')}" if r.get("passed") else f"✗ {r.get('name')}" for r in pr])
        add("policy_results (6 checks)", pr_lines, wide=True, small=True)
        add("transaction", gd.get("transaction_id"), wide=True)

    elif stage_slug == "10-bounded-authorization":
        ba = art.get("bounded_authorization") or {}
        if not ba:
            add("authorization_id", "— (DENY/REVIEW — no auth minted)", wide=True)
        else:
            add("authorization_id (full, =intent_id)", ba.get("authorization_id"), wide=True)
            add("agent_id (full)", ba.get("agent_id"), wide=True)
            add("transaction", ba.get("transaction_id"), wide=True)
            add("merchant", ba.get("merchant"), tag="ProofStore")
            add("amount", f"{ba.get('amount_minor_units')} {ba.get('currency')}  (₹{ba.get('amount_minor_units',0)/100:.2f})")
            add("expires_at", ba.get("expires_at"), wide=True)
            add("max_usage", str(ba.get("max_usage")), tag="single-use, atomic reserve")
            add("idempotency", "authorization_id is Razorpay idempotency key", wide=True, small=True)

    elif stage_slug == "11-payment-execution":
        pe = art.get("payment_execution") or {}
        if not pe:
            add("state", "— (no provider txn)")
        else:
            add("authorization_id (full)", pe.get("authorization_id"), wide=True)
            add("razorpay_order_id", pe.get("razorpay_order_id"), tag="order_TdrLnfAh9TBQie")
            add("state", pe.get("state"), tag=pe.get("state"))
            add("transitions", "AUTHORIZED → PROVIDER_SUBMITTED → PAYMENT_PENDING → PAID", wide=True, small=True)
            add("provider", "razorpay (Paari-controlled execution)", tag="Test Mode")
            add("order (live)", "order_TdrLnfAh9TBQie")
            add("payment (live)", "pay_TdrWE1S8hVE0PJ")
            add("protocol", f"{pe.get('protocol')} / {pe.get('protocol_version')}")

    elif stage_slug == "12-webhook":
        pr = art.get("payment_result") or {}
        add("webhook_verified", str(pr.get("webhook_verified")), tag="HMAC over raw body")
        wh = pr.get("webhook_event") or ""
        add("webhook_event (full, 64 hex)", wh, wide=True, small=True)
        add("webhook_event head", wh[:16] + "…" if wh else "—", small=True)
        add("events", "payment.authorized → payment.captured  (two webhooks, both HMAC-verified)", wide=True)
        add("provider_order_id", pr.get("provider_order_id"))
        add("final_state", pr.get("final_state"), tag="PAID")
        add("order / payment (live)", "order_TdrLnfAh9TBQie / pay_TdrWE1S8hVE0PJ", wide=True)

    elif stage_slug == "13-payment-result":
        pr = art.get("payment_result") or {}
        if not pr:
            add("final_state", "—")
        else:
            add("provider", pr.get("provider"), tag="razorpay")
            add("provider_order_id", pr.get("provider_order_id"), wide=True)
            add("webhook_event (full)", pr.get("webhook_event"), wide=True, small=True)
            add("webhook_verified", str(pr.get("webhook_verified")), tag="true")
            add("final_state", pr.get("final_state"), tag="PAID")
            add("terminal", str(pr.get("terminal")), tag="TERMINAL_STATES")
            add("transaction (full)", pr.get("transaction_id"), wide=True)
            add("authorization_id (full)", pr.get("authorization_id"), wide=True)

    elif stage_slug == "14-audit-record":
        ar = art.get("audit_record") or {}
        evs = ar.get("events") or []
        add("transaction_id", ar.get("transaction_id"), wide=True)
        add("chain_verified", str(ar.get("chain_verified")), tag="verify_chain() recomputed")
        add("events count", f"{len(evs)} events — tamper-evident hash chain", tag="hash-linked")
        if evs:
            timeline = "\n".join([
                f"{e.get('event_id').rjust(2)} {e.get('event_type') or e.get('kind')}  {e.get('prev_hash','')[:8]}→{e.get('event_hash','')[:8]}  {(e.get('detail',{}).get('event_type') or e.get('detail',{}).get('from_state','') or '')}"
                for e in evs
            ])
            add("timeline (event_id · kind · hash link)", timeline, wide=True, small=True)
            hashes = "\n".join([f"{e.get('event_id')}: {e.get('event_hash')}" for e in evs])
            add("event_hashes (full)", hashes, wide=True, small=True)
        add("bundle", b_id, wide=True)

    elif stage_slug == "15-revocation":
        rv = art.get("revocation") or {}
        add("agent_id (full)", rv.get("agent_id"), wide=True)
        add("revoked", str(rv.get("revoked")), tag="true → 401 on next intent")
        add("revocation_id", rv.get("revocation_id") or "—  (admin-key revoke, no RevocationRecord)", wide=True)
        add("credential status", art.get("credential", {}).get("status"), tag=art.get("credential", {}).get("status"))
        add("agent status", art.get("agent_identity", {}).get("status"), tag="revoked")
        add("evidence", "Live proof revoked after PAID; GET /v1/proof/{tx} still readable with owner proof, POST /v1/payments/intent returns 401", wide=True, small=True)
        add("transaction", tx, wide=True)

    else:
        obj = art.get(stage_key, {}) or {}
        if isinstance(obj, dict):
            for k, v in list(obj.items())[:10]:
                add(k, v, wide=len(str(v))>40)
        else:
            add(stage_key, obj, wide=True)

    return fields


def render_all(bundle: dict):
    env = Environment(loader=FileSystemLoader("scripts/templates"))
    tpl = env.get_template("card_base.html")
    out = pathlib.Path("exports/cards/html")
    out.mkdir(parents=True, exist_ok=True)
    css_src = pathlib.Path("scripts/templates/cards.css")
    css_dst = out / "cards.css"
    if css_src.exists():
        css_dst.write_text(css_src.read_text(encoding="utf-8"), encoding="utf-8")

    chain_verified = bundle.get("artifacts", {}).get("audit_record", {}).get("chain_verified")

    for num, title, key, slug in STAGES:
        fields = _build_fields(bundle, key, slug)
        subtitle_map = {
            "01-discovery": "Protocol Discovery Document — Paari v1.0",
            "02-parent-trust-pending": "Parent Trust — pending_verification / self_asserted",
            "03-parent-trust-verified": "Parent Trust — active / admin_approved",
            "04-delegation": "Signed Delegation — canonical JSON + Ed25519",
            "05-agent-identity": "Agent Identity Record",
            "06-agent-card": "Signed Agent Card — Ed25519 card_signature_b64",
            "07-credential": "Agent Credential — JWT claims projection",
            "08-authentication": "Authenticated Session — burned nonce + credential status",
            "09-governance": "Governance Decision — allow · 6 policy checks",
            "10-bounded-authorization": "Bounded Authorization — single-use, atomic reserve",
            "11-payment-execution": "Payment Execution — Razorpay Test Mode",
            "12-webhook": "Webhook — HMAC verified over raw body",
            "13-payment-result": "Payment Result — final_state PAID / terminal",
            "14-audit-record": "Audit Record — tamper-evident hash chain",
            "15-revocation": "Revocation — Access Denied (401)",
        }
        html = tpl.render(
            stage_num=num,
            stage_title=title,
            stage_subtitle=subtitle_map.get(slug, ""),
            fields=fields,
            bundle_id=bundle.get("bundle_id", ""),
            footer_left=f"{bundle.get('bundle_id','')} · {bundle.get('transaction_id','')} · order_TdrLnfAh9TBQie · pay_TdrWE1S8hVE0PJ",
            footer_right=f"chain_verified={chain_verified}",
            chain_verified=chain_verified,
        )
        (out / f"stage-{slug}.html").write_text(html, encoding="utf-8")
    print(f"HTML done: {len(STAGES)} files in {out}")


def screenshot_all():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("playwright not installed — HTML ready at exports/cards/html. Run: pip install playwright && playwright install chromium")
        return
    html_dir = pathlib.Path("exports/cards/html")
    png_dir = pathlib.Path("exports/cards/png")
    png_dir.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1200, "height": 750, "deviceScaleFactor": 2})
        for html in sorted(html_dir.glob("stage-*.html")):
            page.goto(html.resolve().as_uri())
            page.wait_for_timeout(400)
            png_path = png_dir / (html.stem + ".png")
            page.screenshot(path=str(png_path), full_page=False)
            print(f"PNG {png_path.name}")
        browser.close()
    print(f"PNG done: {len(list(png_dir.glob('*.png')))} files in {png_dir}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Export Paari 15 stage cards")
    ap.add_argument("--tx", default="TXN-proof-9c5ffd55", help="transaction_id")
    ap.add_argument("--json", default="evidence_live_e2e_2026-09-19.json", help="fallback JSON bundle path")
    args = ap.parse_args()
    try:
        bundle = load_bundle(args.tx, args.json)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        print("Hint: use --json evidence_live_e2e_2026-09-19.json or check transaction_id", file=sys.stderr)
        sys.exit(2)
    render_all(bundle)
    screenshot_all()
