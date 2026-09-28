"""Black-box foreign-agent proof for the Paari protocol (Phase 6 milestone).

A foreign agent - one written against the protocol, not against this repo -
onboards, authenticates, completes a governed REAL Test-Mode payment, and
proves each trust property from the outside. Allowed imports are stdlib +
httpx + cryptography ONLY; importing app.* aborts immediately.

Usage (server already running with Test-Mode keys + public webhook URL):
    set PAARI_ADMIN_API_KEY=<key>   # PowerShell
    python scripts/foreign_agent_proof.py

The proof supports two honest settlement postures:
  * provider-native autonomous mode: consume -> PAID without a browser order;
  * standard provider-order mode: consume -> PROVIDER_SUBMITTED, then a human
    checkout + webhook/reconcile can complete PAID.

Core milestones: discover service; register/approve parent; sign delegation;
agent onboarding; challenge/response auth; signed user mandate; payment
intent + governance; bounded authorization; provider binding; settlement;
audit-chain verification; over-delegation denial; agent revocation; revoked
agent blocking.

For a real provider-native deployment, set PAARI_PROVIDER_MANDATE_REF to the
provider-issued mandate/instrument reference. Reference/simulated providers may
use the harness-owned opaque reference.

Exit codes: 0 all green; 1 any step failed; 2 payment wait timed out.
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def assert_black_box():
    """Refuse to run as a CLI proof if app.* is importable in this process -
    that would mean we are not actually foreign. (The pytest harness imports
    this file for its pure functions, where app.* is legitimately present,
    so the check lives here and runs only from main().)"""
    for _mod in list(sys.modules):
        if _mod == "app" or _mod.startswith("app."):
            sys.exit("ABORT: proof script must not run with app.* imported (black-box violated)")

BASE = os.environ.get("PAARI_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
ADMIN_KEY = os.environ.get("PAARI_ADMIN_API_KEY", "")
PAY_TIMEOUT = int(os.environ.get("PAARI_PAY_TIMEOUT", "600"))
AMOUNT = int(os.environ.get("PAARI_AMOUNT", "100"))  # paise; Rs 1 default

# When set, the transcript must not end green against a server that is not
# actually enforcing mandates. Without it this proof runs in whichever posture
# the server reports - useful for CI, worthless as an autonomy certificate.
AUTONOMOUS_ONLY = os.environ.get("PAARI_REQUIRE_AUTONOMOUS_PROOF", "0") == "1"

# The delegated (parent-signed) cap and the user-mandate cap MUST differ, or the
# "amount above mandate" negative proof tests the wrong layer: the delegated
# limit is checked ~20 lines before the mandate layer runs, so an amount that
# breaches both is denied by the delegation check and the mandate is never
# exercised. DELEGATED_CAP > MANDATE_CAP makes the mandate the binding
# constraint for the over-mandate probe.
DELEGATED_CAP = 500000
MANDATE_CAP = 100000

if not ADMIN_KEY:
    print("warning: PAARI_ADMIN_API_KEY unset (required only for main())",
          file=sys.stderr)

client = httpx.Client(base_url=BASE, timeout=30.0)
RUN = uuid.uuid4().hex[:8]


# --- crypto the foreign agent owns (reimplemented, never imported) ---
def canonical_json(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def canonical_mandate_payload(fields: dict) -> str:
    """Canonical form for user payment mandate cryptographic signing."""
    payload = {
        "purpose": "paari_user_payment_mandate",
        "mandate_version": 1,
        "mandate_id": fields["mandate_id"],
        "user_id": fields["user_id"],
        "agent_id": fields["agent_id"],
        "org_id": fields.get("org_id", "default"),
        "constraints": {
            "currency": fields["currency"],
            "max_per_transaction": int(fields["max_per_transaction"]),
            "max_daily_amount": int(fields["max_daily_amount"]),
            "max_per_hour": int(fields["max_per_hour"]) if fields.get("max_per_hour") is not None else None,
            "max_per_merchant_per_day": (
                int(fields["max_per_merchant_per_day"])
                if fields.get("max_per_merchant_per_day") is not None else None
            ),
            "max_category_per_day": (
                int(fields["max_category_per_day"])
                if fields.get("max_category_per_day") is not None else None
            ),
            "allowed_merchants": sorted(str(m) for m in (fields.get("allowed_merchants") or [])),
            "allowed_categories": sorted(str(c) for c in (fields.get("allowed_categories") or [])),
            "require_review_above": (
                int(fields["require_review_above"])
                if fields.get("require_review_above") is not None else None
            ),
        },
        "issued_at": int(datetime.fromisoformat(str(fields["valid_from"]).replace("+00:00", "+00:00")).timestamp()),
        "expires_at": int(datetime.fromisoformat(str(fields["expires_at"])).timestamp()),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def generate_keypair() -> tuple[str, str]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return (
        priv.private_bytes(serialization.Encoding.PEM,
                           serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption()).decode(),
        pub.public_bytes(serialization.Encoding.PEM,
                         serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
    )


def sign_message(private_pem: str, message: str) -> str:
    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    return base64.b64encode(key.sign(message.encode())).decode()


def verify_message(public_pem: str, message: str, signature_b64: str) -> bool:
    try:
        key = serialization.load_pem_public_key(public_pem.encode())
        key.verify(base64.b64decode(signature_b64), message.encode())
        return True
    except (InvalidSignature, ValueError):
        return False


def fingerprint(public_pem: str) -> str:
    return hashlib.sha256(public_pem.encode()).hexdigest()


def sign_envelope(private_pem: str, type: str, ids: dict, payload: dict,
                  ttl_seconds: int = 300) -> dict:
    now = int(time.time())
    env = {"protocol": "paari", "version": "1.0", "type": type,
           "message_id": ids.get("message_id", str(uuid.uuid4())),
           "sender": ids.get("sender", ""), "receiver": ids.get("receiver", "paari"),
           "issued_at": now, "expires_at": now + ttl_seconds,
           "payload": payload}
    env["signature"] = sign_message(private_pem, canonical_json(env))
    return env


def verify_envelope(public_pem: str, envelope: dict) -> bool:
    try:
        if envelope.get("protocol") != "paari" or envelope.get("version") != "1.0":
            return False
        if int(envelope.get("expires_at", 0)) < int(time.time()):
            return False
        unsigned = {k: v for k, v in envelope.items() if k != "signature"}
        return verify_message(public_pem, canonical_json(unsigned),
                              envelope.get("signature", ""))
    except Exception:
        return False


# --- sender-constrained request proof ---
def sign_request_proof(private_pem: str, method: str, path: str, access_token: str, agent_id: str) -> str:
    now = int(time.time())
    ath = base64.urlsafe_b64encode(hashlib.sha256(access_token.encode()).digest()).rstrip(b"=").decode()
    claims = {"typ": "paari-proof", "alg": "EdDSA", "sub": agent_id, "htm": method.upper(),
              "htu": path, "iat": now, "jti": str(uuid.uuid4()), "ath": ath}
    return jwt_encode(private_pem, claims)


def jwt_encode(private_pem: str, claims: dict) -> str:
    header = {"alg": "EdDSA", "typ": "paari-proof+jwt", "kid": "agent"}
    def b64url(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    encoded_header = b64url(canonical_json(header).encode())
    encoded_payload = b64url(canonical_json(claims).encode())
    signing_input = f"{encoded_header}.{encoded_payload}"
    return signing_input + "." + b64url(serialization.load_pem_private_key(private_pem.encode(), password=None).sign(signing_input.encode()))


# --- wire helpers ---
def check(name: str, cond: bool, evidence):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}: {evidence}", flush=True)
    if not cond:
        sys.exit(f"milestone failed at: {name}")


def main() -> int:
    assert_black_box()
    if not ADMIN_KEY:
        sys.exit("ABORT: set PAARI_ADMIN_API_KEY to the server's admin key first")
    admin_headers = {"X-Admin-Api-Key": ADMIN_KEY}

    # 1. discover
    r = client.get("/health")
    check("1. service healthy", r.status_code == 200, r.json())
    health_data = r.json()
    # Posture and provider come from the SERVER, never inferred from this
    # script's own environment. Reading `RAZORPAY_KEY_ID` here would let the
    # harness print `Provider: real-razorpay` about a server pointed at a
    # simulator, which is the false green this transcript is meant to prevent.
    mandate_mode = health_data.get("mandate_mode", "unknown")
    server_provider = health_data.get("provider", "unknown")
    provider_environment = health_data.get("provider_environment", "unknown")
    agentic_server_provider = health_data.get("agentic_provider", "unknown")
    agentic_server_environment = health_data.get("agentic_provider_environment", "unknown")
    print("\n" + "=" * 48)
    print(" Paari Foreign Agent Proof")
    print(f" Mode:     {mandate_mode}")
    if health_data.get("autonomous_settlement") is True:
        print(f" Provider: {agentic_server_provider} (environment: {agentic_server_environment})")
    else:
        print(f" Provider: {server_provider} (environment: {provider_environment})")
    print(f" LLM:      deterministic")
    print("=" * 48 + "\n", flush=True)
    if AUTONOMOUS_ONLY:
        check("1b. server is in the autonomous posture this proof requires",
              mandate_mode == "autonomous" and health_data.get("mandate_required") is True,
              {"mandate_mode": mandate_mode,
               "mandate_required": health_data.get("mandate_required")})

    # 2. parent registers (untrusted by default)
    parent_priv, parent_pub = generate_keypair()
    r = client.post("/parents/register", json={
        "name": f"Proof Parent {RUN}", "parent_type": "developer",
        "contact": "proof@example.com", "public_key_pem": parent_pub})
    check("2. parent pending", r.status_code == 200
          and r.json()["status"] == "pending_verification", r.json())
    parent_id = r.json()["parent_id"]

    # 3. admin approves
    r = client.post(f"/parents/{parent_id}/approve", headers=admin_headers)
    check("3. parent approved", r.status_code == 200
          and r.json()["status"] == "active", r.json())

    # 4. parent signs delegation locally
    agent_priv, agent_pub = generate_keypair()
    now = datetime.now(timezone.utc)
    delegation = {
        "delegation_id": str(uuid.uuid4()), "parent_id": parent_id,
        "agent_public_key_fingerprint": fingerprint(agent_pub),
        "granted_capabilities": ["make_payment"],
        "payment_limit_minor_units": DELEGATED_CAP, "currency": "INR",
        "issued_at": int(now.timestamp()),
        "expires_at": int((now + timedelta(days=30)).timestamp())}
    delegation_sig = sign_message(parent_priv, canonical_json(delegation))
    check("4. delegation self-verifies",
          verify_message(parent_pub, canonical_json(delegation), delegation_sig),
          {"delegation_id": delegation["delegation_id"]})

    # 5. v1 enveloped onboarding (asks for MORE than delegated: must be ignored)
    payload = {"name": f"Proof Agent {RUN}", "agent_type": "shopping_assistant",
               "purpose": "black-box milestone", "public_key_pem": agent_pub,
               "delegation": delegation, "delegation_signature_b64": delegation_sig,
               "requested_permissions": {"payment_limit_minor_units": 99999999}}
    envelope = sign_envelope(agent_priv, "agent.register", {"sender": fingerprint(agent_pub), "receiver": "paari"}, payload, 300)
    r = client.post("/v1/agents/register", json={"envelope": envelope})
    check("5. v1 register ok", r.status_code == 200, r.json().get("agent_card"))
    card = r.json()["agent_card"]
    check("5b. card bound by delegation, not request",
          card["limits"]["max_amount"] == 500000
          and card["capabilities"] == ["payment.create"], card)
    agent_id, credential_jwt = card["agent_id"], r.json()["credential_jwt"]

    # 6. card is discovery-only
    r = client.get(f"/v1/agents/{agent_id}/card")
    check("6. card discovery-only",
          r.status_code == 200 and r.json()["issuer"] == "paari"
          and "credential_jwt" not in r.json(), r.json())

    # 7. challenge/response auth
    r = client.post("/v1/auth/challenge", json={"agent_id": agent_id})
    check("7a. challenge issued", r.status_code == 200, r.json())
    nonce = r.json()["nonce"]
    r = client.post("/v1/auth/verify", json={
        "agent_id": agent_id, "nonce": nonce,
        "signature_b64": sign_message(agent_priv, nonce),
        "credential_jwt": credential_jwt})
    check("7b. authenticated", r.status_code == 200
          and r.json()["authenticated"] is True, {"session": True})
    session = r.json()["session_token"]

    # ---- User Mandate Setup & Negative Proofs ----
    user_priv, user_pub = generate_keypair()
    now_mandate = datetime.now(timezone.utc)

    # 7c. Negative proof: forged mandate signature is rejected
    forged_fields = {
        "mandate_id": f"UM-FORGED-{RUN}",
        "user_id": f"proof-user-{RUN}",
        "agent_id": agent_id,
        "max_per_transaction": 100000,
        "max_daily_amount": 200000,
        "currency": "INR",
        "valid_from": now_mandate.isoformat(),
        "expires_at": (now_mandate + timedelta(days=30)).isoformat(),
    }
    forged_sig = sign_message(user_priv, json.dumps({"tampered": True}))
    r = client.post("/v1/mandates", json={
        **forged_fields,
        "user_public_key_pem": user_pub,
        "mandate_signature_b64": forged_sig,
        "signing_key_id": f"user-key-{RUN}",
    }, headers=admin_headers)
    check("7c. forged mandate rejected (400)", r.status_code == 400,
          {"http": r.status_code, "detail": r.text[:120]})

    # 7d. Negative proof: expired mandate is rejected/denied
    exp_start = (now_mandate - timedelta(days=5)).isoformat()
    exp_end = (now_mandate - timedelta(days=2)).isoformat()
    expired_fields = {
        "mandate_id": f"UM-EXPIRED-{RUN}",
        "user_id": f"proof-user-{RUN}",
        "agent_id": agent_id,
        "max_per_transaction": 100000,
        "max_daily_amount": 200000,
        "currency": "INR",
        "valid_from": exp_start,
        "expires_at": exp_end,
    }
    canonical_exp = canonical_mandate_payload(expired_fields)
    r = client.post("/v1/mandates", json={
        **expired_fields,
        "user_public_key_pem": user_pub,
        "mandate_signature_b64": sign_message(user_priv, canonical_exp),
        "signing_key_id": f"user-key-{RUN}",
    }, headers=admin_headers)
    check("7d. expired mandate recorded", r.status_code == 200, r.json())
    r_exp_intent = client.post("/v1/payments/intent", json={
        "agent_id": agent_id,
        "transaction_id": f"TXN-exp-{RUN}",
        "idempotency_key": f"idem-exp-{RUN}", "merchant": "ProofStore",
        "amount_minor_units": AMOUNT, "currency": "INR",
        "action": "make_payment", "purpose": "expired mandate test",
        "mandate_id": f"UM-EXPIRED-{RUN}"},
        headers={"Authorization": f"Bearer {session}",
                 "X-Paari-Proof": sign_request_proof(agent_priv, "POST", "/v1/payments/intent", session, agent_id)})
    check("7d-ii. expired mandate DENIES intent",
          r_exp_intent.status_code == 200 and r_exp_intent.json().get("decision") == "deny",
          {"decision": r_exp_intent.json().get("decision"), "reasons": r_exp_intent.json().get("reasons")})

    # 7e. Negative proof: revoked mandate is rejected/denied
    rev_fields = {
        "mandate_id": f"UM-REVOKED-{RUN}",
        "user_id": f"proof-user-{RUN}",
        "agent_id": agent_id,
        "max_per_transaction": 100000,
        "max_daily_amount": 200000,
        "currency": "INR",
        "valid_from": now_mandate.isoformat(),
        "expires_at": (now_mandate + timedelta(days=30)).isoformat(),
    }
    canonical_rev = canonical_mandate_payload(rev_fields)
    r = client.post("/v1/mandates", json={
        **rev_fields,
        "user_public_key_pem": user_pub,
        "mandate_signature_b64": sign_message(user_priv, canonical_rev),
        "signing_key_id": f"user-key-{RUN}",
    }, headers=admin_headers)
    r_rev = client.post(f"/v1/mandates/{rev_fields['mandate_id']}/revoke", json={"reason": "proof revocation test"},
                        headers=admin_headers)
    check("7e. mandate revoked", r_rev.status_code == 200 and r_rev.json()["status"] == "revoked", r_rev.json())
    r_rev_intent = client.post("/v1/payments/intent", json={
        "agent_id": agent_id,
        "transaction_id": f"TXN-rev-{RUN}",
        "idempotency_key": f"idem-rev-{RUN}", "merchant": "ProofStore",
        "amount_minor_units": AMOUNT, "currency": "INR",
        "action": "make_payment", "purpose": "revoked mandate test",
        "mandate_id": f"UM-REVOKED-{RUN}"},
        headers={"Authorization": f"Bearer {session}",
                 "X-Paari-Proof": sign_request_proof(agent_priv, "POST", "/v1/payments/intent", session, agent_id)})
    check("7e-ii. revoked mandate DENIES intent",
          r_rev_intent.status_code == 200 and r_rev_intent.json().get("decision") == "deny",
          {"decision": r_rev_intent.json().get("decision"), "reasons": r_rev_intent.json().get("reasons")})

    # 7f. Positive proof: create cryptographically signed user mandate
    mandate_fields = {
        "mandate_id": f"UM-ACTIVE-{RUN}",
        "user_id": f"proof-user-{RUN}",
        "agent_id": agent_id,
        "max_per_transaction": MANDATE_CAP,
        "max_daily_amount": 1000000,
        "max_per_hour": MANDATE_CAP,
        "max_per_merchant_per_day": MANDATE_CAP,
        "currency": "INR",
        "allowed_merchants": ["ProofStore"],
        "allowed_categories": [],
        "valid_from": now_mandate.isoformat(),
        "expires_at": (now_mandate + timedelta(days=30)).isoformat(),
        "approval_reference": f"user-consent-{RUN}",
    }
    canonical_valid = canonical_mandate_payload(mandate_fields)
    valid_sig = sign_message(user_priv, canonical_valid)
    r = client.post("/v1/mandates", json={
        **mandate_fields,
        "user_public_key_pem": user_pub,
        "mandate_signature_b64": valid_sig,
        "signing_key_id": f"user-key-{RUN}",
    }, headers=admin_headers)
    check("7f. signed user mandate active & signature verified",
          r.status_code == 200 and r.json()["status"] == "active" and r.json()["signature_valid"] is True,
          {"mandate_id": r.json().get("mandate_id"), "signature_valid": r.json().get("signature_valid")})
    active_mandate_id = r.json()["mandate_id"]

    # 7g. Agent reads its active user payment authority
    auth_path = f"/v1/mandates/active/{agent_id}"
    r = client.get(auth_path, headers={
        "Authorization": f"Bearer {session}",
        "X-Paari-Proof": sign_request_proof(agent_priv, "GET", auth_path, session, agent_id),
    })
    check("7g. agent reads payment authority",
          r.status_code == 200 and r.json()["mandate_id"] == active_mandate_id
          and r.json()["signature_valid"] is True
          and r.json()["max_per_transaction"] == MANDATE_CAP,
          {"mandate_id": r.json().get("mandate_id"), "signature_valid": r.json().get("signature_valid"),
           "max_per_transaction": r.json().get("max_per_transaction")})

    # 7h. Negative proof: the amount breaches the USER MANDATE but not the
    # delegated cap, so the denial can only come from the mandate layer.
    # Asserting the reason, not just `decision == "deny"`, is what distinguishes
    # "the mandate stopped it" from "some other check stopped it".
    above_mandate = MANDATE_CAP + 50000
    check("7h. probe is over mandate yet under delegation",
          MANDATE_CAP < above_mandate <= DELEGATED_CAP,
          {"above_mandate": above_mandate, "mandate_cap": MANDATE_CAP,
           "delegated_cap": DELEGATED_CAP})
    r = client.post("/v1/payments/intent", json={
        "agent_id": agent_id,
        "transaction_id": f"TXN-above-mandate-{RUN}",
        "idempotency_key": f"idem-above-mandate-{RUN}", "merchant": "ProofStore",
        "amount_minor_units": above_mandate,
        "currency": "INR",
        "action": "make_payment", "purpose": "above mandate limit",
        "mandate_id": active_mandate_id},
        headers={"Authorization": f"Bearer {session}",
                 "X-Paari-Proof": sign_request_proof(agent_priv, "POST", "/v1/payments/intent", session, agent_id)})
    denied_reasons = " ".join(r.json().get("reasons", [])) if r.status_code == 200 else ""
    check("7h. amount above mandate DENIED by the mandate",
          r.status_code == 200 and r.json().get("decision") == "deny"
          and "mandate" in denied_reasons.lower()
          and "delegated limit" not in denied_reasons.lower(),
          {"decision": r.json().get("decision"), "reasons": r.json().get("reasons")})

    # Provider-native autonomous binding must exist before the payment intent is
    # created, so the proof never mints an authorization that cannot execute.
    autonomous_capable = health_data.get("autonomous_settlement") is True
    agentic_environment = health_data.get("agentic_provider_environment", "unknown")
    agentic_provider = health_data.get("agentic_provider", "unknown")

    provider_mandate_ref = os.environ.get("PAARI_PROVIDER_MANDATE_REF", "")
    if autonomous_capable:
        # A conformance/reference provider can accept an opaque harness-owned
        # reference. A real provider must receive an actual provider-issued
        # mandate/instrument reference; this proof must never invent one.
        if agentic_environment in ("simulated", "reference") or agentic_provider == "ReferenceAutonomousProvider":
            provider_mandate_ref = provider_mandate_ref or f"provider-mandate-{active_mandate_id}"
        else:
            check("7i. real autonomous provider mandate reference supplied",
                  bool(provider_mandate_ref),
                  {"agentic_provider": agentic_provider,
                   "agentic_provider_environment": agentic_environment,
                   "required_env": "PAARI_PROVIDER_MANDATE_REF"})

        bind = client.post(
            f"/v1/mandates/{active_mandate_id}/provider-binding",
            json={
                "provider": agentic_provider,
                "provider_mandate_ref": provider_mandate_ref,
                "currency": "INR",
                "max_amount_minor_units": MANDATE_CAP,
            },
            headers=admin_headers,
        )
        check("7j. autonomous provider mandate/instrument bound",
              bind.status_code == 200,
              bind.text[:250])

    # 8. intent within limits (under active user mandate)
    tx = f"TXN-proof-{RUN}"
    r = client.post("/v1/payments/intent", json={
        "agent_id": agent_id,
        "transaction_id": tx,
        "idempotency_key": f"idem-proof-{RUN}", "merchant": "ProofStore",
        "amount_minor_units": AMOUNT, "currency": "INR",
        "action": "make_payment", "purpose": "milestone payment",
        "mandate_id": active_mandate_id,
        "llm_run_id": f"RUN-{RUN}",
        "llm_model": "deterministic-foreign-agent-harness",
        "llm_tool_call_id": f"call_{RUN}",
        "llm_tool_name": "propose_payment"},
        headers={"Authorization": f"Bearer {session}",
                 "X-Paari-Proof": sign_request_proof(agent_priv, "POST", "/v1/payments/intent", session, agent_id)})
    intent_view = r.json() if r.content else {}
    intent_evidence = {
        "decision": intent_view.get("decision"),
        "mandate_id": intent_view.get("mandate_id"),
        "authorization_id": (intent_view.get("authorization") or {}).get("authorization_id"),
        "mfa_required": intent_view.get("mfa_required"),
        "max_usage": (intent_view.get("authorization") or {}).get("max_usage"),
    }
    check("8. intent ALLOW", r.status_code == 200
          and intent_view.get("decision") == "allow", intent_evidence)
    # The server discards any client-asserted mandate_id and re-derives which
    # mandate governed this payment. Asserting the derived value is what proves
    # THIS mandate governed the payment - sending mandate_id alone proves nothing.
    check("8b. intent governed by the active signed mandate",
          r.json().get("mandate_id") == active_mandate_id,
          {"server_mandate_id": r.json().get("mandate_id"),
           "expected": active_mandate_id})
    auth_id = intent_view["authorization"]["authorization_id"]

    # 9. consume -> either provider-native autonomous PAID or the legacy
    # provider-order boundary. The server's health posture is authoritative.
    consume_path = f"/v1/payments/authorizations/{auth_id}/consume"
    r = client.post(consume_path, json={},
                    headers={"Authorization": f"Bearer {session}",
                             "X-Paari-Proof": sign_request_proof(agent_priv, "POST", consume_path, session, agent_id)})
    consumed = r.json() if r.content else {}

    if autonomous_capable:
        payment_id = consumed.get("razorpay_payment_id") or ""
        check("9. provider-native autonomous settlement -> PAID",
              r.status_code == 200
              and consumed.get("state") == "PAID"
              and consumed.get("consumed") is True
              and payment_id.startswith("pay_"),
              {"http": r.status_code,
               "state": consumed.get("state"),
               "provider_payment_id": payment_id,
               "order_id": consumed.get("razorpay_order_id"),
               "agentic_provider": agentic_provider,
               "agentic_provider_environment": agentic_environment})

        # A provider-native autonomous payment must not expose or require a
        # browser order. There should be no normal checkout order in this path.
        check("9b. autonomous settlement has no browser-order artifact",
              not consumed.get("razorpay_order_id"),
              {"razorpay_order_id": consumed.get("razorpay_order_id")})

        replay_resp = client.post(consume_path, json={},
                                  headers={"Authorization": f"Bearer {session}",
                                           "X-Paari-Proof": sign_request_proof(agent_priv, "POST", consume_path, session, agent_id)})
        replay_ok = replay_resp.status_code == 409
        replay_detail = replay_resp.text[:160]
        check("10. authorization replay refused", replay_ok,
              {"http": replay_resp.status_code, "detail": replay_detail})

        audit_path = f"/v1/audit/{tx}"
        r = client.get(audit_path, headers={
            "Authorization": f"Bearer {session}",
            "X-Paari-Proof": sign_request_proof(agent_priv, "GET", audit_path, session, agent_id)})
        if r.status_code != 200:
            sys.exit(f"milestone failed at: 11. cannot read audit trail "
                     f"(HTTP {r.status_code}: {r.text[:200]})")
        events = r.json().get("events", [])
        kinds = [e.get("kind") for e in events]
        prev = "GENESIS"
        chain_ok = True
        for e in events:
            if e.get("hash_version", 1) == 1:
                payload = e["detail"]
                expected = hashlib.sha256((prev + canonical_json(payload)).encode()).hexdigest()
            else:
                payload = {
                    "prev_hash": prev,
                    "kind": e["kind"],
                    "agent_id": e["agent_id"],
                    "parent_id": e.get("parent_id"),
                    "org_id": e["org_id"],
                    "transaction_id": e["transaction_id"],
                    "created_at": e["created_at"],
                    "detail": e["detail"],
                }
                expected = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
            if e["prev_hash"] != prev or expected != e["event_hash"]:
                chain_ok = False
                break
            prev = e["event_hash"]
        check("11. autonomous audit chain verified through PAID",
              chain_ok
              and kinds[:2] == ["llm_tool_call", "intent_decided"]
              and "authorization_consumed" in kinds
              and "provider_submitted" in kinds
              and kinds[-1] == "agentic_settlement",
              {"chain_verified": chain_ok, "kinds": kinds, "hash_version": events[-1].get("hash_version") if events else None})

        print("[PASS] 12. provider-native autonomous settlement completed with NO HUMAN CHECKOUT", flush=True)

        # 13-15 remain the authorization-boundary and revocation tests below.
    else:
        order_id_value = (consumed.get("razorpay_order_id") or "") if r.status_code == 200 else ""
        provider_says_real = provider_environment in ("test", "live")
        check("9. consume submitted", r.status_code == 200
              and consumed.get("state") == "PROVIDER_SUBMITTED"
              and order_id_value.startswith("order_"), consumed)
        # A simulator also issues ids shaped like `order_...`, so shape alone cannot
        # corroborate the provider label. Refuse a simulated-looking id when the
        # server claims a real provider.
        check("9b. order id agrees with the server's provider environment",
              not provider_says_real or not order_id_value.startswith("order_SIM"),
              {"provider_environment": provider_environment,
               "razorpay_order_id": order_id_value})
        order_id = order_id_value

        # 10. pay in browser; poll audit for the verified webhook
        if PAY_TIMEOUT <= 0:
            print(f"[SKIP] 10-12. PAARI_PAY_TIMEOUT={PAY_TIMEOUT}: skipping human checkout wait and settlement reconcile", flush=True)
        else:
            print(f"[WAIT] pay order {order_id} for Rs {AMOUNT / 100:.2f} in Test Mode, "
                  f"then the webhook settles it (waiting up to {PAY_TIMEOUT}s)...",
                  flush=True)
            deadline = time.time() + PAY_TIMEOUT
            paid = False
            audit_path = f"/v1/audit/{tx}"

            def _audit_events():
                resp = client.get(audit_path, headers={
                    "Authorization": f"Bearer {session}",
                    "X-Paari-Proof": sign_request_proof(agent_priv, "GET", audit_path, session, agent_id)})
                if resp.status_code != 200:
                    sys.exit(f"milestone failed at: 10. cannot read audit trail "
                             f"(HTTP {resp.status_code}: {resp.text[:200]}) - this is a "
                             "harness/authentication fault, NOT evidence that the provider failed to settle")
                return resp.json().get("events", [])

            while time.time() < deadline:
                time.sleep(10)
                events = _audit_events()
                if any(e["detail"].get("to_state") == "PAID"
                       and e["kind"] in ("settlement_confirmed", "reconciled", "webhook_applied")
                       for e in events):
                    paid = True
                    break
            if not paid:
                print(f"[FAIL] 10. no webhook_applied/PAID for {tx} within timeout "
                      f"(the audit trail WAS readable throughout, so this is a genuine "
                      f"non-settlement)", flush=True)
                return 2
            print("[PASS] 10. webhook captured: PAID", flush=True)

            reconcile_path = f"/v1/reconcile/{auth_id}"
            r = client.post(reconcile_path, json={},
                            headers={"Authorization": f"Bearer {session}",
                                     "X-Paari-Proof": sign_request_proof(agent_priv, "POST", reconcile_path, session, agent_id)})
            check("11. reconciled PAID", r.status_code == 200
                  and r.json()["state"] == "PAID", r.json())

            r = client.get(audit_path, headers={
                "Authorization": f"Bearer {session}",
                "X-Paari-Proof": sign_request_proof(agent_priv, "GET", audit_path, session, agent_id)})
            if r.status_code != 200:
                sys.exit(f"milestone failed at: 12. cannot read audit trail "
                         f"(HTTP {r.status_code}: {r.text[:200]})")
            events = r.json()["events"]
            kinds = [e["kind"] for e in events]
            prev = "GENESIS"
            chain_ok = True
            for e in events:
                if hashlib.sha256((prev + canonical_json(e["detail"])).encode()).hexdigest() != e["event_hash"]:
                    chain_ok = False
                    break
                prev = e["event_hash"]
            check("12. audit chain verified",
                  chain_ok
                  and "webhook_applied" in kinds
                  and kinds[-1] in ("settlement_confirmed", "reconciled", "webhook_applied"), kinds)

    # 13. over-delegation denied
    r = client.post("/v1/payments/intent", json={
        "agent_id": agent_id,
        "transaction_id": f"{tx}-over",
        "idempotency_key": f"idem-proof-{RUN}-over", "merchant": "ProofStore",
        "amount_minor_units": 50000000, "currency": "INR",
        "action": "make_payment", "purpose": "over limit",
        "mandate_id": active_mandate_id},
        headers={"Authorization": f"Bearer {session}",
                 "X-Paari-Proof": sign_request_proof(agent_priv, "POST", "/v1/payments/intent", session, agent_id)})
    check("13. over-delegation DENY", r.status_code == 200
          and r.json()["decision"] == "deny", r.json()["decision"])

    # 14. revoke
    r = client.post(f"/agents/{agent_id}/revoke", headers=admin_headers, json={})
    check("14. agent revoked", r.status_code == 200
          and r.json()["status"] == "revoked", r.json())

    # 15. revoked agent blocked
    r = client.post("/v1/auth/challenge", json={"agent_id": agent_id})
    blocked = r.status_code == 401
    r2 = client.post("/v1/payments/intent", json={
        "agent_id": agent_id,
        "transaction_id": f"{tx}-post",
        "idempotency_key": f"idem-proof-{RUN}-post", "merchant": "ProofStore",
        "amount_minor_units": AMOUNT, "currency": "INR",
        "action": "make_payment", "purpose": "post-revocation",
        "mandate_id": active_mandate_id},
        headers={"Authorization": f"Bearer {session}",
                 "X-Paari-Proof": sign_request_proof(agent_priv, "POST", "/v1/payments/intent", session, agent_id)})
    blocked = blocked and (r2.status_code == 401 or r2.json().get("decision") == "deny")
    check("15. revoked blocked", blocked,
          {"challenge": r.status_code, "intent": r2.json()})

    if autonomous_capable:
        print("\nMILESTONE GREEN: provider-native autonomous settlement reached PAID without human checkout", flush=True)
    elif PAY_TIMEOUT <= 0:
        print("\nMILESTONE PARTIAL: governance through provider-order-creation passed; "
              "settlement (steps 10-12) was SKIPPED, so nothing here proves PAID.",
              flush=True)
    else:
        print("\nMILESTONE GREEN: every proof step including settlement passed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
