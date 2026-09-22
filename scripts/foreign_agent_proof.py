"""Black-box foreign-agent proof for the Paari protocol (Phase 6 milestone).

A foreign agent - one written against the protocol, not against this repo -
onboards, authenticates, completes a governed REAL Test-Mode payment, and
proves each trust property from the outside. Allowed imports are stdlib +
httpx + cryptography ONLY; importing app.* aborts immediately.

Usage (server already running with Test-Mode keys + public webhook URL):
    set PAARI_ADMIN_API_KEY=<key>   # PowerShell
    python scripts/foreign_agent_proof.py

The 15 milestone steps (each prints PASS with its raw evidence):
  1. discover service (GET /health)
  2. parent registers -> pending_verification (never trusted by default)
  3. admin approves parent -> active
  4. parent signs delegation locally (this file's own crypto, not the server's)
  5. agent onboards via v1 envelope -> card limits match the DELEGATION
     (requested_permissions in the payload are ignored)
  6. agent card is signed discovery-only (no credential authority)
  7. challenge/response authentication -> session token
  8. payment intent within limits -> ALLOW + bounded authorization
  9. consume -> PROVIDER_SUBMITTED + real razorpay_order_id
 10. browser pays the order; webhook captured (polled via audit chain)
 11. manual reconcile -> state PAID
 12. audit chain is complete and hash-verified locally (tamper-evident)
 13. over-delegation intent -> DENY
 14. admin revokes the agent -> revoked
 15. revoked agent is blocked (challenge 401, intent denied)

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

if not ADMIN_KEY:
    print("warning: PAARI_ADMIN_API_KEY unset (required only for main())",
          file=sys.stderr)

client = httpx.Client(base_url=BASE, timeout=30.0)
RUN = uuid.uuid4().hex[:8]


# --- crypto the foreign agent owns (reimplemented, never imported) ---
def canonical_json(payload: dict) -> str:
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
        "payment_limit_minor_units": 500000, "currency": "INR",
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

    # 8. intent within limits
    tx = f"TXN-proof-{RUN}"
    r = client.post("/v1/payments/intent", json={
        "agent_id": agent_id,
        "transaction_id": tx,
        "idempotency_key": f"idem-proof-{RUN}", "merchant": "ProofStore",
        "amount_minor_units": AMOUNT, "currency": "INR",
        "action": "make_payment", "purpose": "milestone payment"},
        headers={"Authorization": f"Bearer {session}",
                 "X-Paari-Proof": sign_request_proof(agent_priv, "POST", "/v1/payments/intent", session, agent_id)})
    check("8. intent ALLOW", r.status_code == 200
          and r.json()["decision"] == "allow", r.json())
    auth_id = r.json()["authorization"]["authorization_id"]

    # 9. consume -> real order
    consume_path = f"/v1/payments/authorizations/{auth_id}/consume"
    r = client.post(consume_path, json={},
                    headers={"Authorization": f"Bearer {session}",
                             "X-Paari-Proof": sign_request_proof(agent_priv, "POST", consume_path, session, agent_id)})
    check("9. consume submitted", r.status_code == 200
          and r.json()["state"] == "PROVIDER_SUBMITTED"
          and r.json()["razorpay_order_id"].startswith("order_"), r.json())
    order_id = r.json()["razorpay_order_id"]

    # 10. pay in browser; poll audit for the verified webhook
    print(f"[WAIT] pay order {order_id} for Rs {AMOUNT / 100:.2f} in Test Mode, "
          f"then the webhook settles it (waiting up to {PAY_TIMEOUT}s)...",
          flush=True)
    deadline = time.time() + PAY_TIMEOUT
    paid = False
    while time.time() < deadline:
        time.sleep(10)
        events = client.get(f"/v1/audit/{tx}",
                            headers={"Authorization": f"Bearer {session}"}).json().get("events", [])
        if any(e["kind"] == "webhook_applied" and e["detail"].get("to_state") == "PAID"
               for e in events):
            paid = True
            break
    if not paid:
        print(f"[FAIL] 10. no webhook_applied/PAID for {tx} within timeout")
        return 2
    print("[PASS] 10. webhook captured: PAID", flush=True)

    # 11. reconcile agrees
    reconcile_path = f"/v1/reconcile/{auth_id}"
    r = client.post(reconcile_path, json={},
                    headers={"Authorization": f"Bearer {session}",
                             "X-Paari-Proof": sign_request_proof(agent_priv, "POST", reconcile_path, session, agent_id)})
    check("11. reconciled PAID", r.status_code == 200
          and r.json()["state"] == "PAID", r.json())

    # 12. audit chain complete + locally hash-verified
    r = client.get(f"/v1/audit/{tx}", headers={"Authorization": f"Bearer {session}"})
    events = r.json()["events"]
    kinds = [e["kind"] for e in events]
    prev = "GENESIS"
    chain_ok = True
    for e in events:
        if hashlib.sha256((prev + canonical_json(e["detail"])).encode()
                          ).hexdigest() != e["event_hash"]:
            chain_ok = False
            break
        prev = e["event_hash"]
    check("12. audit chain verified",
          r.status_code == 200 and chain_ok
          and "webhook_applied" in kinds
          and kinds[-1] in ("webhook_applied", "reconciled"), kinds)

    # 13. over-delegation denied
    r = client.post("/v1/payments/intent", json={
        "agent_id": agent_id,
        "transaction_id": f"{tx}-over",
        "idempotency_key": f"idem-proof-{RUN}-over", "merchant": "ProofStore",
        "amount_minor_units": 50000000, "currency": "INR",
        "action": "make_payment", "purpose": "over limit"},
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
        "action": "make_payment", "purpose": "post-revocation"},
        headers={"Authorization": f"Bearer {session}",
                 "X-Paari-Proof": sign_request_proof(agent_priv, "POST", "/v1/payments/intent", session, agent_id)})
    blocked = blocked and (r2.status_code == 401 or r2.json().get("decision") == "deny")
    check("15. revoked blocked", blocked,
          {"challenge": r.status_code, "intent": r2.json()})

    print("MILESTONE GREEN: 15/15 steps passed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
