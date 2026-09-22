"""
End-to-end demo of the full, hardened trust chain:

  Parent registers (its own Ed25519 key pair) -> lands PENDING_VERIFICATION
       -> an admin approves it (POST /parents/{id}/approve, admin key)
       -> parent signs a delegation document for a specific agent public key
  Agent registers, presenting the signed delegation
       -> Paari verifies the parent's signature, binds capabilities/limits
          from the delegation (NOT from the agent's own request)
       -> receives a signed Agent Card
  Agent authenticates (challenge/response proof-of-possession)
       -> receives a short-lived session token
  Agent submits a payment intent within limits
       -> Phase 3 governance engine runs identity/authority/capability/
          limit/policy/risk checks -> ALLOW
       -> Phase 4 issues a single-use bounded authorization
  Bounded authorization is consumed once, authenticated with the agent's
  own session token
       -> Phase 5 creates a REAL Razorpay Order (needs RAZORPAY_KEY_ID /
          RAZORPAY_KEY_SECRET in the server's environment; without them
          consume fails closed with 502 and the single-use stays spent).
          With keys set, the response carries state + razorpay_order_id,
          and Razorpay posts payment events to /payments/webhooks/razorpay
          (verified with RAZORPAY_WEBHOOK_SECRET), advancing the
          ProviderTransaction to PAID.
       -> a second attempt to consume it is rejected (single-use)
       -> an attempt to consume it with no session token is rejected (P0 fix)
  Agent submits a payment intent close to its limit
       -> governance parks it on REVIEW with mfa_required=true
       -> the agent requests a step-up challenge WITH its session token
          (anonymous challenge requests are rejected)
       -> the PARENT signs the challenge (a different key than the
          agent's) and the intent is promoted to ALLOW
  Agent submits a payment intent OVER its delegated limit -> DENY
  Admin revokes the agent -> a further payment intent is DENIED

Run the server first:
    export PAARI_ADMIN_API_KEY=dev-admin-key   # or read the generated one from server logs
    export RAZORPAY_KEY_ID=rzp_test_xxx RAZORPAY_KEY_SECRET=yyy RAZORPAY_WEBHOOK_SECRET=zzz
    uvicorn app.main:app --reload

Then in another terminal:
    export PAARI_ADMIN_API_KEY=dev-admin-key
    python demo_client.py
"""
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import httpx

from app.crypto_utils import (
    generate_agent_keypair,
    sign_with_private_key,
    canonical_json,
    public_key_fingerprint,
)

BASE_URL = "http://127.0.0.1:8000"
ADMIN_API_KEY = os.environ.get("PAARI_ADMIN_API_KEY", "")
ADMIN_HEADERS = {"X-Admin-Api-Key": ADMIN_API_KEY}


def main():
    if not ADMIN_API_KEY:
        print(
            "WARNING: PAARI_ADMIN_API_KEY is not set in this shell. The parent-"
            "approval and admin-revocation steps below will fail with 401 unless "
            "it matches what the server is using. Check the server's startup "
            "log for the auto-generated key if you didn't set one.\n"
        )

    # --- Parent registers its own key pair and identity with Paari ---
    parent_private_pem, parent_public_pem = generate_agent_keypair()
    r = httpx.post(f"{BASE_URL}/parents/register", json={
        "name": "Acme AI Labs",
        "parent_type": "developer",
        "contact": "founder@acmeailabs.com",
        "public_key_pem": parent_public_pem,
    })
    r.raise_for_status()
    parent_id = r.json()["parent_id"]
    print(f"Parent registered: {parent_id} (status: {r.json()['status']})")

    # --- Admin approves the parent (real KYB plugs in here in production) ---
    r = httpx.post(f"{BASE_URL}/parents/{parent_id}/approve", headers=ADMIN_HEADERS)
    r.raise_for_status()
    print(f"Parent approved by admin (status: {r.json()['status']})\n")

    # --- Agent generates its own key pair (private key never leaves the agent) ---
    agent_private_pem, agent_public_pem = generate_agent_keypair()

    # --- Parent signs a delegation document authorizing THIS agent public key ---
    now = datetime.now(timezone.utc)
    delegation = {
        "delegation_id": str(uuid.uuid4()),
        "parent_id": parent_id,
        "agent_public_key_fingerprint": public_key_fingerprint(agent_public_pem),
        "granted_capabilities": ["make_payment", "issue_refund_request"],
        "payment_limit_minor_units": 5000_00,  # INR 5,000.00 in paise
        "currency": "INR",
        "issued_at": int(now.timestamp()),
        "expires_at": int((now + timedelta(days=30)).timestamp()),
    }
    delegation_signature = sign_with_private_key(parent_private_pem, canonical_json(delegation))
    print("Parent signed a delegation for the agent's public key.\n")

    # --- Agent registers, presenting the signed delegation ---
    r = httpx.post(f"{BASE_URL}/agents/register", json={
        "name": "Demo Shopping Agent",
        "agent_type": "shopping_assistant",
        "purpose": "Buy groceries on behalf of the user within a monthly budget",
        "public_key_pem": agent_public_pem,
        "delegation": delegation,
        "delegation_signature_b64": delegation_signature,
    })
    r.raise_for_status()
    reg = r.json()
    agent_id = reg["agent_card"]["agent_id"]
    credential_jwt = reg["credential_jwt"]
    print(f"Agent registered: {agent_id}")
    print(f"Granted capabilities (from delegation): {reg['agent_card']['granted_capabilities']}")
    print(f"Payment limit (from delegation): {reg['agent_card']['payment_limit_minor_units']} {reg['agent_card']['currency']}")
    print(f"Agent Card is Paari-signed: card_signature_b64 present = {bool(reg['agent_card']['card_signature_b64'])}\n")

    # --- Authenticate: challenge / sign / verify ---
    def authenticate():
        r = httpx.post(f"{BASE_URL}/auth/challenge", json={"agent_id": agent_id})
        r.raise_for_status()
        nonce = r.json()["nonce"]
        signature_b64 = sign_with_private_key(agent_private_pem, nonce)
        r = httpx.post(f"{BASE_URL}/auth/verify", json={
            "agent_id": agent_id,
            "nonce": nonce,
            "signature_b64": signature_b64,
            "credential_jwt": credential_jwt,
        })
        r.raise_for_status()
        return r.json()["session_token"]

    session_token = authenticate()
    print("Authenticated - received session token.\n")

    # --- Payment intent within limits: should ALLOW ---
    r = httpx.post(f"{BASE_URL}/payments/intent", json={
        "session_token": session_token,
        "transaction_id": "TXN-001",
        "idempotency_key": "idem-001",
        "merchant": "BigBasket",
        "amount_minor_units": 1200_00,
        "currency": "INR",
        "action": "make_payment",
        "purpose": "weekly groceries",
    })
    r.raise_for_status()
    result = r.json()
    print("Payment intent (within limit):")
    print(result)

    if result["decision"] == "allow":
        auth_id = result["authorization"]["authorization_id"]

        print("\n--- Consuming with no session token (should be rejected - P0 fix) ---")
        r_noauth = httpx.post(f"{BASE_URL}/payments/authorizations/{auth_id}/consume", json={"session_token": ""})
        print(f"Status: {r_noauth.status_code}, detail: {r_noauth.json().get('detail')}")

        r = httpx.post(f"{BASE_URL}/payments/authorizations/{auth_id}/consume", json={"session_token": session_token})
        print(f"\nConsumed authorization (status {r.status_code}): {r.json()}")
        if r.status_code == 502:
            print("Consume failed closed: no Razorpay keys in the server env, so no")
            print("Order was created and the single-use stays spent (fresh intent needed).")

        print("\n--- Second consume attempt (should fail: single-use) ---")
        r2 = httpx.post(f"{BASE_URL}/payments/authorizations/{auth_id}/consume", json={"session_token": session_token})
        print(f"Status: {r2.status_code}, detail: {r2.json().get('detail')}")

    # --- Payment intent close to the limit: should REVIEW and require step-up MFA ---
    print("\n--- Near-limit payment intent (should REVIEW, require step-up MFA) ---")
    r = httpx.post(f"{BASE_URL}/payments/intent", json={
        "session_token": session_token,
        "transaction_id": "TXN-003",
        "idempotency_key": "idem-003",
        "merchant": "Croma Electronics",
        "amount_minor_units": 4500_00,  # 90% of the 5,000.00 limit
        "currency": "INR",
        "action": "make_payment",
        "purpose": "small appliance",
    })
    result = r.json()
    print(result)
    intent_id = result["intent_id"]

    print("\n--- Trying to skip straight to ALLOW by claiming MFA happened is no longer possible: ---")
    print("there is no mfa_verified field on the request anymore. Instead:")

    print("\n--- Requesting a step-up MFA challenge for that intent (own session) ---")
    r = httpx.post(f"{BASE_URL}/payments/mfa/challenge", json={"intent_id": intent_id, "session_token": session_token})
    r.raise_for_status()
    challenge = r.json()
    print(challenge)

    # The PARENT (a different key than the agent's) signs the exact challenge context.
    parent_signature = sign_with_private_key(parent_private_pem, challenge["context_to_sign"])

    print("\n--- Submitting the parent's signature to complete step-up MFA ---")
    r = httpx.post(f"{BASE_URL}/payments/mfa/verify", json={
        "intent_id": intent_id,
        "challenge_id": challenge["challenge_id"],
        "parent_signature_b64": parent_signature,
    })
    r.raise_for_status()
    print(r.json())

    # --- Payment intent OVER the delegated limit: should DENY ---
    print("\n--- Over-limit payment intent (should deny) ---")
    r = httpx.post(f"{BASE_URL}/payments/intent", json={
        "session_token": session_token,
        "transaction_id": "TXN-002",
        "idempotency_key": "idem-002",
        "merchant": "Croma Electronics",
        "amount_minor_units": 9000_00,
        "currency": "INR",
        "action": "make_payment",
        "purpose": "laptop",
    })
    print(r.json())

    # --- Admin revokes the agent; a further payment intent must be denied ---
    print("\n--- Admin revokes the agent ---")
    r = httpx.post(f"{BASE_URL}/agents/{agent_id}/revoke", headers=ADMIN_HEADERS)
    r.raise_for_status()
    print(r.json())

    print("\n--- Revoked agents can't even get past the auth challenge ---")
    r = httpx.post(f"{BASE_URL}/auth/challenge", json={"agent_id": agent_id})
    print(f"\nRe-authenticating a revoked agent -> status {r.status_code}: {r.json().get('detail')}")


if __name__ == "__main__":
    main()
