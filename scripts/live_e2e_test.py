"""Live E2E test: real Razorpay order + webhook tunnel + state verification."""
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dotenv import load_dotenv

load_dotenv()

BASE = "http://127.0.0.1:8000"
ADMIN_KEY = os.environ.get("PAARI_ADMIN_API_KEY", "")
WEBHOOK_URL = os.environ.get("PAARI_WEBHOOK_URL", "")


def generate_keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, pub


def fingerprint(pub_pem: str) -> str:
    from app.crypto_utils import public_key_fingerprint
    return public_key_fingerprint(pub_pem)


def sign_delegation(parent_priv, delegation: dict) -> str:
    import base64
    canonical = json.dumps(delegation, sort_keys=True, separators=(",", ":"))
    return base64.b64encode(parent_priv.sign(canonical.encode())).decode()


def start_server():
    env = os.environ.copy()
    env["PAARI_MODE"] = "autonomous"
    env["PAARI_REQUIRE_USER_MANDATE"] = "1"
    env["PAARI_ENV"] = "sandbox"
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    for _ in range(30):
        try:
            r = httpx.get(f"{BASE}/health", timeout=2.0)
            if r.status_code == 200:
                return proc, r.json()
        except Exception:
            pass
        time.sleep(1)
    proc.terminate()
    raise RuntimeError("Server failed to start")


def main():
    if not ADMIN_KEY:
        print("ERROR: PAARI_ADMIN_API_KEY is required for this live script.")
        return 2
    if not WEBHOOK_URL:
        print("ERROR: PAARI_WEBHOOK_URL is required; no tunnel URL is hard-coded.")
        return 2
    print("=== Starting Live E2E Test ===\n")

    proc, health = start_server()
    print(f"Server health: {json.dumps(health, indent=2)}\n")

    try:
        admin = {"X-Admin-Api-Key": ADMIN_KEY}

        # 1. Register parent
        parent_priv, parent_pub = generate_keypair()
        r = httpx.post(f"{BASE}/parents/register", json={
            "name": "Live E2E Parent",
            "parent_type": "developer",
            "contact": "livee2e@example.com",
            "public_key_pem": parent_pub,
        }, headers=admin)
        print(f"1. Parent register: {r.status_code}")
        if r.status_code != 200:
            print(f"   ERROR: {r.text}")
            return 1
        parent_id = r.json()["parent_id"]
        print(f"   parent_id: {parent_id}")

        # 2. Approve parent
        r = httpx.post(f"{BASE}/parents/{parent_id}/approve", headers=admin)
        print(f"2. Parent approve: {r.status_code} status={r.json().get('status')}")

        # 3. Register agent via SDK
        from paari_agent.client import PaariAgentClient
        agent_priv, agent_pub = generate_keypair()
        now = datetime.now(timezone.utc)
        delegation = {
            "delegation_id": str(uuid.uuid4()),
            "parent_id": parent_id,
            "agent_public_key_fingerprint": fingerprint(agent_pub),
            "granted_capabilities": ["make_payment"],
            "payment_limit_minor_units": 500000,
            "currency": "INR",
            "issued_at": int(now.timestamp()),
            "expires_at": int((now + timedelta(days=7)).timestamp()),
        }
        client = PaariAgentClient(BASE, agent_priv, agent_pub)
        client.register(
            name="Live E2E Agent",
            agent_type="shopping_assistant",
            purpose="live e2e test",
            delegation=delegation,
            delegation_signature_b64=sign_delegation(parent_priv, delegation),
        )
        print(f"3. Agent register: agent_id={client.agent_id}")

        # 4. Authenticate
        client.authenticate()
        print(f"4. Authenticate: got session token")

        # 5. Create signed user mandate
        user_priv, user_pub = generate_keypair()
        mandate_id = f"UM-LIVE-{uuid.uuid4().hex[:8]}"
        mandate_fields = {
            "mandate_id": mandate_id,
            "user_id": "user-live-e2e",
            "agent_id": client.agent_id,
            "max_per_transaction": 100000,
            "max_daily_amount": 200000,
            "max_per_hour": 100000,
            "max_per_merchant_per_day": 100000,
            "max_category_per_day": None,
            "currency": "INR",
            "allowed_merchants": ["LiveE2EStore"],
            "allowed_categories": [],
            "require_review_above": None,
            "valid_from": now.isoformat(),
            "expires_at": (now + timedelta(days=30)).isoformat(),
            "approval_reference": f"live-e2e-{mandate_id}",
        }
        from paari_agent.crypto import sign_text
        from app.mandate_signing import canonical_mandate_payload
        canonical = canonical_mandate_payload(mandate_fields)
        signature = sign_text(user_priv, canonical)
        r = httpx.post(f"{BASE}/v1/mandates", json={
            **mandate_fields,
            "user_public_key_pem": user_pub,
            "mandate_signature_b64": signature,
            "signing_key_id": f"user-key-{mandate_id}",
        }, headers=admin)
        print(f"5. Mandate create: {r.status_code}")
        if r.status_code != 200:
            print(f"   ERROR: {r.text}")
            return 1
        mandate_data = r.json()
        print(f"   mandate_id: {mandate_data['mandate_id']}, status: {mandate_data['status']}")

        # 6. Payment intent
        # The server derives the active mandate; do not supply a client-selected mandate_id.
        r = httpx.post(f"{BASE}/v1/payments/intent", json={
            "agent_id": client.agent_id,
            "transaction_id": f"TXN-live-{uuid.uuid4().hex[:8]}",
            "idempotency_key": f"idem-live-{uuid.uuid4().hex[:8]}",
            "merchant": "LiveE2EStore",
            "amount_minor_units": 10000,
            "currency": "INR",
            "action": "make_payment",
            "purpose": "live e2e test payment",
        }, headers={"Authorization": f"Bearer {client.session_token}"})
        print(f"6. Payment intent: {r.status_code}")
        if r.status_code != 200:
            print(f"   ERROR: {r.text}")
            return 1
        intent_data = r.json()
        transaction_id = intent_data["transaction_id"]
        authorization_id = intent_data["authorization"]["authorization_id"]
        print(f"   transaction_id: {transaction_id}")
        print(f"   authorization_id: {authorization_id}")
        print(f"   decision: {intent_data['decision']}")

        # 7. Consume authorization (creates real Razorpay order)
        r = httpx.post(
            f"{BASE}/v1/payments/authorizations/{authorization_id}/consume",
            headers={"Authorization": f"Bearer {client.session_token}"},
        )
        print(f"7. Consume: {r.status_code}")
        if r.status_code != 200:
            print(f"   ERROR: {r.text}")
            return 1
        consume_data = r.json()
        razorpay_order_id = consume_data.get("razorpay_order_id", "N/A")
        print(f"   state: {consume_data['state']}")
        print(f"   razorpay_order_id: {razorpay_order_id}")

        # 8. Check audit chain
        r = httpx.get(
            f"{BASE}/v1/audit/{transaction_id}",
            headers={"Authorization": f"Bearer {client.session_token}"},
        )
        print(f"8. Audit chain: {r.status_code}")
        if r.status_code == 200:
            audit_data = r.json()
            print(f"   chain_verified: {audit_data['chain_verified']}")
            kinds = [e["kind"] for e in audit_data["events"]]
            print(f"   events: {kinds}")

        # 9. Check proof bundle
        r = httpx.get(
            f"{BASE}/v1/proof/{transaction_id}",
            headers={"Authorization": f"Bearer {client.session_token}"},
        )
        print(f"9. Proof bundle: {r.status_code}")
        if r.status_code == 200:
            proof = r.json()
            print(f"   settlement_source: {proof.get('settlement_source')}")
            print(f"   provider_environment: {proof.get('provider_environment')}")

        print(f"\n=== Live E2E Test Complete ===")
        print(f"Transaction ID: {transaction_id}")
        print(f"Authorization ID: {authorization_id}")
        print(f"Razorpay Order ID: {razorpay_order_id}")
        print(f"Webhook URL: {WEBHOOK_URL}")
        print(f"\nNext: Complete the payment on Razorpay checkout to trigger webhook delivery")

        return 0

    finally:
        proc.terminate()


if __name__ == "__main__":
    sys.exit(main())
