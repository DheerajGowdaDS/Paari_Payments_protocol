"""Mint a Razorpay token via a one-time test-mode checkout payment.

This is the one-time human enrollment: a person authenticates a card once,
and every charge after it is human-free.

Flow:
1. Create (or reuse) a customer
2. Create an order with save_token enabled
3. Pay it with a test card (simulated)
4. Verify the token exists on the customer
"""
import os
import sys
import json
import httpx
from pathlib import Path

# Load .env
_env_path = Path(__file__).resolve().parents[1] / ".env"
if _env_path.exists():
    for _line in _env_path.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip())

key_id = os.environ.get("RAZORPAY_KEY_ID", "")
key_secret = os.environ.get("RAZORPAY_KEY_SECRET", "")
if not key_id or not key_secret:
    print("ERROR: RAZORPAY_KEY_ID/RAZORPAY_KEY_SECRET not set")
    sys.exit(1)

base = os.environ.get("RAZORPAY_API_BASE", "https://api.razorpay.com/v1").rstrip("/")
client = httpx.Client(base_url=base, auth=(key_id, key_secret), timeout=15.0)

# Step 1: Create or reuse a customer
print("=== Step 1: Create/reuse customer ===")
r = client.get("/customers", params={"count": 1})
customers = r.json().get("items", []) if r.status_code == 200 else []

if customers:
    customer_id = customers[0]["id"]
    print(f"Reusing existing customer: {customer_id}")
else:
    r = client.post("/customers", json={
        "name": "Paari Test User",
        "email": "paari-test@example.com",
        "contact": "9999999999",
        "notes": {"purpose": "paari_token_enrollment"},
    })
    r.raise_for_status()
    customer_id = r.json()["id"]
    print(f"Created new customer: {customer_id}")

# Step 2: Create an order with save_token enabled
print("\n=== Step 2: Create order with save_token ===")
r = client.post("/orders", json={
    "amount": 10000,  # ₹100.00 in paise
    "currency": "INR",
    "receipt": f"paari_enrollment_{customer_id[:8]}",
    "notes": {"purpose": "one_time_token_enrollment"},
    "method": "card",
})
r.raise_for_status()
order = r.json()
order_id = order["id"]
print(f"Order created: {order_id}")
print(f"  amount: {order['amount']} {order['currency']}")
print(f"  status: {order['status']}")

# Step 3: Simulate payment with test card
print("\n=== Step 3: Pay with test card ===")
r = client.post("/payments/create/json", json={
    "order_id": order_id,
    "amount": 10000,
    "currency": "INR",
    "email": "paari-test@example.com",
    "contact": "9999999999",
    "method": "card",
    "card": {
        "number": "4111111111111111",
        "expiry_month": "12",
        "expiry_year": "2030",
        "cvv": "123",
        "name": "Paari Test",
    },
    "save_token": True,
    "customer_id": customer_id,
    "recurring": True,
    "notes": {"purpose": "one_time_token_enrollment"},
})
print(f"POST /payments/create/json -> {r.status_code}")
payment_data = r.json()
print(f"  response: {json.dumps(payment_data, indent=2)[:500]}")

if r.status_code != 200:
    print(f"\nPayment failed. Trying alternative approach...")
    # Try the standard payment creation flow
    r = client.post(f"/orders/{order_id}/payments", json={
        "amount": 10000,
        "currency": "INR",
        "email": "paari-test@example.com",
        "contact": "9999999999",
        "method": "card",
        "card": {
            "number": "4111111111111111",
            "expiry_month": "12",
            "expiry_year": "2030",
            "cvv": "123",
            "name": "Paari Test",
        },
        "save_token": True,
        "customer_id": customer_id,
        "recurring": True,
    })
    print(f"POST /orders/{{id}}/payments -> {r.status_code}")
    payment_data = r.json()
    print(f"  response: {json.dumps(payment_data, indent=2)[:500]}")

# Step 4: Check for token
print("\n=== Step 4: Verify token ===")
r = client.get(f"/customers/{customer_id}/tokens")
print(f"GET /customers/{customer_id}/tokens -> {r.status_code}")
if r.status_code == 200:
    tokens = r.json().get("items", [])
    print(f"  tokens count: {len(tokens)}")
    for t in tokens:
        print(f"    token: {t.get('id')} status={t.get('status')} bank={t.get('bank')}")
    if tokens:
        print(f"\nSUCCESS: Token minted!")
        print(f"  customer_id: {customer_id}")
        print(f"  token_id: {tokens[0]['id']}")
        print(f"\nNext steps:")
        print(f"  1. Bind to mandate: POST /v1/mandates/{{mandate_id}}/provider-binding")
        print(f"     with provider_mandate_ref = '{customer_id}'")
        print(f"  2. Enable: PAARI_AGENTIC_PROVIDER=app.providers.razorpay_agentic:RazorpayAgenticProvider")
        print(f"  3. Run consume -> should reach PAID with no human")
    else:
        print("\nNo tokens found. The payment may not have completed.")
        print("Check the payment status and try again.")
else:
    print(f"  error: {r.text[:300]}")
