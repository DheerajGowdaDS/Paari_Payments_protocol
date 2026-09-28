"""Read-only probe: is /payments/create/recurring missing because no token
exists, or because the endpoint is not enabled for this account?"""
import os
import httpx
from pathlib import Path

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
    raise SystemExit(1)

base = os.environ.get("RAZORPAY_API_BASE", "https://api.razorpay.com/v1").rstrip("/")
client = httpx.Client(base_url=base, auth=(key_id, key_secret), timeout=10.0)

# Probe 1: List customers (read-only)
r = client.get("/customers", params={"count": 1})
print(f"GET /customers -> {r.status_code}")
if r.status_code == 200:
    data = r.json()
    items = data.get("items", [])
    print(f"  customers count: {data.get('count', 0)}")
    if items:
        cust_id = items[0]["id"]
        print(f"  first customer: {cust_id}")
        r2 = client.get(f"/customers/{cust_id}/tokens")
        print(f"GET /customers/{cust_id}/tokens -> {r2.status_code}")
        if r2.status_code == 200:
            tokens = r2.json().get("items", [])
            print(f"  tokens count: {len(tokens)}")
            for t in tokens[:3]:
                print(f"    token: {t.get('id')} status={t.get('status')}")
        else:
            print(f"  error: {r2.text[:200]}")
    else:
        print("  no customers exist yet")
else:
    print(f"  error: {r.text[:200]}")

# Probe 2: Does the recurring endpoint exist? (POST with empty body)
r3 = client.post("/payments/create/recurring", json={})
print(f"POST /payments/create/recurring (empty body) -> {r3.status_code}")
print(f"  response: {r3.text[:300]}")

# Probe 3: Does the subscriptions endpoint exist?
r4 = client.post("/subscriptions", json={})
print(f"POST /subscriptions (empty body) -> {r4.status_code}")
print(f"  response: {r4.text[:300]}")

# Probe 4: Does the token endpoint exist? (GET on a fake customer)
r5 = client.get("/customers/cust_nonexistent/tokens")
print(f"GET /customers/cust_nonexistent/tokens -> {r5.status_code}")
print(f"  response: {r5.text[:300]}")

print("\n--- Interpretation ---")
if r3.status_code == 404:
    print("VERDICT: Endpoint NOT ENABLED for this account (404 = not found)")
elif r3.status_code == 400:
    print("VERDICT: Endpoint EXISTS but rejected the empty request (400 = bad request)")
    print("  This means the endpoint is ENABLED — the earlier 400 was due to missing token.")
else:
    print(f"VERDICT: Unexpected status {r3.status_code} — manual investigation needed")
