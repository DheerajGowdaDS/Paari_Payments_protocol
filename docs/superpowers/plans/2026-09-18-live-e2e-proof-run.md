# Live E2E Proof Run — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute `scripts/foreign_agent_proof.py` end-to-end against a locally hosted Paari server wired to Razorpay Test Mode, with a real ₹1 payment and a real webhook settling it, and produce the 15/15 transcript as the E2E certificate.

**Architecture:** Server runs locally (uvicorn + fresh SQLite DB); ngrok exposes only the webhook path publicly; the proof script drives everything over localhost; the human completes one Test-Mode checkout in a browser. No repo code changes — this is an operations runbook.

**Tech Stack:** Python 3.11, uvicorn, ngrok (fallback: cloudflared), Razorpay Test Mode, Razorpay Checkout.js (test card), PowerShell 5.1.

## Global Constraints

- Test-Mode keys only (`rzp_test_*`). Never touch Live keys.
- Secrets travel via process env vars only. Never write them to repo files, the plan, logs, or transcripts. The `key_secret` is never reprinted in chat.
- Fresh isolated DB file `paari_live_e2e.db` (`*.db` is gitignored). Never reuse `paari.db` or `.phase5_test.db`.
- `alembic upgrade head` reads `ALEMBIC_URL`; the app reads `DATABASE_URL`. Set both to the same value.
- No commits during this run (no code changes expected). If a code fix becomes necessary, stop and report — do not freelance.
- The user performs the browser payment and the Razorpay dashboard webhook registration. The agent prepares everything else.

---

### Task 1: Preflight — validate keys and tooling

**Files:** none (read-only checks)

- [ ] **Step 1: Validate Razorpay Test-Mode keys (no side effects)**

```powershell
$env:RAZORPAY_KEY_ID = "<user-provided test key_id>"
$pair = "$env:RAZORPAY_KEY_ID:<user-provided test key_secret>"
$basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
Invoke-RestMethod -Uri "https://api.razorpay.com/v1/orders?count=1" -Headers @{Authorization = "Basic $basic"}
```

Run: the command above.
Expected: JSON with an `items` array (possibly empty) — proves auth works. `401` = keys wrong → stop and ask user to regenerate.

- [ ] **Step 2: Check runtime tooling**

```powershell
python --version; uvicorn --version; Get-Command ngrok -ErrorAction SilentlyContinue; Test-NetConnection -ComputerName 127.0.0.1 -Port 8000 -WarningAction SilentlyContinue | Select-Object TcpTestSucceeded
```

Expected: Python 3.11+, uvicorn present, port 8000 free (`TcpTestSucceeded: False`). If ngrok is missing, try `cloudflared`; if neither exists, fall back to plan B (section below) and tell the user before proceeding.

- [ ] **Step 3: Generate run secrets (session env only)**

```powershell
$env:PAARI_ADMIN_API_KEY = -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})
$env:PAARI_WEBHOOK_SECRET = -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 24 | ForEach-Object {[char]$_})
```

Record: keep both in session memory only. The webhook secret value will be handed to the user once (for dashboard entry), never written to disk.

### Task 2: Boot the server on a fresh DB

**Files:** creates `paari_live_e2e.db` (gitignored, runtime state only)

- [ ] **Step 1: Migrate a fresh database**

```powershell
$env:ALEMBIC_URL = "sqlite:///./paari_live_e2e.db"; $env:DATABASE_URL = "sqlite:///./paari_live_e2e.db"
Remove-Item -LiteralPath ".\paari_live_e2e.db" -ErrorAction SilentlyContinue
alembic upgrade head
```

Expected: no errors; `paari_live_e2e.db` created.

- [ ] **Step 2: Start uvicorn in the background (sandbox profile)**

```powershell
$env:RAZORPAY_KEY_ID = "<test key_id>"; $env:RAZORPAY_KEY_SECRET = "<test key_secret>"
$env:RAZORPAY_WEBHOOK_SECRET = $env:PAARI_WEBHOOK_SECRET
$env:PAARI_ENV = "sandbox"
Start-Process python -ArgumentList "-m","uvicorn","app.main:app","--host","127.0.0.1","--port","8000" -NoNewWindow -PassThru
```

- [ ] **Step 3: Health-check the server**

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/health"
```

Expected: `{"status":"ok","service":"paari","env":"sandbox","database":"up"}`. If `degraded`, stop and diagnose before continuing.

### Task 3: Public webhook exposure + user dashboard registration

**Interfaces:**
- Produces: `NGROK_URL` (e.g. `https://abcd-1-2-3-4.ngrok-free.app`), webhook secret value — both handed to the user.

- [ ] **Step 1: Open the tunnel**

```powershell
ngrok http 127.0.0.1:8000
```

Record the `https://...` forwarding URL from ngrok's output.

- [ ] **Step 2: Hand the user exactly this package (chat message)**

```text
1. Webhook URL:  <NGROK_URL>/v1/payments/webhooks/razorpay
2. Webhook secret: <PAARI_WEBHOOK_SECRET value>
3. In Razorpay Dashboard (TEST MODE) → Settings → Webhooks → Add:
   - URL = (1), Secret = (2)
   - Events: payment.authorized, payment.captured, payment.failed
4. Reply "webhook registered".
```

- [ ] **Step 3: Verify delivery (after user confirms)**

Ask the user to click "Test Webhook" in the dashboard if available, then check server logs for `POST /v1/payments/webhooks/razorpay`. Any response (even `ignored — unknown order`) proves the network path + signature path work. If nothing arrives, debug tunnel/dashboard before the paid run.

### Task 4: Execute the 15-step live proof

**Files:** creates `C:\Users\gowda\AppData\Local\Temp\opencode\paari_checkout_<ORDER>.html` (outside repo; per-order checkout page)

- [ ] **Step 1: Launch the proof script**

```powershell
$env:PAARI_BASE_URL = "http://127.0.0.1:8000"
$env:PAARI_AMOUNT = "100"
$env:PAARI_PAY_TIMEOUT = "900"
python scripts/foreign_agent_proof.py 2>&1 | Tee-Object -FilePath "$env:TEMP\paari_e2e_transcript.txt"
```

Expected: steps 1–8 print `PASS`, step 9 prints `PASS` with a real `razorpay_order_id` starting with `order_`, then the script prints `[WAIT]` and blocks. If any step 1–9 FAILs, stop — do not ask the user to pay.

- [ ] **Step 2: Hand the user the payment package (chat message)**

Build the checkout page from this template with the real values substituted:

```html
<!doctype html><html><body>
<button id="pay">Pay Rs 1.00 (TEST MODE)</button>
<script src="https://checkout.razorpay.com/v1/checkout.js"></script>
<script>
var options = { key: "<RAZORPAY_KEY_ID>", amount: "100", currency: "INR",
  order_id: "<order_id from step 9>", name: "Paari E2E",
  theme: { color: "#3399cc" } };
document.getElementById("pay").onclick = function () { new Razorpay(options).open(); };
</script></body></html>
```

Message: file path + "open it, click Pay, use card `4111 1111 1111 1111`, any future expiry, any CVV, then reply 'paid'." (Test card works only in Test Mode; no real money moves.)

- [ ] **Step 3: Let the script finish (steps 10–15)**

Expected after payment: `[PASS] 10. webhook captured: PAID`, then `11. reconciled PAID`, `12. audit chain verified`, `13. over-delegation DENY`, `14. agent revoked`, `15. revoked blocked`, `MILESTONE GREEN: 15/15 steps passed`. If step 10 times out (exit 2): check Razorpay dashboard → Payments (Test Mode) for the payment status, check server logs for webhook arrival, then decide: retry payment on a fresh run vs. debug webhook delivery. Never mark steps green manually.

### Task 5: Evidence capture and teardown

- [ ] **Step 1: Publish the certificate (chat message)**

Post: the full transcript from `$env:TEMP\paari_e2e_transcript.txt` (it contains no secrets — verify before posting), plus the `order_id`, `payment_id`, and final audit-chain verdict.

- [ ] **Step 2: Teardown and hygiene**

```powershell
Stop-Process -Name uvicorn -ErrorAction SilentlyContinue
ngrok kill  # or stop the tunnel process
```

Then tell the user: (a) webhook in Test-Mode dashboard may be left or deleted — harmless; (b) test keys stay valid for future runs; (c) evidence DB `paari_live_e2e.db` kept as the audit record, terminal transcript kept at `$env:TEMP\paari_e2e_transcript.txt`.

---

## Plan B (fallback — no public tunnel available)

If ngrok/cloudflared cannot run: proceed with steps 1–9 live (real order creation proves provider execution), then satisfy step 10 by crafting an HMAC-signed `payment.captured` event locally with `PAARI_WEBHOOK_SECRET` and POSTing it to localhost — this proves all settlement logic but NOT the Razorpay→server network path. State this substitution explicitly in the certificate; do not claim a full live webhook proof.

## Self-Review

- **Spec coverage:** every user requirement maps to a task — test keys (T1), server self-created (T2), ngrok URL handoff for user-registered webhook (T3), user pays ₹1 via checkout page (T4 steps 2–3), approach plan first (this document).
- **Placeholder scan:** no TBD/TODO; all commands copy-pasteable except `<...>` values that are genuinely runtime (order_id) or user secrets (keys) — both resolved at execution time from session env.
- **Type consistency:** env var names match `app/config.py`, `app/main.py` lifespan, `app/security.py`, and the proof script's `os.environ` reads (`PAARI_BASE_URL`, `PAARI_ADMIN_API_KEY`, `PAARI_AMOUNT`, `PAARI_PAY_TIMEOUT` verified in `scripts/foreign_agent_proof.py:57-60`).
