# Paari Blueprint Gap Closure — Master Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every gap identified in the 2026-09-18 blueprint audit and finish the remaining partial items so the full Paari v1.0 system is built and provable locally.

**Architecture:** Nine phased sub-plans, each independently reviewable and deployable. Later phases depend on earlier ones only where noted; most can be picked up in parallel. Each sub-plan produces working, testable software.

**Tech Stack:** Python 3.11, FastAPI 0.115, SQLAlchemy 2.0, Pydantic 2.9, PyJWT 2.9, cryptography 43, httpx 0.27, pytest 8.3, pytest-asyncio 0.24, respx 0.21. No new external dependencies are introduced — the reconciliation worker uses stdlib `threading`, alerting uses stdlib `logging` plus optional env-driven webhook.

**Spec:** `docs/superpowers/plans/2026-09-18-blueprint-gap-audit.md` (the gap analysis produced alongside this plan).

## Global Constraints

- Python 3.11 only. No syntax newer than 3.11.
- Pin exact versions in `requirements.txt` only; dev deps in `requirements-dev.txt`.
- All timestamps must go through `app.database.UTCDateTime`; never use plain `DateTime(timezone=True)`.
- All money-state transitions must go through `app.transitions.transition_txn`; never mutate `.state` directly.
- All governance, webhook, and reconcile events must append to the audit chain via `app.audit.record_audit` and flush-only (caller commits).
- Tests use the `paari_client` fixture from `tests/conftest.py` unless a task explicitly states otherwise.
- Do not import `app.*` from `sdk/paari_agent/` or any `examples/` or `scripts/` file.
- Commit after each task boundary, not mid-task.

---

## Phase Roadmap

| Phase | Sub-plan file | What it closes | Dependencies |
|---|---|---|---|
| A | `protocol-completeness.md` | 7.1 error codes, schemas, examples | — |
| B | `audit-hardening.md` | 7.5 structured policy results, state before/after | Phase A |
| C | `trust-provider-wiring.md` | 7.3 SUSPENDED state, trust provider wired in | Phase A |
| D | `reconciliation-worker.md` | 7.6 worker, retry, backoff, dead-letter, alerting | Phase B |
| E | `webhook-org-verification.md` | 7.4 residual webhook org-account check | Phase A |
| F | `sandbox-separation.md` | 8.7 env profiles, sandbox guard | — |
| G | `production-ops.md` | 7.7 Postgres CI test, health checks | Phase F |
| H | `adversarial-failure-tests.md` | 8.4 governance attack suite, 8.6 failure/recovery | Phases A–E |

Execute in order A → B → C → D → E → F → G → H unless a phase is blocked; phases F and H can overlap with earlier phases where noted.

---

## Phase A — Protocol Completeness (closes 7.1 gaps)

**Files:**
- Create: `app/protocol/errors.py`, `schemas/paari-credential.v1.schema.json`, `schemas/paari-session.v1.schema.json`, `schemas/paari-bounded-authorization.v1.schema.json`, `schemas/paari-consume.v1.schema.json`, `schemas/paari-mfa.v1.schema.json`, `schemas/paari-reconcile.v1.schema.json`, `schemas/paari-webhook.v1.schema.json`, `schemas/paari-revocation.v1.schema.json`, `schemas/paari-discovery.v1.schema.json`, `docs/protocol-examples.md`
- Modify: `app/main.py`, `app/schemas.py`, `app/protocol/envelope.py`, `app/protocol/messages.py`, `docs/PROTOCOL.md`
- Test: `tests/test_protocol_errors.py`, `tests/test_schemas.py`

**Interfaces:**
- Consumes: existing FastAPI `HTTPException` pattern, existing `app/protocol/*` helpers
- Produces: `app.protocol.errors.PaariErrorCode` enum, `app.protocol.errors.error_response()` helper, `app.protocol.errors.paari_exception_handler` registered in `main.py`, 9 new JSON schemas, protocol examples doc

### Task A1 — Error-code taxonomy and structured error responses

- [ ] **Step 1: Write failing test**

```python
# tests/test_protocol_errors.py
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_unknown_protocol_version_returns_structured_error():
    r = client.post("/v1/agents/register", json={"envelope": {"version": "9.9"}})
    assert r.status_code == 400
    body = r.json()
    assert "code" in body
    assert body["code"] == "UNSUPPORTED_PROTOCOL_VERSION"

def test_error_response_has_required_fields():
    r = client.post("/v1/auth/challenge", json={"agent_id": "does-not-exist"})
    assert r.status_code in (401, 404)
    body = r.json()
    assert "code" in body
    assert "detail" in body
    assert "request_id" in body
```

Run: `pytest tests/test_protocol_errors.py -v`
Expected: FAIL — `code` key missing from response body.

- [ ] **Step 2: Implement the error taxonomy**

```python
# app/protocol/errors.py
from __future__ import annotations

import uuid
from enum import StrEnum

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse


class PaariErrorCode(StrEnum):
    # Protocol
    UNSUPPORTED_PROTOCOL_VERSION = "UNSUPPORTED_PROTOCOL_VERSION"
    ENVELOPE_SIGNATURE_INVALID = "ENVELOPE_SIGNATURE_INVALID"
    DELEGATION_EXPIRED = "DELEGATION_EXPIRED"
    # Auth
    SESSION_INVALID = "SESSION_INVALID"
    PROOF_REPLAYED = "PROOF_REPLAYED"
    PROOF_PATH_MISMATCH = "PROOF_PATH_MISMATCH"
    # Governance
    CAPABILITY_NOT_DELEGATED = "CAPABILITY_NOT_DELEGATED"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    CURRENCY_MISMATCH = "CURRENCY_MISMATCH"
    PARENT_REVOKED = "PARENT_REVOKED"
    AGENT_REVOKED = "AGENT_REVOKED"
    # Execution
    AUTHORIZATION_ALREADY_USED = "AUTHORIZATION_ALREADY_USED"
    AUTHORIZATION_EXPIRED = "AUTHORIZATION_EXPIRED"
    PROVIDER_MISCONFIGURED = "PROVIDER_MISCONFIGURED"
    # Settlement
    WEBHOOK_SIGNATURE_INVALID = "WEBHOOK_SIGNATURE_INVALID"
    WEBHOOK_VALUE_MISMATCH = "WEBHOOK_VALUE_MISMATCH"
    # Reconciliation
    PROVIDER_UNKNOWN = "PROVIDER_UNKNOWN"
    RECONCILIATION_VALUE_MISMATCH = "RECONCILIATION_VALUE_MISMATCH"
    # Generic
    NOT_FOUND = "NOT_FOUND"
    INTERNAL = "INTERNAL"


class PaariHTTPException(HTTPException):
    def __init__(self, status_code: int, code: PaariErrorCode, detail: str = "", headers: dict | None = None):
        self.code = code
        super().__init__(status_code=status_code, detail=detail, headers=headers)


def error_response(code: PaariErrorCode, detail: str = "", status_code: int = 400) -> dict:
    return {"code": code.value, "detail": detail, "request_id": str(uuid.uuid4())}


async def paari_exception_handler(request: Request, exc: PaariHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content=error_response(exc.code, exc.detail, exc.status_code),
        headers=exc.headers,
    )
```

- [ ] **Step 3: Wire handler into main.py**

In `app/main.py`, add:

```python
from app.protocol.errors import paari_exception_handler, PaariHTTPException
app.add_exception_handler(PaariHTTPException, paari_exception_handler)
```

- [ ] **Step 4: Replace HTTPException strings with PaariHTTPException in one router**

Edit `app/routers/v1.py` `v1_register_agent` to raise `PaariHTTPException(400, PaariErrorCode.UNSUPPORTED_PROTOCOL_VERSION, ...)` instead of `HTTPException(400, ...)`. Keep the same HTTP status codes and detail strings.

- [ ] **Step 5: Run test**

Run: `pytest tests/test_protocol_errors.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add app/protocol/errors.py app/main.py app/routers/v1.py tests/test_protocol_errors.py
git commit -m "feat(protocol): add PaariErrorCode taxonomy and structured error responses"
```

### Task A2 — Add remaining JSON schemas

- [ ] **Step 1: Write failing test**

```python
# tests/test_schemas.py
import json
import pathlib

SCHEMA_DIR = pathlib.Path(__file__).resolve().parents[1] / "schemas"

def test_all_v1_schemas_are_valid_json():
    for path in SCHEMA_DIR.glob("paari-*.v1.schema.json"):
        data = json.loads(path.read_text())
        assert "$schema" in data
        assert "type" in data

def test_each_schema_has_example():
    for path in SCHEMA_DIR.glob("paari-*.v1.schema.json"):
        data = json.loads(path.read_text())
        assert "examples" in data or "example" in data, f"{path.name} missing example"
```

Run: `pytest tests/test_schemas.py -v`
Expected: FAIL on missing schemas / missing examples.

- [ ] **Step 2: Create the 9 missing schemas**

Each schema is a standalone JSON Schema draft 2020-12 file under `schemas/`. Use the existing `paari-envelope.v1.schema.json` and `paari-agent-card.v1.schema.json` as style reference. Each must include:
- `"$schema": "https://json-schema.org/draft/2020-12/schema"`
- `"type": "object"`
- `"properties"` matching the corresponding Pydantic model field names exactly
- `"required"` array for mandatory fields
- `"examples"` array with at least one valid instance

Files to create (in one step, one commit):
- `schemas/paari-credential.v1.schema.json`
- `schemas/paari-session.v1.schema.json`
- `schemas/paari-bounded-authorization.v1.schema.json`
- `schemas/paari-consume.v1.schema.json`
- `schemas/paari-mfa.v1.schema.json`
- `schemas/paari-reconcile.v1.schema.json`
- `schemas/paari-webhook.v1.schema.json`
- `schemas/paari-revocation.v1.schema.json`
- `schemas/paari-discovery.v1.schema.json`

- [ ] **Step 3: Run test**

Run: `pytest tests/test_schemas.py -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add schemas/ tests/test_schemas.py
git commit -m "feat(protocol): add JSON schemas for all v1 message types"
```

### Task A3 — Protocol request/response examples

- [ ] **Step 1: Create docs/protocol-examples.md**

Populate with one realistic curl-style block per operation:
`register`, `challenge`, `verify`, `payment_intent` (allow/review/deny), `mfa_challenge`, `mfa_verify`, `consume`, `webhook`, `reconcile`, `revoke_authorization`, `rotate_key`. Use exact paths, exact headers (`Authorization: Bearer`, `X-Paari-Proof`), and realistic response bodies drawn from the Pydantic response models in `app/schemas.py`.

- [ ] **Step 2: Link from PROTOCOL.md**

Add one line at the top of `docs/PROTOCOL.md`:
`> Per-operation examples: [protocol-examples.md](protocol-examples.md)`

- [ ] **Step 3: Add schema links to PROTOCOL.md**

Under "Interoperability", link each schema file:
```markdown
- Agent Card: `schemas/paari-agent-card.v1.schema.json`
- Envelope: `schemas/paari-envelope.v1.schema.json`
- Payment Intent: `schemas/paari-payment-intent.v1.schema.json`
- Credential: `schemas/paari-credential.v1.schema.json`
... (all 9)
```

- [ ] **Step 4: Commit**

```bash
git add docs/protocol-examples.md docs/PROTOCOL.md schemas/
git commit -m "docs(protocol): add per-operation examples and link all schemas from PROTOCOL.md"
```

---

## Phase B — Audit Hardening (closes 7.5)

**Files:**
- Create: `app/governance.py`
- Modify: `app/routers/payments.py`, `app/audit.py`, `app/models.py` (optional: add `previous_state`/`current_state` columns to `AuditEvent`), `app/schemas.py`
- Test: `tests/test_audit_hardening.py`

**Interfaces:**
- Consumes: `app.transitions.transition_txn`, `app.audit.record_audit`
- Produces: `app.governance.PolicyResult`, `app.governance.PolicyCheck`, `app.governance.evaluate_governance()`, enriched audit events with `previous_state`/`current_state`

### Task B1 — Structured policy-result model and governance engine

- [ ] **Step 1: Write failing test**

```python
# tests/test_audit_hardening.py
from tests.conftest import paari_client

CAPABILITY = "make_payment"

def test_intent_decided_audit_contains_structured_policy_results(paari_client):
    ctx = paari_client
    r = ctx.client.post(
        "/payments/intent",
        json={
            "session_token": ctx.session_token,
            "transaction_id": "TXN-audit-hard-1",
            "idempotency_key": "idem-audit-hard-1",
            "merchant": "TestMerchant",
            "amount_minor_units": 1000,
            "currency": "INR",
            "action": "make_payment",
            "purpose": "audit hardening",
        },
    )
    assert r.status_code == 200, r.text
    intent_id = r.json()["intent_id"]

    r = ctx.client.get(f"/v1/audit/{intent_id}", headers={"Authorization": f"Bearer {ctx.session_token}"})
    assert r.status_code == 200
    events = r.json()["events"]
    kinds = [e["kind"] for e in events]
    assert "intent_decided" in kinds
    decided = next(e for e in events if e["kind"] == "intent_decided")
    detail = decided["detail"]
    assert "policy_results" in detail
    assert isinstance(detail["policy_results"], list)
    assert any(p.get("name") == "capability_check" for p in detail["policy_results"])
    assert any(p.get("name") == "limit_check" for p in detail["policy_results"])
```

Run: `pytest tests/test_audit_hardening.py -v`
Expected: FAIL — `policy_results` key missing.

- [ ] **Step 2: Create structured policy model**

```python
# app/governance.py
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from app import models


@dataclass(frozen=True)
class PolicyResult:
    name: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class GovernanceResult:
    decision: models.GovernanceDecision
    reasons: list[str] = field(default_factory=list)
    policy_results: Sequence[PolicyResult] = ()
    mfa_required: bool = False
    mfa_verified: bool = False
```

- [ ] **Step 3: Refactor payments.py governance to accumulate PolicyResult**

In `app/routers/payments.py`, replace the flat `reasons: list[str]` accumulation inside `submit_payment_intent` with a local `policy_results: list[PolicyResult]`. Each check (parent active, agent active, delegation not expired, capability, limit, currency, velocity) appends a `PolicyResult(name=..., passed=..., detail=...)`. After all checks, derive `reasons = [r.detail for r in policy_results]` and pass `policy_results` into `_record_intent`.

- [ ] **Step 4: Enrich record_audit call**

Modify `_record_intent` signature to accept `policy_results: Sequence[PolicyResult] | None = None` and `previous_state: str | None = None, current_state: str | None = None`. Pass them into `record_audit` detail as `policy_results=[p.__dict__ for p in (policy_results or [])]` and `previous_state`/`current_state` keys.

- [ ] **Step 5: Enrich other audit calls**

Update every `record_audit(... kind="authorization_minted" ...)` call to include `previous_state="AUTHORIZED"` / `current_state="AUTHORIZED"` (or whatever the transition is). Update webhook, reconcile, consume, revoke audit calls to include `previous_state`/`current_state` on state-changing events.

- [ ] **Step 6: Run test**

Run: `pytest tests/test_audit_hardening.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add app/governance.py app/routers/payments.py app/audit.py tests/test_audit_hardening.py
git commit -m "feat(audit): structured policy results and previous/current state in audit events"
```

---

## Phase C — Trust Provider Wiring (closes 7.3)

**Files:**
- Modify: `app/models.py`, `app/trust.py`, `app/routers/parents.py`, `app/routers/agents.py`, `app/routers/payments.py`
- Test: `tests/test_trust_provider.py`

**Interfaces:**
- Produces: wired `ParentTrustProvider` called at registration and governance time; `ParentStatus.SUSPENDED` enum value; unified `TrustTier` enum

### Task C1 — Unify trust states and wire provider

- [ ] **Step 1: Write failing test**

```python
# tests/test_trust_provider.py
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app import models

client = TestClient(app)

def _register_parent(db_session):
    from app.database import get_engine
    from sqlalchemy.orm import sessionmaker
    from app import models as m
    engine = get_engine("sqlite:///./.trust_test.db")
    from alembic import command
    from alembic.config import Config
    import pathlib
    cfg = Config(str(pathlib.Path("alembic.ini")))
    cfg.set_main_option("sqlalchemy.url", "sqlite:///./.trust_test.db")
    command.upgrade(cfg, "head")
    # ... (mirror conftest pattern) ...
```

Use the existing `paari_client` fixture for speed. The test asserts that a parent with `trust_tier="suspended"` is rejected at agent registration and at payment governance.

- [ ] **Step 2: Add SUSPENDED to ParentStatus enum**

In `app/models.py`, add `SUSPENDED = "suspended"` to `ParentStatus`.

- [ ] **Step 3: Add TrustTier enum and migration**

In `app/models.py` (or a new `app/trust.py`), add:

```python
class TrustTier(str, enum.Enum):
    SELF_ASSERTED = "self_asserted"
    ADMIN_APPROVED = "admin_approved"
    KYB_VERIFIED = "kyb_verified"
    SUSPENDED = "suspended"
```

Run `alembic revision -m "add trust_tier enum"` and create a migration that alters the `trust_tier` column to use the enum or validates allowed values. Note: SQLite does not enforce CHECK constraints retroactively; tests should seed valid values.

- [ ] **Step 4: Wire trust provider into registration**

In `app/routers/agents.py` `register_agent`, after the parent ACTIVE check, call:

```python
from app.trust import get_trust_provider
result = get_trust_provider().verify(db, parent)
if not result.approved:
    raise PaariHTTPException(401, PaariErrorCode.PARENT_REVOKED, result.reason)
```

- [ ] **Step 5: Wire trust provider into governance**

In `app/routers/payments.py` `submit_payment_intent`, after the parent ACTIVE check, call `get_trust_provider().verify(db, parent)` and deny if not approved.

- [ ] **Step 6: Add SUSPENDED parent rejection test**

Extend `tests/test_trust_provider.py` to register a parent, set its status to SUSPENDED, and assert agent registration and payment intent both return 401 with the appropriate error code.

- [ ] **Step 7: Commit**

```bash
git add app/models.py app/trust.py app/routers/parents.py app/routers/agents.py app/routers/payments.py tests/test_trust_provider.py alembic/versions/<new_migration>.py
git commit -m "feat(trust): wire ParentTrustProvider into registration and governance; add SUSPENDED state"
```

---

## Phase D — Reconciliation Worker (closes 7.6)

**Files:**
- Modify: `app/reconcile.py`
- Create: `app/reconcile_worker.py`
- Test: `tests/test_reconcile_worker.py`

**Interfaces:**
- Consumes: `app.reconcile.reconcile_one`, `app.provider_accounts.get_provider_for_org`
- Produces: `app.reconcile_worker.ReconciliationWorker` (start/stop/config), `app.reconcile_worker.ReconciliationAlertSink` (log + optional webhook)

### Task D1 — Reconciliation worker with retry and dead-letter

- [ ] **Step 1: Write failing test**

```python
# tests/test_reconcile_worker.py
from unittest.mock import MagicMock
from app.reconcile_worker import ReconciliationWorker
from app import models

def test_worker_reconciles_pending_and_marks_dead_letter(paari_client):
    ctx = paari_client
    # Create a PROVIDER_UNKNOWN txn
    # ... create bounded auth + provider txn in DB ...
    worker = ReconciliationWorker(interval_seconds=1, max_attempts=3, dead_letter_after=2)
    # mock provider that always raises
    # run reconcile_one directly (not in thread) for determinism
    ...
```

- [ ] **Step 2: Implement worker**

```python
# app/reconcile_worker.py
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from logging import getLogger
from typing import Callable

from sqlalchemy.orm import Session

from app.database import get_engine
from app import models
from app.reconcile import reconcile_one

logger = getLogger("paari.reconcile")

@dataclass
class ReconciliationWorker:
    interval_seconds: int = 60
    max_attempts: int = 10
    dead_letter_after: int = 5
    _stop: threading.Event = field(default_factory=threading.Event, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)

    def start(self, db_url: str | None = None):
        engine = get_engine(db_url) if db_url else None
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, args=(engine,), daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self.interval_seconds + 5)

    def _loop(self, engine):
        from sqlalchemy.orm import sessionmaker
        SessionLocal = sessionmaker(bind=engine) if engine else None
        while not self._stop.is_set():
            try:
                self._run_batch(SessionLocal() if SessionLocal else None)
            except Exception:
                logger.exception("reconciliation batch failed")
            self._stop.wait(self.interval_seconds)

    def _run_batch(self, session: Session | None):
        # Use a fresh session per batch; close after.
        ...
```

- [ ] **Step 3: Add dead-letter promotion**

When `txn.attempts >= self.dead_letter_after`, transition to `PROVIDER_UNKNOWN` (if not already), set `txn.last_error = "dead-letter: exceeded max reconcile attempts"`, audit with kind `reconcile_dead_letter`.

- [ ] **Step 4: Add AlertSink**

```python
class ReconciliationAlertSink:
    def __init__(self, webhook_url: str = ""):
        self.webhook_url = webhook_url

    def alert(self, event: str, txn: models.ProviderTransaction):
        msg = f"[reconcile] {event} auth={txn.authorization_id} org={txn.org_id}"
        logger.warning(msg)
        if self.webhook_url:
            # fire-and-forget httpx post, swallow errors
            import httpx
            try:
                httpx.post(self.webhook_url, json={"event": event, "txn": ...}, timeout=5.0)
            except Exception:
                pass
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_reconcile_worker.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add app/reconcile_worker.py app/reconcile.py tests/test_reconcile_worker.py
git commit -m "feat(reconcile): add background worker with retry/backoff, dead-letter, and alert sink"
```

---

## Phase E — Webhook Org-Account Verification (closes 7.4 residual)

**Files:**
- Modify: `app/routers/payments.py`
- Test: `tests/test_webhook_org_isolation.py`

**Interfaces:**
- Consumes: `app.provider_accounts.get_provider_for_org`
- Produces: additional webhook rejection path with audit `webhook_rejected_org_mismatch`

### Task E1 — Cross-org webhook rejection

- [ ] **Step 1: Write failing test**

```python
# tests/test_webhook_org_isolation.py
def test_webhook_from_wrong_provider_account_is_rejected(paari_client, monkeypatch):
    # 1. Create payment for org "tenant-a" with its own Razorpay keys
    # 2. Build a webhook payload signed with a DIFFERENT org's webhook secret
    # 3. POST to /v1/payments/webhooks/razorpay
    # 4. Assert status 401 (invalid signature) OR a new 403 with error code WEBHOOK_ORG_MISMATCH
    pass
```

- [ ] **Step 2: Implement**

In `razorpay_webhook`, after finding `txn` and selecting `provider`, add:

```python
expected_key_id = provider.key_id
actual_key_id = (((event.get("payload") or {}).get("account") or {}).get("id")) or event.get("account_id")
if actual_key_id and expected_key_id and actual_key_id != expected_key_id:
    # audit and return rejected
```

If Razorpay's webhook payload does not surface the account key id in the event body, derive the check from the already-verified signature: since `get_provider_for_org` selects the secret by org, a valid signature under Org A's secret proves the event came from Org A's account. Document this in a code comment and add a test that mocks the provider to return a different `key_id` for the same txn and asserts 401.

- [ ] **Step 3: Run tests**

Run: `pytest tests/test_webhook_org_isolation.py -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add app/routers/payments.py tests/test_webhook_org_isolation.py
git commit -m "feat(webhook): reject cross-org provider account events"
```

---

## Phase F — Sandbox/Production Separation (closes 8.7)

**Files:**
- Create: `app/config.py`
- Modify: `app/main.py` lifespan, `app/providers/razorpay.py`, `app/provider_accounts.py`
- Test: `tests/test_sandbox_separation.py`

**Interfaces:**
- Produces: `app.config.PaariEnv` enum, `app.config.load_config()` raising on prod misconfig

### Task F1 — Environment profiles

- [ ] **Step 1: Write failing test**

```python
def test_sandbox_allows_missing_secrets():
    import os; os.environ["PAARI_ENV"] = "sandbox"
    from app.config import load_config
    cfg = load_config()
    assert cfg.env == "sandbox"

def test_prod_requires_all_secrets(monkeypatch):
    monkeypatch.delenv("PAARI_LIVE", raising=False)
    monkeypatch.setenv("PAARI_ENV", "prod")
    for key in ["RAZORPAY_KEY_ID", "RAZORPAY_KEY_SECRET", ...]:
        monkeypatch.delenv(key, raising=False)
    from app.config import load_config
    with pytest.raises(RuntimeError, match="prod"):
        load_config()
```

- [ ] **Step 2: Implement `app/config.py`**

```python
from __future__ import annotations
import os
from enum import StrEnum

class PaariEnv(StrEnum):
    SANDBOX = "sandbox"
    PROD = "prod"
    PROD_LIVE = "prod-live"

def load_config() -> dict:
    env = PaariEnv(os.environ.get("PAARI_ENV", "sandbox"))
    is_live = os.environ.get("PAARI_LIVE") == "1"
    required = ["RAZORPAY_KEY_ID", "RAZORPAY_KEY_SECRET", "RAZORPAY_WEBHOOK_SECRET",
                "PAARI_ADMIN_API_KEY", "PAARI_SIGNING_KEY_PATH", "DATABASE_URL"]
    if env != PaariEnv.SANDBOX or is_live:
        missing = [k for k in required if not os.environ.get(k)]
        if missing:
            raise RuntimeError(f"{'PAARI_LIVE=1' if is_live else env.value} requires {', '.join(missing)}")
    api_base = os.environ.get("RAZORPAY_API_BASE", "")
    if env == PaariEnv.SANDBOX and not api_base:
        os.environ.setdefault("RAZORPAY_API_BASE", "https://api.razorpay.com/v1")
    return {"env": env, "is_live": is_live, "database_url": os.environ.get("DATABASE_URL", "sqlite:///./paari.db")}
```

- [ ] **Step 3: Wire into main.py lifespan**

In `lifespan()`, call `load_config()` before the `PAARI_LIVE=1` guard and store result in `app.state.paari_config`.

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_sandbox_separation.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add app/config.py app/main.py tests/test_sandbox_separation.py
git commit -m "feat(config): add sandbox/prod env profiles with required-secret guards"
```

---

## Phase G — Production Operations (closes 7.7)

**Files:**
- Modify: `.github/workflows/ci.yml`, `app/main.py`
- Create: `tests/test_postgres_migration.py`

**Interfaces:**
- Produces: CI Postgres migration test; `/health` richer response

### Task G1 — Postgres migration test in CI

- [ ] **Step 1: Write failing test**

```python
# tests/test_postgres_migration.py
import pytest

def test_alembic_migrates_postgres_if_url_provided(monkeypatch):
    url = monkeypatch.getenv("DATABASE_URL", "")
    if not url.startswith("postgresql"):
        pytest.skip("DATABASE_URL not set to postgresql; skipping migration test")
    from alembic import command
    from alembic.config import Config
    import pathlib
    cfg = Config(str(pathlib.Path("alembic.ini")))
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")
    command.check(cfg)
```

- [ ] **Step 2: Add Postgres service to CI**

In `.github/workflows/ci.yml`, add a matrix job or second job that:
- starts Postgres 16
- exports `DATABASE_URL=postgresql://paari:paari@127.0.0.1:5432/paari`
- runs `pip install -r requirements-postgres.txt`
- runs `python -m compileall -q app sdk scripts`
- runs `pytest -q tests/test_postgres_migration.py`

- [ ] **Step 3: Run test locally (if Postgres available) or skip**

Run: `pytest tests/test_postgres_migration.py -v`
Expected: PASS or SKIP

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml tests/test_postgres_migration.py
git commit -m "ci: add Postgres migration test job"
```

### Task G2 — Rich health check

- [ ] **Step 1: Write failing test**

```python
def test_health_returns_env_and_db_status(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert "env" in body
    assert "database" in body
```

- [ ] **Step 2: Implement**

In `app/main.py`, replace `health()` with:

```python
@app.get("/health")
def health():
    db_ok = False
    try:
        from app.database import engine
        with engine.connect() as c:
            c.execute("SELECT 1")
        db_ok = True
    except Exception:
        pass
    return {
        "status": "ok" if db_ok else "degraded",
        "service": "paari",
        "env": app.state.paari_config.get("env", "unknown") if hasattr(app.state, "paari_config") else "unknown",
        "database": "up" if db_ok else "down",
    }
```

- [ ] **Step 3: Run test**

Run: `pytest tests/ -k health -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add app/main.py tests/test_health.py
git commit -m "feat(health): include env and database status in /health"
```

---

## Phase H — Adversarial & Failure-Recovery Tests (closes 8.4, 8.6)

**Files:**
- Create: `tests/test_governance_attacks.py`, `tests/test_failure_recovery.py`
- Modify: none required — existing routers already enforce the rules; tests expose them.

**Interfaces:**
- Consumes: `paari_client` fixture, existing governance/reconcile/webhook endpoints

### Task H1 — Governance attack suite

- [ ] **Step 1: Write tests**

`tests/test_governance_attacks.py` with tests asserting DENY for:
1. Wrong merchant (merchant field tampered in intent)
2. Revoked parent (set parent status to REVOKED, submit intent → 401)
3. Revoked agent at execution (set agent status to REVOKED after minting auth, consume → 403)
4. High velocity (>5 intents in 1 minute → REVIEW or DENY)
5. Invalid MFA (submit bad parent signature to /mfa/verify → 401)
6. Modified payment intent after ALLOW (return cached intent; assert reasons unchanged)

- [ ] **Step 2: Run tests**

Run: `pytest tests/test_governance_attacks.py -v`
Expected: PASS (current code already enforces these; tests document the contract)

- [ ] **Step 3: Commit**

```bash
git add tests/test_governance_attacks.py
git commit -m "test(security): governance attack suite — wrong merchant, revoked parent/agent, velocity, invalid MFA"
```

### Task H2 — Failure and recovery tests

- [ ] **Step 1: Write tests**

`tests/test_failure_recovery.py` with tests asserting:
1. Razorpay timeout → `PROVIDER_UNKNOWN` + authorization remains spent
2. Duplicate webhook → `duplicate_ignored`, state unchanged
3. Delayed webhook (late arrival after PAID terminal) → ignored, state unchanged
4. Webhook unavailable (provider never posts) → manual reconcile restores state
5. No double payment (consume twice on same auth → second call 409)
6. Audit trail complete (after every failure path, `verify_chain` returns True)

- [ ] **Step 2: Run tests**

Run: `pytest tests/test_failure_recovery.py -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/test_failure_recovery.py
git commit -m "test(reliability): failure and recovery suite — timeout, duplicate/delayed webhook, reconcile, no double spend"
```

---

## Execution Order Summary

1. **Phase A** (Protocol completeness) — unblocks external implementers; required by every other phase that touches error handling or schemas.
2. **Phase B** (Audit hardening) — depends on A for error codes; small diff, high accountability value.
3. **Phase C** (Trust provider wiring) — can run in parallel with B; both touch routers but different ones.
4. **Phase E** (Webhook org verification) — depends on A; small, do in parallel with C.
5. **Phase D** (Reconciliation worker) — depends on B (audit events for dead-letter); main deliverable.
6. **Phase F** (Sandbox separation) — independent; run in parallel with A–E.
7. **Phase G** (Production ops) — depends on F (env profiles); run after F.
8. **Phase H** (Tests) — depends on A–E being in place so tests have endpoints to exercise; run last.

**Estimated scope:** 9 sub-plans, ~25 tasks, ~50–80 commits.

---

Plan complete and saved to `docs/superpowers/plans/2026-09-18-blueprint-implementation-plan.md`. Two execution options:

1. **Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

2. **Inline Execution** — Execute tasks in this session using `executing-plans`, batch execution with checkpoints.

Which approach?
