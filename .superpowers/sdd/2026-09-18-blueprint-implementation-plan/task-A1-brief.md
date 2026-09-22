# Task A1 Brief — Error-code taxonomy and structured error responses

**Phase:** A (Protocol Completeness)
**Depends on:** nothing (first task)
**Blocks:** A2, B1, C1, E1 (all use error codes or touch routers)

## What to build

Create `app/protocol/errors.py` with:
- `PaariErrorCode(StrEnum)` — the exact enum values listed in Step 2 of the plan
- `PaariHTTPException(HTTPException)` — stores `code` on the exception
- `error_response(code, detail, status_code)` — returns `{"code": ..., "detail": ..., "request_id": str(uuid.uuid4())}`
- `paari_exception_handler(request, exc)` — async FastAPI exception handler returning JSONResponse

Wire it into `app/main.py`:
- Import `paari_exception_handler` and `PaariHTTPException`
- Call `app.add_exception_handler(PaariHTTPException, paari_exception_handler)`

Replace one router's HTTPException strings with PaariHTTPException:
- In `app/routers/v1.py`, function `v1_register_agent`, replace every `HTTPException(status_code=..., detail=...)` with `PaariHTTPException(status_code, PaariErrorCode.<CODE>, ...)` using the exact mapping:
  - 400 "Unsupported protocol version" → `UNSUPPORTED_PROTOCOL_VERSION`
  - 400 "Envelope has no payload" → `ENVELOPE_SIGNATURE_INVALID`  
  - 401 "Envelope signature verification failed" → `ENVELOPE_SIGNATURE_INVALID`
  - 401 "Envelope sender is not bound to the registering agent key" → `ENVELOPE_SIGNATURE_INVALID`
  - 400 "Delegation missing required fields" → `ENVELOPE_SIGNATURE_INVALID`
  - 401 "Unknown, unverified, or revoked parent authority" → `PARENT_REVOKED`
  - 401 "Delegation signature verification failed" → `ENVELOPE_SIGNATURE_INVALID`
  - 400 "Delegation timestamps invalid" → `DELEGATION_EXPIRED`
  - 401 "Delegation is issued in the future" → `DELEGATION_EXPIRED`
  - 401 "Delegation has expired" → `DELEGATION_EXPIRED`
  - 400 "Delegation lifetime exceeds protocol maximum" → `DELEGATION_EXPIRED`
  - 401 "Delegation is not bound to this agent's public key" → `ENVELOPE_SIGNATURE_INVALID`
  - 409 "Delegation has already been consumed" → `ENVELOPE_SIGNATURE_INVALID`
  - 400 "Delegation must grant at least one capability" → `CAPABILITY_NOT_DELEGATED`
  - 400 "Delegated payment limit must be positive" → `LIMIT_EXCEEDED`

Keep all HTTP status codes identical. Keep all detail strings identical.

## Tests to write

`tests/test_protocol_errors.py`:
```python
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

## Commit

```bash
git add app/protocol/errors.py app/main.py app/routers/v1.py tests/test_protocol_errors.py
git commit -m "feat(protocol): add PaariErrorCode taxonomy and structured error responses"
```

## Report

Write your report to: `C:\Users\gowda\projects_DS\paari_fixed\.superpowers\sdd\2026-09-18-blueprint-implementation-plan\task-A1-report.md`

Report format:
- Status: DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED
- Tests: <count>/<count> passing
- Commits: <base7>..<head7>
- Concerns: <one-line per concern, or "None">
