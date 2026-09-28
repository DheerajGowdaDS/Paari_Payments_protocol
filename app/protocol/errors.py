"""Paari v1 structured error taxonomy and FastAPI exception handler."""
from __future__ import annotations

import uuid
from enum import StrEnum

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse


class PaariErrorCode(StrEnum):
    UNSUPPORTED_PROTOCOL_VERSION = "UNSUPPORTED_PROTOCOL_VERSION"
    ENVELOPE_SIGNATURE_INVALID = "ENVELOPE_SIGNATURE_INVALID"
    DELEGATION_EXPIRED = "DELEGATION_EXPIRED"
    SESSION_INVALID = "SESSION_INVALID"
    PROOF_REPLAYED = "PROOF_REPLAYED"
    PROOF_PATH_MISMATCH = "PROOF_PATH_MISMATCH"
    CAPABILITY_NOT_DELEGATED = "CAPABILITY_NOT_DELEGATED"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    CURRENCY_MISMATCH = "CURRENCY_MISMATCH"
    PARENT_REVOKED = "PARENT_REVOKED"
    AGENT_REVOKED = "AGENT_REVOKED"
    AUTHORIZATION_ALREADY_USED = "AUTHORIZATION_ALREADY_USED"
    AUTHORIZATION_EXPIRED = "AUTHORIZATION_EXPIRED"
    PROVIDER_MISCONFIGURED = "PROVIDER_MISCONFIGURED"
    WEBHOOK_SIGNATURE_INVALID = "WEBHOOK_SIGNATURE_INVALID"
    WEBHOOK_VALUE_MISMATCH = "WEBHOOK_VALUE_MISMATCH"
    WEBHOOK_ORG_MISMATCH = "WEBHOOK_ORG_MISMATCH"
    PROVIDER_UNKNOWN = "PROVIDER_UNKNOWN"
    RECONCILIATION_VALUE_MISMATCH = "RECONCILIATION_VALUE_MISMATCH"
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
