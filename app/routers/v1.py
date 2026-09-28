"""Stable Paari Protocol v1.0 surface."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os

import jwt as pyjwt
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, schemas, security, crypto_utils
from app.protocol.envelope import verify_envelope
from app.protocol.errors import PaariHTTPException, PaariErrorCode

router = APIRouter(prefix="/v1", tags=["protocol-v1"])
KEY_SUNSET_GRACE = timedelta(hours=24)
CAPABILITY_MAP = {"make_payment": "payment.create", "issue_refund_request": "refund.request"}


# The governance posture (PAARI_MODE / PAARI_REQUIRE_USER_MANDATE /
# PAARI_REQUIRE_SIGNED_MANDATE) has exactly ONE definition:
# app.config.mandate_policy(). A local `_mandate_mode()` used to live here and
# was never called, while routers/payments.py re-derived the same rule inline -
# three definitions, two of them dead, and any drift failed OPEN.


class V1RegisterRequest(BaseModel):
    envelope: dict


# Stable v1 protocol aliases. Legacy Phase 1-5 routes remain available, but
# external protocol clients can use only the versioned surface below.
@router.post("/auth/challenge", response_model=schemas.ChallengeResponse)
def v1_auth_challenge(req: schemas.ChallengeRequest, db: Session = Depends(get_db)):
    from app.routers.auth import create_challenge
    return create_challenge(req, db)


@router.post("/auth/verify", response_model=schemas.VerifyResponse)
def v1_auth_verify(req: schemas.VerifyRequest, db: Session = Depends(get_db)):
    from app.routers.auth import verify_challenge
    return verify_challenge(req, db)


@router.post("/mandates", response_model=schemas.PaymentMandateResponse)
def create_user_payment_mandate(req: schemas.CreatePaymentMandateRequest, db: Session = Depends(get_db),
                                x_admin_api_key: str = Header(default="")):
    """Create a trusted-surface/user mandate for the current MVP.

    The admin key represents the trusted user-consent/bootstrap boundary in
    this POC. A future user-facing surface should replace this with a real
    user authentication/signature flow; provider payment credentials never
    belong in this API.
    """
    agent = db.query(models.Agent).filter_by(agent_id=req.agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    security.require_admin_org(x_admin_api_key, agent.org_id)
    now = datetime.now(timezone.utc)
    valid_from = req.valid_from or now
    if valid_from.tzinfo is None:
        valid_from = valid_from.replace(tzinfo=timezone.utc)
    expires = req.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires <= valid_from:
        raise HTTPException(status_code=400, detail="expires_at must be after valid_from")
    if req.max_per_transaction <= 0 or req.max_daily_amount <= 0:
        raise HTTPException(status_code=400, detail="mandate limits must be positive")
    if req.max_per_transaction > req.max_daily_amount:
        raise HTTPException(status_code=400, detail="max_per_transaction cannot exceed max_daily_amount")
    for label, value in (("max_per_hour", req.max_per_hour),
                         ("max_per_merchant_per_day", req.max_per_merchant_per_day),
                         ("max_category_per_day", req.max_category_per_day)):
        if value is not None and value <= 0:
            raise HTTPException(status_code=400, detail=f"{label} must be positive when set")
    if req.currency.upper() != agent.currency.upper():
        raise HTTPException(status_code=400, detail="mandate currency must match the agent currency")
    mandate = models.UserPaymentMandate(
        org_id=agent.org_id, user_id=req.user_id, agent_id=agent.agent_id,
        mandate_id=req.mandate_id,  # client-chosen (like delegation_id); uniqueness enforced
        max_per_transaction=req.max_per_transaction, max_daily_amount=req.max_daily_amount,
        max_per_hour=req.max_per_hour, max_per_merchant_per_day=req.max_per_merchant_per_day,
        max_category_per_day=req.max_category_per_day,
        currency=req.currency.upper(), allowed_merchants=req.allowed_merchants or [],
        allowed_categories=req.allowed_categories or [], require_review_above=req.require_review_above,
        valid_from=valid_from, expires_at=expires, status=models.MandateStatus.ACTIVE,
        approval_reference=req.approval_reference,
    )
    db.add(mandate)
    if req.mandate_signature_b64 or req.user_public_key_pem:
        if not (req.user_public_key_pem and req.mandate_signature_b64):
            raise HTTPException(status_code=400, detail="signature requires both user_public_key_pem and mandate_signature_b64")
        mandate.user_public_key_pem = req.user_public_key_pem
        mandate.signature_b64 = req.mandate_signature_b64
        mandate.signing_key_id = req.signing_key_id or "user-key-1"
        mandate.signed_at = now
        from app.mandate_signing import verify_mandate_signature
        result = verify_mandate_signature(mandate)
        if not result.signature_valid:
            db.rollback()
            raise HTTPException(status_code=400, detail=f"mandate signature rejected: {'; '.join(result.reasons)}")
    try:
        db.flush()  # enforce mandate_id uniqueness before audit/commit
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="mandate_id already exists")
    from app.audit import record_audit
    record_audit(db, transaction_id=f"mandate:{mandate.mandate_id}", agent_id=agent.agent_id,
                 parent_id=(agent.parent.parent_id if agent.parent else None),
                 kind="user_mandate_created",
                 detail={"mandate_id": mandate.mandate_id, "user_id": req.user_id,
                         "max_per_transaction": req.max_per_transaction,
                         "max_daily_amount": req.max_daily_amount,
                         "max_per_hour": req.max_per_hour,
                         "max_per_merchant_per_day": req.max_per_merchant_per_day,
                         "max_category_per_day": req.max_category_per_day,
                         "currency": req.currency.upper(),
                         "signed": bool(mandate.signature_b64),
                         "signing_key_id": mandate.signing_key_id},
                 org_id=agent.org_id)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="mandate_id already exists")
    db.refresh(mandate)
    return _mandate_view(db, mandate)


def _mandate_view(db: Session, mandate: models.UserPaymentMandate,
                  now: datetime | None = None) -> dict:
    """Agent-facing view of a mandate.

    Every budget dimension is reported with a real aggregated figure. The
    merchant/category fields used to be hardcoded `None` even though the
    aggregation functions were imported on the very next line, so the API
    advertised per-merchant/category spend and always returned null.
    """
    from app.mandates import (daily_spend, hourly_spend, merchant_daily_spend,
                              category_daily_spend)
    from app.mandate_signing import verify_mandate_signature
    now = now or datetime.now(timezone.utc)
    spent = daily_spend(db, mandate, now=now)
    hourly = hourly_spend(db, mandate, now=now)
    # Per-merchant and per-category spend have no single value for the mandate
    # itself, so report the total across the mandate's own allowlists - which
    # is what "how much of my grocery budget is left" actually means.
    merchant_spent = sum(
        merchant_daily_spend(db, mandate, m, now=now)
        for m in (mandate.allowed_merchants or [])
    ) or None
    category_spent = sum(
        category_daily_spend(db, mandate, c, now=now)
        for c in (mandate.allowed_categories or [])
    ) or None
    signature_result = verify_mandate_signature(mandate) if mandate.signature_b64 else None
    return {
        "mandate_id": mandate.mandate_id, "user_id": mandate.user_id, "agent_id": mandate.agent_id,
        "status": mandate.status.value, "max_per_transaction": mandate.max_per_transaction,
        "max_daily_amount": mandate.max_daily_amount,
        "max_per_hour": mandate.max_per_hour,
        "max_per_merchant_per_day": mandate.max_per_merchant_per_day,
        "max_category_per_day": mandate.max_category_per_day,
        "currency": mandate.currency,
        "allowed_merchants": list(mandate.allowed_merchants or []),
        "allowed_categories": list(mandate.allowed_categories or []),
        "require_review_above": mandate.require_review_above, "valid_from": mandate.valid_from,
        "expires_at": mandate.expires_at, "daily_spent": spent,
        "daily_remaining": max(0, mandate.max_daily_amount - spent),
        "hourly_spent": hourly,
        "hourly_remaining": (max(0, mandate.max_per_hour - hourly) if mandate.max_per_hour is not None else None),
        "merchant_daily_spent": merchant_spent,
        "category_daily_spent": category_spent,
        "signing_key_id": mandate.signing_key_id,
        "signature_b64": mandate.signature_b64,
        "signature_valid": (signature_result.signature_valid if signature_result else None),
        "signed_at": mandate.signed_at,
    }


@router.get("/mandates/active/{agent_id}", response_model=schemas.PaymentMandateResponse)
def get_active_user_payment_mandate(agent_id: str, request: Request,
                                    x_paari_proof: str = Header(default=""),
                                    authorization: str = Header(default=""), db: Session = Depends(get_db)):
    from app.routers.payments import _authenticate, _resolve_session_token
    token = _resolve_session_token("", authorization)
    agent, _claims = _authenticate(db, token, expected_agent_id=agent_id, request=request, proof=x_paari_proof)
    from app.mandates import active_mandate, resolve_state, MandateState
    mandate = active_mandate(db, agent_id=agent.agent_id, org_id=agent.org_id)
    if mandate is None:
        # Distinguish "never had a mandate" from "had one that lapsed". The
        # distinction matters to the agent: a lapsed mandate means the user's
        # consent ENDED, whereas NONE just means this surface never set one up.
        state = resolve_state(db, agent_id=agent.agent_id, org_id=agent.org_id)
        detail = ("No active user payment mandate: a mandate exists for this agent but it "
                  "has expired or been revoked" if state is MandateState.LAPSED
                  else "No active user payment mandate")
        raise HTTPException(status_code=404, detail=detail)
    return _mandate_view(db, mandate)


@router.post("/admin/mandates/sweep", include_in_schema=False)
def sweep_mandate_lifecycle(db: Session = Depends(get_db),
                            x_admin_api_key: str = Header(default="")):
    """Run the mandate lifecycle sweepers: expire elapsed mandates and deny
    parked REVIEW intents whose step-up window closed (releasing their budget
    reservation). Idempotent; safe to call from cron."""
    from app.mandates import run_sweepers
    security.require_admin(x_admin_api_key)
    return run_sweepers(db)


@router.post("/mandates/{mandate_id}/revoke", response_model=schemas.PaymentMandateResponse)
def revoke_user_payment_mandate(mandate_id: str, req: schemas.RevokeMandateRequest,
                                db: Session = Depends(get_db), x_admin_api_key: str = Header(default="")):
    mandate = db.query(models.UserPaymentMandate).filter_by(mandate_id=mandate_id).first()
    if mandate:
        security.require_admin_org(x_admin_api_key, mandate.org_id)
    if not mandate:
        raise HTTPException(status_code=404, detail="Mandate not found")
    mandate.status = models.MandateStatus.REVOKED
    mandate.revoked_at = datetime.now(timezone.utc)
    agent = db.query(models.Agent).filter_by(agent_id=mandate.agent_id, org_id=mandate.org_id).first()
    from app.audit import record_audit
    record_audit(db, transaction_id=f"mandate:{mandate.mandate_id}", agent_id=mandate.agent_id,
                 parent_id=(agent.parent.parent_id if agent and agent.parent else None),
                 kind="user_mandate_revoked", detail={"mandate_id": mandate.mandate_id, "reason": req.reason},
                 org_id=mandate.org_id)
    db.commit(); db.refresh(mandate)
    return _mandate_view(db, mandate)


@router.post("/mandates/{mandate_id}/provider-binding", response_model=schemas.PaymentInstrumentBindingResponse)
def bind_provider_mandate(mandate_id: str, req: schemas.BindProviderMandateRequest,
                          db: Session = Depends(get_db), x_admin_api_key: str = Header(default="")):
    """Store only provider-issued mandate references; never raw payment credentials."""
    mandate = db.query(models.UserPaymentMandate).filter_by(mandate_id=mandate_id).first()
    if mandate:
        security.require_admin_org(x_admin_api_key, mandate.org_id)
    if not mandate:
        raise HTTPException(status_code=404, detail="Mandate not found")
    if mandate.status != models.MandateStatus.ACTIVE:
        raise HTTPException(status_code=409, detail="Mandate is not active")
    now_bind = datetime.now(timezone.utc)
    if mandate.expires_at <= now_bind or mandate.valid_from > now_bind:
        # Fail closed: an ACTIVE-status row outside its validity window cannot
        # take on a provider mandate binding.
        raise HTTPException(status_code=409, detail="Mandate is outside its validity window")
    if req.currency.upper() != mandate.currency.upper():
        raise HTTPException(status_code=400, detail="provider binding currency must match the mandate")
    if req.max_amount_minor_units > mandate.max_per_transaction:
        raise HTTPException(status_code=400, detail="provider binding exceeds mandate per-transaction limit")
    row = models.PaymentInstrumentBinding(
        org_id=mandate.org_id, mandate_id=mandate.mandate_id, provider=req.provider,
        provider_customer_ref=req.provider_customer_ref, provider_mandate_ref=req.provider_mandate_ref,
        provider_instrument_ref=req.provider_instrument_ref, currency=req.currency.upper(),
        max_amount_minor_units=req.max_amount_minor_units, status="active", expires_at=req.expires_at,
    )
    db.add(row)
    from app.audit import record_audit
    record_audit(db, transaction_id=f"mandate:{mandate.mandate_id}", agent_id=mandate.agent_id,
                 parent_id=None, kind="provider_mandate_bound",
                 detail={"binding_id": row.binding_id, "provider": req.provider,
                         "provider_mandate_ref": req.provider_mandate_ref}, org_id=mandate.org_id)
    db.commit(); db.refresh(row)
    return {
        "binding_id": row.binding_id, "mandate_id": row.mandate_id, "provider": row.provider,
        "provider_mandate_ref": row.provider_mandate_ref, "provider_instrument_ref": row.provider_instrument_ref,
        "currency": row.currency, "max_amount_minor_units": row.max_amount_minor_units,
        "status": row.status, "expires_at": row.expires_at,
    }


@router.get("/mandates/{mandate_id}/provider-binding", response_model=schemas.PaymentInstrumentBindingResponse)
def get_provider_binding(mandate_id: str, request: Request,
                         x_paari_proof: str = Header(default=""),
                         authorization: str = Header(default=""), db: Session = Depends(get_db)):
    from app.routers.payments import _authenticate, _resolve_session_token
    token = _resolve_session_token("", authorization)
    agent, _claims = _authenticate(db, token, request=request, proof=x_paari_proof)
    binding = db.query(models.PaymentInstrumentBinding).filter_by(
        mandate_id=mandate_id, org_id=agent.org_id
    ).first()
    if not binding:
        raise HTTPException(status_code=404, detail="No provider binding for this mandate")
    return {
        "binding_id": binding.binding_id, "mandate_id": binding.mandate_id,
        "provider": binding.provider, "provider_mandate_ref": binding.provider_mandate_ref,
        "provider_instrument_ref": binding.provider_instrument_ref,
        "currency": binding.currency, "max_amount_minor_units": binding.max_amount_minor_units,
        "status": binding.status, "expires_at": binding.expires_at,
    }


@router.post("/payments/intent", response_model=schemas.PaymentIntentResponse)
def v1_payment_intent(req: schemas.V1PaymentIntentRequest, request: Request,
                     x_paari_proof: str = Header(default=""),
                     authorization: str = Header(default=""), db: Session = Depends(get_db)):
    from app.routers.payments import submit_payment_intent
    return submit_payment_intent(req, request, x_paari_proof, authorization, db)


@router.post("/payments/authorizations/{authorization_id}/consume",
             response_model=schemas.ConsumeAuthorizationResponse)
def v1_consume_authorization(authorization_id: str, req: schemas.ConsumeAuthorizationRequest,
                             request: Request, x_paari_proof: str = Header(default=""),
                             authorization: str = Header(default=""), db: Session = Depends(get_db)):
    from app.routers.payments import consume_authorization
    return consume_authorization(authorization_id, req, request, x_paari_proof, authorization, db)


@router.post("/payments/mfa/challenge", response_model=schemas.MFAChallengeResponse)
def v1_mfa_challenge(req: schemas.MFAChallengeRequest, request: Request,
                     x_paari_proof: str = Header(default=""),
                     authorization: str = Header(default=""), db: Session = Depends(get_db)):
    from app.routers.payments import request_mfa_challenge
    return request_mfa_challenge(req, request, x_paari_proof, authorization, db)


@router.post("/payments/mfa/verify", response_model=schemas.PaymentIntentResponse)
def v1_mfa_verify(req: schemas.MFAVerifyRequest, db: Session = Depends(get_db)):
    from app.routers.payments import verify_mfa_challenge
    return verify_mfa_challenge(req, db)


@router.post("/payments/webhooks/razorpay")
def v1_razorpay_webhook(request: Request, x_razorpay_signature: str = Header(default=""),
                       db: Session = Depends(get_db)):
    from app.routers.payments import razorpay_webhook
    return razorpay_webhook(request, x_razorpay_signature, db)


def _signed_card(agent: models.Agent, parent: models.ParentAuthority | None, credential_id: str = "") -> schemas.V1AgentCard:
    """Canonical protocol v1 Agent Card: signed discovery object only."""
    fields = {
        "protocol": "paari",
        "protocol_version": "1.0",
        "issuer": "paari",
        "agent_id": agent.agent_id,
        "name": agent.name,
        "agent_type": agent.agent_type,
        "parent_id": parent.parent_id if parent else "",
        "status": agent.status.value,
        "public_key": agent.public_key_pem,
        "capabilities": [CAPABILITY_MAP.get(c, c) for c in list(agent.granted_capabilities or [])],
        "limits": {"max_amount": int(agent.payment_limit_minor_units), "currency": agent.currency},
        "credential_id": credential_id,
        "expires_at": (agent.valid_until.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if agent.valid_until else None),
        "endpoints": {
            "protocol_discovery": "/.well-known/paari",
            "agent_card": f"/v1/agents/{agent.agent_id}/card",
            "payment_intent": "/v1/payments/intent",
            "consume": "/v1/payments/authorizations/{authorization_id}/consume",
        },
    }
    return schemas.V1AgentCard(
        **fields,
        card_signature_b64=security.sign_agent_card(fields),
        paari_public_key_pem=security.paari_public_key_pem(),
    )


@router.post("/agents/register")
def v1_register_agent(req: V1RegisterRequest, db: Session = Depends(get_db)):
    envelope = req.envelope
    if not isinstance(envelope, dict) or envelope.get("version") != "1.0" or envelope.get("protocol") != "paari":
        raise PaariHTTPException(status_code=400, code=PaariErrorCode.UNSUPPORTED_PROTOCOL_VERSION, detail="Unsupported protocol version")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise PaariHTTPException(status_code=400, code=PaariErrorCode.ENVELOPE_SIGNATURE_INVALID, detail="Envelope has no payload")
    agent_pub = payload.get("public_key_pem", "")
    if not agent_pub or not verify_envelope(agent_pub, envelope):
        raise PaariHTTPException(status_code=401, code=PaariErrorCode.ENVELOPE_SIGNATURE_INVALID, detail="Envelope signature verification failed")
    presented_fingerprint = crypto_utils.public_key_fingerprint(agent_pub)
    if envelope.get("sender") != presented_fingerprint:
        raise PaariHTTPException(status_code=401, code=PaariErrorCode.ENVELOPE_SIGNATURE_INVALID, detail="Envelope sender is not bound to the registering agent key")
    delegation = payload.get("delegation") or {}
    required = {"delegation_id", "parent_id", "agent_public_key_fingerprint", "granted_capabilities",
                "payment_limit_minor_units", "currency", "issued_at", "expires_at"}
    if not required.issubset(delegation):
        raise PaariHTTPException(status_code=400, code=PaariErrorCode.ENVELOPE_SIGNATURE_INVALID, detail="Delegation missing required fields")
    parent = db.query(models.ParentAuthority).filter_by(parent_id=delegation["parent_id"]).first()
    if not parent or parent.status != models.ParentStatus.ACTIVE:
        raise PaariHTTPException(status_code=401, code=PaariErrorCode.PARENT_REVOKED, detail="Unknown, unverified, or revoked parent authority")
    delegation_json = crypto_utils.canonical_json(delegation)
    if not crypto_utils.verify_signature(parent.public_key_pem, delegation_json, payload.get("delegation_signature_b64", "")):
        raise PaariHTTPException(status_code=401, code=PaariErrorCode.ENVELOPE_SIGNATURE_INVALID, detail="Delegation signature verification failed")

    now = datetime.now(timezone.utc)
    try:
        issued = datetime.fromtimestamp(int(delegation["issued_at"]), tz=timezone.utc)
        expires = datetime.fromtimestamp(int(delegation["expires_at"]), tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        raise PaariHTTPException(status_code=400, code=PaariErrorCode.DELEGATION_EXPIRED, detail="Delegation timestamps invalid")
    if issued > now + timedelta(seconds=security.CLOCK_SKEW_LEEWAY_SECONDS):
        raise PaariHTTPException(status_code=401, code=PaariErrorCode.DELEGATION_EXPIRED, detail="Delegation is issued in the future")
    if expires <= now:
        raise PaariHTTPException(status_code=401, code=PaariErrorCode.DELEGATION_EXPIRED, detail="Delegation has expired")
    if expires - issued > timedelta(days=366):
        raise PaariHTTPException(status_code=400, code=PaariErrorCode.DELEGATION_EXPIRED, detail="Delegation lifetime exceeds protocol maximum")

    fingerprint = crypto_utils.public_key_fingerprint(agent_pub)
    if delegation["agent_public_key_fingerprint"] != fingerprint:
        raise PaariHTTPException(status_code=401, code=PaariErrorCode.ENVELOPE_SIGNATURE_INVALID, detail="Delegation is not bound to this agent's public key")
    if db.query(models.DelegationRecord).filter_by(delegation_id=delegation["delegation_id"]).first() is not None:
        raise PaariHTTPException(status_code=409, code=PaariErrorCode.ENVELOPE_SIGNATURE_INVALID, detail="Delegation has already been consumed")
    capabilities = list(delegation.get("granted_capabilities") or [])
    if not capabilities:
        raise PaariHTTPException(status_code=400, code=PaariErrorCode.CAPABILITY_NOT_DELEGATED, detail="Delegation must grant at least one capability")
    limit = int(delegation["payment_limit_minor_units"])
    if limit <= 0:
        raise PaariHTTPException(status_code=400, code=PaariErrorCode.LIMIT_EXCEEDED, detail="Delegated payment limit must be positive")

    db.add(models.DelegationRecord(
        delegation_id=delegation["delegation_id"], parent_pk=parent.id,
        org_id=parent.org_id, agent_public_key_fingerprint=fingerprint,
        granted_capabilities=capabilities, payment_limit_minor_units=limit,
        currency=delegation["currency"], issued_at=issued, expires_at=expires,
        consumed=True, consumed_at=now,
    ))
    agent = models.Agent(
        name=payload.get("name", ""), agent_type=payload.get("agent_type", ""),
        purpose=payload.get("purpose", ""), parent_pk=parent.id, org_id=parent.org_id,
        delegation_id=delegation["delegation_id"], public_key_pem=agent_pub,
        granted_capabilities=capabilities, payment_limit_minor_units=limit,
        currency=delegation["currency"], status=models.AgentStatus.ACTIVE,
        valid_until=expires, protocol_version="1.0",
    )
    db.add(agent)
    db.flush()
    jwt_token, credential_id, cred_exp = security.issue_credential_jwt(
        agent_id=agent.agent_id, capabilities=capabilities, payment_limit=limit,
        currency=delegation["currency"], protocol_version="1.0",
    )
    credential_expires_at = min(cred_exp, expires)
    db.add(models.Credential(credential_id=credential_id, agent_pk=agent.id,
                             org_id=parent.org_id, signed_jwt=jwt_token, expires_at=credential_expires_at))
    from app.audit import record_audit
    record_audit(db, transaction_id=f"delegation:{delegation['delegation_id']}", agent_id=agent.agent_id,
                 parent_id=parent.parent_id, kind="delegation_consumed",
                 detail={"delegation_id": delegation["delegation_id"], "protocol": "1.0"}, org_id=parent.org_id)
    record_audit(db, transaction_id=f"delegation:{delegation['delegation_id']}", agent_id=agent.agent_id,
                 parent_id=parent.parent_id, kind="credential_issued", detail={"credential_id": credential_id}, org_id=parent.org_id)
    db.commit(); db.refresh(agent)
    return {"agent_card": _signed_card(agent, parent, credential_id),
            "credential_jwt": jwt_token, "credential_expires_at": credential_expires_at.isoformat()}


@router.get("/agents/{agent_id}/card")
def v1_get_card(agent_id: str, db: Session = Depends(get_db)):
    agent = db.query(models.Agent).filter_by(agent_id=agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    parent = db.query(models.ParentAuthority).filter_by(id=agent.parent_pk).first()
    cred = db.query(models.Credential).filter_by(agent_pk=agent.id, revoked=False).order_by(models.Credential.issued_at.desc()).first()
    return _signed_card(agent, parent, cred.credential_id if cred else "")


class CreateOrgRequest(BaseModel):
    org_id: str
    name: str
    parent_id: str | None = None


@router.post("/orgs")
def create_org(req: CreateOrgRequest, db: Session = Depends(get_db), x_admin_api_key: str = Header(default="")):
    from app.audit import record_audit
    security.require_admin_org(x_admin_api_key, None)
    if not req.org_id or not req.name:
        raise HTTPException(status_code=400, detail="org_id and name are required")
    if db.query(models.Organization).filter_by(org_id=req.org_id).first():
        raise HTTPException(status_code=409, detail="Organization already exists")
    parent = None
    if req.parent_id:
        parent = db.query(models.ParentAuthority).filter_by(parent_id=req.parent_id).first()
        if not parent:
            raise HTTPException(status_code=404, detail="Parent authority not found")
    db.add(models.Organization(org_id=req.org_id, name=req.name))
    if parent:
        parent.org_id = req.org_id
    record_audit(db, transaction_id=f"org:{req.org_id}", agent_id="", parent_id=req.parent_id,
                 kind="org_created", detail={"org_id": req.org_id, "name": req.name}, org_id=req.org_id)
    db.commit()
    return {"org_id": req.org_id, "name": req.name}


@router.post("/reconcile/{authorization_id}")
def manual_reconcile(authorization_id: str, req: schemas.ReconcileRequest,
                     request: Request, x_paari_proof: str = Header(default=""),
                     authorization: str = Header(default=""), db: Session = Depends(get_db)):
    from app.reconcile import reconcile_one
    auth = db.query(models.BoundedAuthorization).filter_by(authorization_id=authorization_id).first()
    if not auth:
        raise HTTPException(status_code=404, detail="Authorization not found")
    # Reconciliation is still a money-sensitive operation: use the same
    # sender-constrained session proof as payment execution.
    from app.routers.payments import _authenticate, _resolve_session_token
    token = _resolve_session_token(req.session_token, authorization)
    _authenticate(db, token, expected_agent_id=auth.agent_id, request=request, proof=x_paari_proof)
    return reconcile_one(db, authorization_id)


@router.get("/proof/{transaction_id}")
def get_proof_bundle(transaction_id: str, request: Request, authorization: str = Header(default=""),
                     x_paari_proof: str = Header(default=""), db: Session = Depends(get_db)):
    """Inspectable proof bundle for one transaction — the per-request evidence package.

    The bundle is per-payment-request (keyed by transaction_id + idempotency),
    not per arbitrary transaction string. If `transaction_id` is ambiguous (multiple
    intents share it, e.g. after a velocity-REVIEW resubmission), this endpoint
    fails closed with 409 and the caller must disambiguate via the audit trail.
    """
    from app.proof_bundle import collect_proof_bundle
    from app.routers.payments import _authenticate, _resolve_session_token
    # Require a valid sender-constrained session; then enforce that the bundle
    # belongs to the authenticated agent (same pattern as /audit).
    # Accept transaction-bound proof (no body) by resolving token from header only.
    token = _resolve_session_token("", authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Authorization: Bearer <session-token> is required")
    agent, _claims = _authenticate(db, token, request=request, proof=x_paari_proof)
    try:
        bundle = collect_proof_bundle(db, transaction_id)
    except ValueError as e:
        msg = str(e)
        if "unknown" in msg:
            raise HTTPException(status_code=404, detail=msg)
        if "ambiguous" in msg:
            raise HTTPException(status_code=409, detail=msg + " — bundle is per-payment-request; use intent_id via audit")
        raise
    # Enforce ownership: the intent's agent must match the caller
    bundle_agent = bundle["artifacts"]["agent_identity"]["agent_id"]
    if bundle_agent != agent.agent_id:
        raise HTTPException(status_code=403, detail="This proof bundle does not belong to your agent")
    return bundle


@router.get("/audit/{transaction_id}")
def query_audit(transaction_id: str, request: Request, authorization: str = Header(default=""),
                 x_paari_proof: str = Header(default=""), db: Session = Depends(get_db)):
    from app.routers.payments import _authenticate, _resolve_session_token
    token = _resolve_session_token("", authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Authorization: Bearer <session-token> is required")
    agent, _claims = _authenticate(db, token, request=request, proof=x_paari_proof)
    events = db.query(models.AuditEvent).filter_by(transaction_id=transaction_id).order_by(models.AuditEvent.id.asc()).all()
    if not events:
        raise HTTPException(status_code=404, detail="No audit trail for this transaction")
    event_agents = {e.agent_id for e in events}
    if event_agents != {agent.agent_id}:
        raise HTTPException(status_code=403, detail="This audit trail does not belong to your agent")
    event_orgs = {e.org_id for e in events}
    if event_orgs != {agent.org_id}:
        raise HTTPException(status_code=403, detail="Cross-organization audit access denied")
    from app.audit import verify_chain
    return {"transaction_id": transaction_id,
            "chain_verified": verify_chain(db, transaction_id),
            "events": [{"kind": e.kind, "detail": e.detail, "prev_hash": e.prev_hash,
                         "event_hash": e.event_hash, "created_at": e.created_at.isoformat(),
                         "event_id": e.id, "agent_id": e.agent_id, "parent_id": e.parent_id,
                         "org_id": e.org_id, "transaction_id": e.transaction_id,
                         "hash_version": getattr(e, "hash_version", 1) or 1} for e in events]}


class RotateKeyRequest(BaseModel):
    new_public_key_pem: str
    delegation: dict
    delegation_signature_b64: str


@router.post("/agents/{agent_id}/rotate-key")
def rotate_agent_key(agent_id: str, req: RotateKeyRequest, db: Session = Depends(get_db),
                     x_admin_api_key: str = Header(default="")):
    from app.audit import record_audit
    agent = db.query(models.Agent).filter_by(agent_id=agent_id).first()
    if not agent or agent.status != models.AgentStatus.ACTIVE:
        raise HTTPException(status_code=401, detail="Agent not eligible for rotation")
    parent = db.query(models.ParentAuthority).filter_by(id=agent.parent_pk).first()
    if not parent or parent.status != models.ParentStatus.ACTIVE:
        raise HTTPException(status_code=401, detail="Parent authority is no longer active")
    is_admin = security.is_admin_key(x_admin_api_key)
    if is_admin:
        security.require_admin_org(x_admin_api_key, parent.org_id)
    delegation = req.delegation or {}
    if not delegation:
        raise HTTPException(status_code=401, detail="Fresh parent-signed delegation required for key rotation")
    if not crypto_utils.verify_signature(parent.public_key_pem, crypto_utils.canonical_json(delegation), req.delegation_signature_b64):
        raise HTTPException(status_code=401, detail="Rotation delegation signature verification failed")
    now = datetime.now(timezone.utc)
    try:
        issued = datetime.fromtimestamp(int(delegation["issued_at"]), tz=timezone.utc)
        expires = datetime.fromtimestamp(int(delegation["expires_at"]), tz=timezone.utc)
    except KeyError:
        raise HTTPException(status_code=400, detail="Rotation delegation timestamps are required")
    except Exception:
        raise HTTPException(status_code=400, detail="Rotation delegation expiry is invalid")
    if issued > now + timedelta(seconds=security.CLOCK_SKEW_LEEWAY_SECONDS) or abs(int(now.timestamp()) - int(issued.timestamp())) > 5 * 60:
        raise HTTPException(status_code=401, detail="Rotation delegation is stale or issued in the future")
    if delegation.get("parent_id") != parent.parent_id:
        raise HTTPException(status_code=401, detail="Rotation delegation belongs to a different parent")
    if expires <= now:
        raise HTTPException(status_code=401, detail="Rotation delegation has expired")
    new_fp = crypto_utils.public_key_fingerprint(req.new_public_key_pem)
    if delegation.get("agent_public_key_fingerprint") != new_fp:
        raise HTTPException(status_code=401, detail="Rotation delegation is not bound to new key")
    if db.query(models.DelegationRecord).filter_by(delegation_id=delegation.get("delegation_id")).first():
        raise HTTPException(status_code=409, detail="Rotation delegation already consumed")
    db.add(models.DelegationRecord(
        delegation_id=delegation["delegation_id"], parent_pk=parent.id, org_id=parent.org_id,
        agent_public_key_fingerprint=new_fp, granted_capabilities=delegation.get("granted_capabilities", agent.granted_capabilities),
        payment_limit_minor_units=delegation.get("payment_limit_minor_units", agent.payment_limit_minor_units),
        currency=delegation.get("currency", agent.currency),
        issued_at=datetime.fromtimestamp(int(delegation.get("issued_at", int(now.timestamp()))), tz=timezone.utc),
        expires_at=expires, consumed=True, consumed_at=now,
    ))
    agent.old_public_key_pem = agent.public_key_pem
    agent.key_sunset_at = now + KEY_SUNSET_GRACE
    agent.public_key_pem = req.new_public_key_pem
    agent.delegation_id = delegation["delegation_id"]
    agent.granted_capabilities = delegation.get("granted_capabilities", agent.granted_capabilities)
    agent.payment_limit_minor_units = delegation.get("payment_limit_minor_units", agent.payment_limit_minor_units)
    agent.currency = delegation.get("currency", agent.currency)
    agent.valid_until = expires
    token, credential_id, exp = security.issue_credential_jwt(agent.agent_id, agent.granted_capabilities,
                                                              agent.payment_limit_minor_units, agent.currency,
                                                              protocol_version=agent.protocol_version or "1.0")
    exp = min(exp, expires)
    for cred in db.query(models.Credential).filter_by(agent_pk=agent.id, revoked=False).all():
        cred.revoked = True; cred.superseded_by = credential_id; cred.rotates_at = now
    db.add(models.Credential(credential_id=credential_id, agent_pk=agent.id, org_id=agent.org_id,
                             signed_jwt=token, expires_at=exp))
    record_audit(db, transaction_id=f"delegation:{delegation['delegation_id']}", agent_id=agent.agent_id,
                 parent_id=parent.parent_id, kind="key_rotated",
                 detail={"credential_id": credential_id, "key_sunset_at": agent.key_sunset_at.isoformat()}, org_id=agent.org_id)
    db.commit()
    return {"agent_id": agent.agent_id, "credential_jwt": token, "credential_expires_at": exp.isoformat(),
            "key_sunset_at": agent.key_sunset_at.isoformat()}


class RevokeAuthorizationRequest(BaseModel):
    session_token: str


@router.post("/authorizations/{authorization_id}/revoke")
def revoke_authorization(authorization_id: str, req: RevokeAuthorizationRequest,
                         request: Request, x_paari_proof: str = Header(default=""),
                         authorization: str = Header(default=""), db: Session = Depends(get_db)):
    from app.audit import record_audit
    from app.routers.payments import _authenticate, _resolve_session_token
    auth = db.query(models.BoundedAuthorization).filter_by(authorization_id=authorization_id).first()
    if not auth:
        raise HTTPException(status_code=404, detail="Authorization not found")
    token = _resolve_session_token(req.session_token, authorization)
    _authenticate(db, token, expected_agent_id=auth.agent_id, request=request, proof=x_paari_proof)
    burned = db.execute(update(models.BoundedAuthorization)
                         .where(models.BoundedAuthorization.authorization_id == authorization_id,
                                models.BoundedAuthorization.usage_count < models.BoundedAuthorization.max_usage)
                         .values(usage_count=models.BoundedAuthorization.max_usage)).rowcount
    if burned != 1:
        db.rollback(); raise HTTPException(status_code=409, detail="Authorization already used or revoked")
    record_audit(db, transaction_id=auth.transaction_id, agent_id=auth.agent_id, parent_id=None,
                 kind="authorization_revoked", detail={"authorization_id": authorization_id}, org_id=auth.org_id)
    db.commit(); return {"authorization_id": authorization_id, "revoked": True}


class ParentRotateKeyRequest(BaseModel):
    new_public_key_pem: str


@router.post("/parents/{parent_id}/rotate-key")
def rotate_parent_key(parent_id: str, req: ParentRotateKeyRequest, db: Session = Depends(get_db),
                      x_admin_api_key: str = Header(default="")):
    from app.audit import record_audit
    parent = db.query(models.ParentAuthority).filter_by(parent_id=parent_id).first()
    if not parent or parent.status != models.ParentStatus.ACTIVE:
        raise HTTPException(status_code=404, detail="Active parent authority not found")
    security.require_admin_org(x_admin_api_key, parent.org_id)
    try:
        key = serialization.load_pem_public_key(req.new_public_key_pem.encode())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("parent key must be Ed25519")
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid parent public key; expected Ed25519 PEM") from exc
    parent.public_key_pem = req.new_public_key_pem
    record_audit(db, transaction_id=f"parent:{parent_id}", agent_id="", parent_id=parent_id,
                 kind="parent_key_rotated", detail={"fingerprint": crypto_utils.public_key_fingerprint(req.new_public_key_pem)}, org_id=parent.org_id)
    db.commit(); return {"parent_id": parent_id, "rotated": True}


class KybRequest(BaseModel):
    provider_ref: str


@router.post("/parents/{parent_id}/kyb")
def record_parent_kyb(parent_id: str, req: KybRequest, db: Session = Depends(get_db),
                      x_admin_api_key: str = Header(default="")):
    from app.audit import record_audit
    parent = db.query(models.ParentAuthority).filter_by(parent_id=parent_id).first()
    if not parent:
        raise HTTPException(status_code=404, detail="Parent authority not found")
    security.require_admin_org(x_admin_api_key, parent.org_id)
    parent.trust_tier = "kyb_verified"; parent.kyb_provider_ref = req.provider_ref
    record_audit(db, transaction_id=f"parent:{parent_id}", agent_id="", parent_id=parent_id,
                 kind="kyb_verified", detail={"provider_ref": req.provider_ref}, org_id=parent.org_id)
    db.commit(); return {"parent_id": parent_id, "trust_tier": parent.trust_tier}
