"""Paari payment governance and provider execution boundary.

Security contract:
  1. authenticate the agent before reading agent-scoped idempotency data;
  2. revalidate live trust at authorization and execution time;
  3. mint only a short-lived, single-use authorization;
  4. reserve usage atomically before touching the provider;
  5. bind provider account to the authorization's organization;
  6. use provider idempotency keyed by authorization_id;
  7. settle ONLY from a signature-verified webhook or provider reconciliation;
  8. compare provider amount/currency/order against the exact authorization;
  9. record a tamper-evident audit trail of decisions and state transitions.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from datetime import datetime, timezone, timedelta

import httpx

import jwt as pyjwt
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app import config, models, schemas, security, crypto_utils, governance, mandates
from app.trust import get_trust_provider
from app.mandates import evaluate_mandate
from app.provider_accounts import get_provider_for_org
from app.providers.razorpay import RazorpayConfigError
from app.transitions import transition_txn, IllegalTransitionError
from app.providers.base import get_provider
from app.protocol.errors import PaariHTTPException, PaariErrorCode

router = APIRouter(prefix="/payments", tags=["payments"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


VELOCITY_WINDOW = timedelta(minutes=1)
VELOCITY_MAX_INTENTS = 5
STEP_UP_THRESHOLD_RATIO = 0.8
REVIEW_TTL = timedelta(minutes=5)


def _key_for_session(agent: models.Agent, claims: dict) -> tuple[str, str]:
    fingerprint = ((claims.get("cnf") or {}).get("jkt") or "").strip()
    current = crypto_utils.public_key_fingerprint(agent.public_key_pem)
    if fingerprint == current or not fingerprint:
        return agent.public_key_pem, current
    if agent.old_public_key_pem and agent.key_sunset_at and agent.key_sunset_at > _now():
        old = crypto_utils.public_key_fingerprint(agent.old_public_key_pem)
        if fingerprint == old:
            return agent.old_public_key_pem, old
    raise pyjwt.InvalidTokenError("session key binding is no longer valid")


def _resolve_session_token(body_token: str | None, authorization: str) -> str:
    header_token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
    if header_token and body_token and not secrets.compare_digest(header_token, body_token):
        raise HTTPException(status_code=400, detail="Authorization header and body session token do not match")
    return header_token or (body_token or "")


def _authenticate(db: Session, token: str, *, expected_agent_id: str | None = None,
                  request: Request | None = None, proof: str | None = None) -> tuple[models.Agent, dict]:
    try:
        claims = security.decode_session_token(token)
    except pyjwt.PyJWTError as exc:
        raise PaariHTTPException(status_code=401, code=PaariErrorCode.SESSION_INVALID, detail="Session token invalid or expired") from exc
    if expected_agent_id and claims.get("sub") != expected_agent_id:
        raise PaariHTTPException(status_code=403, code=PaariErrorCode.SESSION_INVALID, detail="Session token does not belong to this agent")
    agent = db.query(models.Agent).filter_by(agent_id=claims.get("sub")).first()
    if not agent or agent.status != models.AgentStatus.ACTIVE:
        raise PaariHTTPException(status_code=401, code=PaariErrorCode.AGENT_REVOKED, detail="Agent is no longer active")
    credential = db.query(models.Credential).filter_by(credential_id=claims.get("credential_id")).first()
    now = _now()
    if not credential or credential.revoked or credential.expires_at < now:
        raise PaariHTTPException(status_code=401, code=PaariErrorCode.SESSION_INVALID, detail="Credential is revoked or expired")
    parent = db.query(models.ParentAuthority).filter_by(id=agent.parent_pk).first()
    if not parent or parent.status != models.ParentStatus.ACTIVE:
        raise PaariHTTPException(status_code=401, code=PaariErrorCode.PARENT_REVOKED, detail="Parent authority is no longer active")
    if agent.valid_until and agent.valid_until < now:
        raise PaariHTTPException(status_code=401, code=PaariErrorCode.SESSION_INVALID, detail="Agent delegation has expired")

    require_proof = claims.get("protocol_version") == "1.0" or os.environ.get("PAARI_REQUIRE_REQUEST_PROOF") == "1"
    if require_proof:
        if not proof or request is None:
            raise PaariHTTPException(status_code=401, code=PaariErrorCode.PROOF_REPLAYED, detail="Paari-Proof-JWT is required")
        try:
            public_key, _ = _key_for_session(agent, claims)
            security.verify_request_proof(
                proof,
                token,
                agent_id=agent.agent_id,
                public_key_pem=public_key,
                method=request.method,
                path=request.url.path + (("?" + request.url.query) if request.url.query else ""),
                db=db,
                org_id=agent.org_id,
            )
        except pyjwt.PyJWTError as exc:
            raise PaariHTTPException(status_code=401, code=PaariErrorCode.PROOF_REPLAYED, detail="Paari request proof invalid or replayed") from exc
    return agent, claims


def _parent_for(db: Session, agent: models.Agent) -> models.ParentAuthority | None:
    return db.query(models.ParentAuthority).filter_by(id=agent.parent_pk).first()


def _provider_for(db: Session, org_id: str):
    # Default org retains the Phase 5 test seam (tests can monkeypatch
    # payments.get_provider); tenant orgs always use strict per-org routing.
    if org_id == "default":
        return get_provider()
    return get_provider_for_org(db, org_id)


def _mint_bounded_authorization(db: Session, intent: models.PaymentIntent) -> models.BoundedAuthorization:
    authorization_id = intent.intent_id
    token, expires_at = security.issue_bounded_authorization_jwt(
        authorization_id=authorization_id,
        agent_id=intent.agent_id,
        intent_id=intent.intent_id,
        transaction_id=intent.transaction_id,
        merchant=intent.merchant,
        amount_minor_units=intent.amount_minor_units,
        currency=intent.currency,
        mandate_id=intent.mandate_id,
    )
    auth = models.BoundedAuthorization(
        authorization_id=authorization_id,
        intent_id=intent.intent_id,
        mandate_id=intent.mandate_id,
        agent_id=intent.agent_id,
        org_id=intent.org_id,
        transaction_id=intent.transaction_id,
        merchant=intent.merchant,
        amount_minor_units=intent.amount_minor_units,
        currency=intent.currency,
        token=token,
        expires_at=expires_at,
        max_usage=1,
        usage_count=0,
    )
    db.add(auth)
    db.flush()
    return auth


def _record_provider_txn(db: Session, auth: models.BoundedAuthorization, state: str = "AUTHORIZED") -> models.ProviderTransaction:
    txn = models.ProviderTransaction(
        authorization_id=auth.authorization_id,
        intent_id=auth.intent_id,
        agent_id=auth.agent_id,
        org_id=auth.org_id,
        state=state,
    )
    db.add(txn)
    db.flush()
    return txn


def _authorization_view(auth: models.BoundedAuthorization) -> dict:
    return {
        "authorization_id": auth.authorization_id,
        "token": auth.token,
        "expires_at": auth.expires_at.isoformat(),
        "max_usage": auth.max_usage,
        "amount_minor_units": auth.amount_minor_units,
        "currency": auth.currency,
        "merchant": auth.merchant,
        "transaction_id": auth.transaction_id,
        "mandate_id": auth.mandate_id,
    }


def _llm_causal(req) -> dict:
    """The LLM trace labels, or all-None when the client asserted none."""
    return {
        "llm_run_id": getattr(req, "llm_run_id", None),
        "llm_model": getattr(req, "llm_model", None),
        "llm_tool_call_id": getattr(req, "llm_tool_call_id", None),
        "llm_tool_name": getattr(req, "llm_tool_name", None),
    }


def _llm_attributed(req) -> bool:
    """True only when the caller actually claimed an LLM origin.

    The `llm_tool_call` audit event used to be written for EVERY payment,
    including plain protocol clients that sent no causal ids at all - so the
    chain asserted a model tool invocation that never happened and an auditor
    could not tell a real model call from a synthetic marker.
    """
    return any(getattr(req, f, None) for f in
               ("llm_run_id", "llm_model", "llm_tool_call_id", "llm_tool_name"))


def _record_intent(db: Session, agent: models.Agent, req: schemas.PaymentIntentRequest,
                   decision: models.GovernanceDecision, reasons: list[str], mfa_required: bool,
                   mfa_verified: bool, review_expires_at=None, now: datetime | None = None,
                   policy_results: Sequence[governance.PolicyResult] | None = None) -> models.PaymentIntent:
    llm_causal = _llm_causal(req)
    llm_attributed = _llm_attributed(req)
    intent = models.PaymentIntent(
        agent_id=agent.agent_id,
        org_id=agent.org_id,
        transaction_id=req.transaction_id,
        idempotency_key=req.idempotency_key,
        merchant=req.merchant,
        amount_minor_units=req.amount_minor_units,
        currency=req.currency,
        action=req.action,
        purpose=req.purpose,
        merchant_category=req.merchant_category,
        mandate_id=getattr(req, "mandate_id", None),
        decision=decision,
        reasons=reasons,
        mfa_required=mfa_required,
        mfa_verified=mfa_verified,
        review_expires_at=review_expires_at,
        llm_attributed=llm_attributed,
        created_at=now or _now(),
        **{k: v for k, v in llm_causal.items()},
    )
    db.add(intent)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        existing = db.query(models.PaymentIntent).filter_by(agent_id=agent.agent_id, idempotency_key=req.idempotency_key).first()
        if existing:
            return existing
        raise
    from app.audit import record_audit
    parent = _parent_for(db, agent)
    # Provenance marker is written ONLY when the caller claimed an LLM origin.
    # A plain protocol client now gets a `payment_proposed` event instead, so
    # the chain never asserts a model tool invocation that did not happen.
    if llm_attributed:
        record_audit(
            db,
            transaction_id=req.transaction_id,
            agent_id=agent.agent_id,
            parent_id=parent.parent_id if parent else None,
            kind="llm_tool_call",
            detail={**llm_causal,
                    "intent_id": intent.intent_id,
                    "action": req.action, "mandate_id": getattr(req, "mandate_id", None)},
            org_id=agent.org_id,
        )
    else:
        record_audit(
            db,
            transaction_id=req.transaction_id,
            agent_id=agent.agent_id,
            parent_id=parent.parent_id if parent else None,
            kind="payment_proposed",
            detail={"intent_id": intent.intent_id, "action": req.action,
                    "mandate_id": getattr(req, "mandate_id", None),
                    "llm_attributed": False},
            org_id=agent.org_id,
        )
    record_audit(
        db,
        transaction_id=req.transaction_id,
        agent_id=agent.agent_id,
        parent_id=parent.parent_id if parent else None,
        kind="intent_decided",
        detail={"intent_id": intent.intent_id, "decision": decision.value,
                "reasons": reasons,
                "policy_results": [p.__dict__ for p in (policy_results or [])],
                "amount_minor_units": req.amount_minor_units,
                "currency": req.currency, "merchant": req.merchant, "merchant_category": req.merchant_category,
                "action": req.action, "mandate_id": getattr(req, "mandate_id", None),
                **llm_causal},
        org_id=agent.org_id,
    )
    db.commit()
    db.refresh(intent)
    return intent


@router.post("/intent", response_model=schemas.PaymentIntentResponse)
def submit_payment_intent(req: schemas.PaymentIntentRequest,
                           request: Request,
                           x_paari_proof: str = Header(default=""),
                           authorization: str = Header(default=""),
                           db: Session = Depends(get_db)):
    token = _resolve_session_token(req.session_token, authorization)
    agent, claims = _authenticate(db, token, request=request, proof=x_paari_proof)
    if req.agent_id and req.agent_id != agent.agent_id:
        raise HTTPException(status_code=403, detail="agent_id does not match authenticated session")
    now = _now()
    # The mandate binding is server-derived only. Never honor a mandate_id
    # selected by the LLM/client. The active mandate is resolved below.
    req.mandate_id = None
    # Sprint 7: LLM causal identifiers are untrusted labels. Normalize length
    # and whitespace; they are stored for traceability only and never
    # influence any authorization decision.
    for _f in ("llm_run_id", "llm_model", "llm_tool_call_id", "llm_tool_name"):
        _v = getattr(req, _f, None)
        if isinstance(_v, str):
            setattr(req, _f, _v.strip()[:120] or None)

    existing = db.query(models.PaymentIntent).filter_by(
        agent_id=agent.agent_id, idempotency_key=req.idempotency_key).first()
    if existing:
        auth = db.query(models.BoundedAuthorization).filter_by(intent_id=existing.intent_id).first()
        return schemas.PaymentIntentResponse(
            intent_id=existing.intent_id,
            transaction_id=existing.transaction_id,
            decision=existing.decision.value,
            reasons=list(existing.reasons or []) + ["idempotent replay: returning original decision"],
            mfa_required=existing.mfa_required,
            authorization=_authorization_view(auth) if auth else None,
            review_expires_at=existing.review_expires_at,
            mandate_id=existing.mandate_id,
        )

    parent = _parent_for(db, agent)
    if not parent or parent.status != models.ParentStatus.ACTIVE:
        return _deny(db, agent, req, ["parent authority revoked, unverified, or missing"], [governance.PolicyResult(name="parent_check", passed=False, detail="parent authority is not active")])
    trust_result = get_trust_provider().verify(db, parent)
    if not trust_result.approved:
        return _deny(db, agent, req, [trust_result.reason], [governance.PolicyResult(name="trust_check", passed=False, detail=trust_result.reason)])
    if agent.valid_until and agent.valid_until < now:
        return _deny(db, agent, req, ["agent's delegation has expired"], [governance.PolicyResult(name="delegation_expiry", passed=False, detail="agent's delegation has expired")])
    if req.amount_minor_units <= 0:
        return _deny(db, agent, req, ["amount must be positive"], [governance.PolicyResult(name="amount_check", passed=False, detail="amount must be positive")])
    if req.action not in agent.granted_capabilities and req.action not in {"payment.create"}:
        return _deny(db, agent, req, [f"agent not delegated capability '{req.action}'"], [governance.PolicyResult(name="capability_check", passed=False, detail=f"agent not delegated capability '{req.action}'")])
    if req.amount_minor_units > agent.payment_limit_minor_units:
        return _deny(db, agent, req, [f"amount {req.amount_minor_units} exceeds delegated limit {agent.payment_limit_minor_units}"], [governance.PolicyResult(name="limit_check", passed=False, detail=f"amount {req.amount_minor_units} exceeds delegated limit {agent.payment_limit_minor_units}")])
    if req.currency != agent.currency:
        return _deny(db, agent, req, [f"currency {req.currency} does not match delegated currency {agent.currency}"], [governance.PolicyResult(name="currency_check", passed=False, detail=f"currency {req.currency} does not match delegated currency {agent.currency}")])

    # Paari v2 user-mandate layer.
    #
    # Governance posture is resolved in ONE place (app.config.mandate_policy),
    # not re-derived from os.environ here. An unrecognised PAARI_MODE raises
    # instead of silently degrading to `standard` (mandate optional).
    #
    #   standard   - legacy v1 behaviour: enforce an active mandate when one
    #                exists; absence alone does not block a payment.
    #   autonomous - a user mandate is REQUIRED. No active mandate -> DENY.
    #                (PAARI_REQUIRE_USER_MANDATE=1 remains a legacy alias.)
    #
    # LAPSED (a mandate existed but expired / was revoked) denies in BOTH
    # modes. Previously it resolved to "no mandate", so an expired spending
    # cap silently became no cap and the payment was ALLOWed with
    # "all checks passed" and mandate_id=null.
    policy = config.mandate_policy()
    mandate_decision = evaluate_mandate(
        db, agent=agent, merchant=req.merchant, amount_minor_units=req.amount_minor_units,
        currency=req.currency, merchant_category=req.merchant_category, now=now,
        require_signed=policy.require_signed_mandate,
    )
    mandate = mandate_decision.mandate
    if mandate_decision.state is mandates.MandateState.LAPSED:
        return _deny(
            db, agent, req, list(mandate_decision.reasons),
            [governance.PolicyResult(name="user_mandate_check", passed=False,
                                     detail="; ".join(mandate_decision.reasons))],
        )
    if policy.mandate_required and mandate_decision.state is mandates.MandateState.NONE:
        return _deny(
            db, agent, req, ["no active user payment mandate"],
            [governance.PolicyResult(name="user_mandate_check", passed=False,
                                     detail="no active user payment mandate")],
        )
    if mandate_decision.state is mandates.MandateState.ACTIVE and not mandate_decision.ok:
        return _deny(
            db, agent, req, list(mandate_decision.reasons),
            [governance.PolicyResult(name="user_mandate_check", passed=False,
                                     detail="; ".join(mandate_decision.reasons))],
        )
    if mandate is not None:
        req.mandate_id = mandate.mandate_id

    policy_results: list[governance.PolicyResult] = [
        governance.PolicyResult(name="parent_check", passed=True, detail="parent authority is active"),
        governance.PolicyResult(name="delegation_expiry", passed=True, detail="agent delegation is not expired"),
        governance.PolicyResult(name="amount_check", passed=True, detail="amount is positive"),
        governance.PolicyResult(name="capability_check", passed=True, detail=f"agent is delegated capability '{req.action}'"),
        governance.PolicyResult(name="limit_check", passed=True, detail=f"amount {req.amount_minor_units} is within delegated limit {agent.payment_limit_minor_units}"),
        governance.PolicyResult(name="currency_check", passed=True, detail=f"currency {req.currency} matches delegated currency {agent.currency}"),
    ]
    if mandate is not None:
        policy_results.append(governance.PolicyResult(
            name="user_mandate_check",
            passed=True,
            detail=f"mandate {mandate.mandate_id} permits this payment",
        ))
        if mandate_decision.review:
            policy_results.append(governance.PolicyResult(
                name="user_mandate_review",
                passed=False,
                detail="user mandate requires step-up/review for this amount",
            ))
    window_start = now - VELOCITY_WINDOW
    recent_count = db.query(models.PaymentIntent).filter(
        models.PaymentIntent.agent_id == agent.agent_id,
        models.PaymentIntent.created_at >= window_start,
    ).count()
    if recent_count >= VELOCITY_MAX_INTENTS:
        policy_results.append(governance.PolicyResult(name="velocity_check", passed=False, detail=f"velocity check: {recent_count} intents in the last minute - needs manual review"))

    mfa_required = req.amount_minor_units > STEP_UP_THRESHOLD_RATIO * agent.payment_limit_minor_units
    if mfa_required:
        policy_results.append(governance.PolicyResult(name="step_up_threshold", passed=False, detail="amount close to delegated limit - step-up approval required"))

    # The decision summary is derived from ONE structured result rather than
    # being re-derived inline. `governance.GovernanceResult` existed but was
    # never constructed (dead code), so the outcome was computed twice: once
    # as `reasons`/`mfa_required` here and again from `policy_results` a few
    # lines later. It is now the single place the verdict is assembled.
    failed = [r for r in policy_results if not r.passed]
    result = governance.GovernanceResult(
        decision=(models.GovernanceDecision.REVIEW
                  if (mfa_required or failed) else models.GovernanceDecision.ALLOW),
        reasons=[r.detail for r in failed] or ["all checks passed"],
        policy_results=tuple(policy_results),
        mfa_required=mfa_required,
    )
    reasons = result.reasons

    if result.decision is models.GovernanceDecision.REVIEW:
        expires = now + REVIEW_TTL if failed and not mfa_required else None
        intent = _record_intent(db, agent, req, result.decision, reasons, result.mfa_required, False, expires, now=now, policy_results=policy_results)
        return schemas.PaymentIntentResponse(
            intent_id=intent.intent_id, transaction_id=intent.transaction_id, decision="review", reasons=reasons,
            mfa_required=result.mfa_required, authorization=None, review_expires_at=expires,
            mandate_id=mandate.mandate_id if mandate else None,
        )

    intent = _record_intent(db, agent, req, result.decision, ["all checks passed"], False, False, now=now, policy_results=policy_results)
    auth = _mint_bounded_authorization(db, intent)
    _record_provider_txn(db, auth)
    from app.audit import record_audit
    parent_id = parent.parent_id if parent else None
    llm_causal = {"llm_run_id": intent.llm_run_id, "llm_model": intent.llm_model,
                  "llm_tool_call_id": intent.llm_tool_call_id, "llm_tool_name": intent.llm_tool_name}
    record_audit(db, transaction_id=req.transaction_id, agent_id=agent.agent_id, parent_id=parent_id,
                 kind="authorization_minted",
                 detail={"authorization_id": auth.authorization_id, "amount_minor_units": auth.amount_minor_units,
                         "currency": auth.currency, "merchant": auth.merchant, "expires_at": auth.expires_at.isoformat(),
                         "previous_state": "AUTHORIZED", "current_state": "AUTHORIZED", **llm_causal},
                 org_id=agent.org_id)
    db.commit()
    return schemas.PaymentIntentResponse(
        intent_id=intent.intent_id, transaction_id=intent.transaction_id, decision="allow", reasons=["all checks passed"],
        mfa_required=False, authorization=_authorization_view(auth), review_expires_at=None,
        mandate_id=mandate.mandate_id if mandate else None,
    )


def _deny(db: Session, agent: models.Agent, req: schemas.PaymentIntentRequest, reasons: list[str], policy_results: Sequence[governance.PolicyResult] | None = None):
    intent = _record_intent(db, agent, req, models.GovernanceDecision.DENY, reasons, False, False, policy_results=policy_results)
    return schemas.PaymentIntentResponse(intent_id=intent.intent_id, transaction_id=intent.transaction_id, decision="deny", reasons=reasons, mfa_required=False, authorization=None, mandate_id=intent.mandate_id)


@router.post("/mfa/challenge", response_model=schemas.MFAChallengeResponse)
def request_mfa_challenge(req: schemas.MFAChallengeRequest, request: Request,
                          x_paari_proof: str = Header(default=""),
                          authorization: str = Header(default=""), db: Session = Depends(get_db)):
    intent = db.query(models.PaymentIntent).filter_by(intent_id=req.intent_id).first()
    if not intent:
        raise HTTPException(status_code=404, detail="Payment intent not found")
    token = _resolve_session_token(req.session_token, authorization)
    _authenticate(db, token, expected_agent_id=intent.agent_id, request=request, proof=x_paari_proof)
    if intent.decision != models.GovernanceDecision.REVIEW or not intent.mfa_required:
        raise HTTPException(status_code=400, detail="This intent does not require step-up approval")
    db.query(models.MFAChallenge).filter_by(intent_id=intent.intent_id, used=False).update({"used": True})
    now = _now()
    challenge = models.MFAChallenge(intent_id=intent.intent_id, org_id=intent.org_id, expires_at=now + security.MFA_CHALLENGE_TTL)
    db.add(challenge)
    db.flush()
    context_to_sign = crypto_utils.canonical_json({
        "purpose": "paari_mfa_step_up", "challenge_id": challenge.challenge_id,
        "intent_id": intent.intent_id, "agent_id": intent.agent_id,
        "transaction_id": intent.transaction_id, "merchant": intent.merchant,
        "amount_minor_units": intent.amount_minor_units, "currency": intent.currency,
        "nonce": challenge.nonce,
    })
    db.commit(); db.refresh(challenge)
    return schemas.MFAChallengeResponse(challenge_id=challenge.challenge_id, intent_id=intent.intent_id,
                                        nonce=challenge.nonce, context_to_sign=context_to_sign,
                                        expires_at=challenge.expires_at)


@router.post("/mfa/verify", response_model=schemas.PaymentIntentResponse)
def verify_mfa_challenge(req: schemas.MFAVerifyRequest, db: Session = Depends(get_db)):
    intent = db.query(models.PaymentIntent).filter_by(intent_id=req.intent_id).first()
    if not intent or intent.decision != models.GovernanceDecision.REVIEW or not intent.mfa_required:
        raise HTTPException(status_code=400, detail="This intent is not awaiting step-up approval")
    challenge = db.query(models.MFAChallenge).filter_by(challenge_id=req.challenge_id, intent_id=intent.intent_id).first()
    now = _now()
    if not challenge or challenge.used or challenge.expires_at < now:
        raise HTTPException(status_code=401, detail="MFA challenge invalid, expired, or already used")
    agent = db.query(models.Agent).filter_by(agent_id=intent.agent_id).first()
    parent = _parent_for(db, agent) if agent else None
    if not agent or agent.status != models.AgentStatus.ACTIVE or not parent or parent.status != models.ParentStatus.ACTIVE:
        raise HTTPException(status_code=401, detail="Agent or parent authority is no longer active")
    context_to_sign = crypto_utils.canonical_json({
        "purpose": "paari_mfa_step_up", "challenge_id": challenge.challenge_id,
        "intent_id": intent.intent_id, "agent_id": intent.agent_id,
        "transaction_id": intent.transaction_id, "merchant": intent.merchant,
        "amount_minor_units": intent.amount_minor_units, "currency": intent.currency,
        "nonce": challenge.nonce,
    })
    if not crypto_utils.verify_signature(parent.public_key_pem, context_to_sign, req.parent_signature_b64):
        raise HTTPException(status_code=401, detail="Step-up signature verification failed")
    challenge.used = True
    intent.decision = models.GovernanceDecision.ALLOW
    intent.mfa_verified = True
    intent.reasons = list(intent.reasons or []) + ["step-up approval verified via parent-authority signature"]
    auth = _mint_bounded_authorization(db, intent)
    _record_provider_txn(db, auth)
    from app.audit import record_audit
    llm_causal = {"llm_run_id": intent.llm_run_id, "llm_model": intent.llm_model,
                  "llm_tool_call_id": intent.llm_tool_call_id, "llm_tool_name": intent.llm_tool_name}
    record_audit(db, transaction_id=intent.transaction_id, agent_id=agent.agent_id, parent_id=parent.parent_id,
                 kind="mfa_verified",
                 detail={"challenge_id": challenge.challenge_id, "intent_id": intent.intent_id, **llm_causal}, org_id=agent.org_id)
    record_audit(db, transaction_id=intent.transaction_id, agent_id=agent.agent_id, parent_id=parent.parent_id,
                 kind="authorization_minted",
                 detail={"authorization_id": auth.authorization_id, "amount_minor_units": auth.amount_minor_units,
                         "currency": auth.currency, "merchant": auth.merchant, "expires_at": auth.expires_at.isoformat(),
                         **llm_causal}, org_id=agent.org_id)
    db.commit()
    return schemas.PaymentIntentResponse(intent_id=intent.intent_id, transaction_id=intent.transaction_id, decision="allow", reasons=intent.reasons,
                                         mfa_required=True, authorization=_authorization_view(auth))


def _revalidate_execution(db: Session, auth: models.BoundedAuthorization) -> models.Agent:
    agent = db.query(models.Agent).filter_by(agent_id=auth.agent_id, org_id=auth.org_id).first()
    now = _now()
    if not agent or agent.status != models.AgentStatus.ACTIVE:
        raise HTTPException(status_code=403, detail="Agent is no longer active")
    parent = _parent_for(db, agent)
    if not parent or parent.status != models.ParentStatus.ACTIVE:
        raise HTTPException(status_code=403, detail="Parent authority is no longer active")
    if agent.valid_until and agent.valid_until < now:
        raise HTTPException(status_code=403, detail="Delegation expired")
    cred = db.query(models.Credential).filter_by(agent_pk=agent.id, revoked=False).order_by(models.Credential.issued_at.desc()).first()
    if not cred or cred.expires_at < now:
        raise HTTPException(status_code=403, detail="No current valid credential")
    if auth.expires_at < now:
        raise HTTPException(status_code=410, detail="Authorization has expired")
    if auth.mandate_id:
        mandate = db.query(models.UserPaymentMandate).filter_by(
            mandate_id=auth.mandate_id, agent_id=agent.agent_id, org_id=agent.org_id
        ).first()
        if not mandate or mandate.status != models.MandateStatus.ACTIVE:
            raise HTTPException(status_code=403, detail="User payment mandate is no longer active")
        if mandate.expires_at < now or mandate.valid_from > now:
            raise HTTPException(status_code=403, detail="User payment mandate is outside its validity window")
        # Re-verify the signature at EXECUTION time, not just at creation.
        # A signed mandate whose row was altered after minting must not be
        # spendable just because the authorization was already issued.
        sig_ok, sig_reasons = mandates.check_mandate_signature(
            mandate, require_signed=config.mandate_policy().require_signed_mandate)
        if not sig_ok:
            raise HTTPException(status_code=403, detail="; ".join(sig_reasons))
        if auth.amount_minor_units > mandate.max_per_transaction:
            raise HTTPException(status_code=403, detail="Authorization exceeds the current user mandate limit")
        if auth.currency.upper() != mandate.currency.upper():
            raise HTTPException(status_code=403, detail="Authorization currency no longer matches user mandate")
        # The merchant/category dimensions are re-checked here too: the
        # allowlists are part of the signed payload, so a mandate that was
        # re-scoped after minting must not be able to spend the authorization.
        allowed_merchants = [str(x).casefold() for x in (mandate.allowed_merchants or [])]
        if allowed_merchants and auth.merchant.casefold() not in allowed_merchants:
            raise HTTPException(status_code=403,
                                detail="Authorization merchant is no longer permitted by the user mandate")
        allowed_categories = [str(x).casefold() for x in (mandate.allowed_categories or [])]
        if allowed_categories:
            intent = db.query(models.PaymentIntent).filter_by(intent_id=auth.intent_id).first()
            category = (intent.merchant_category if intent else None)
            if not category or category.casefold() not in allowed_categories:
                raise HTTPException(status_code=403,
                                    detail="Authorization category is no longer permitted by the user mandate")
    return agent


def _provider_order_matches(auth: models.BoundedAuthorization, order: dict) -> bool:
    return (
        str(order.get("receipt", "")) == auth.authorization_id
        and int(order.get("amount", -1)) == auth.amount_minor_units
        and str(order.get("currency", "")).upper() == auth.currency.upper()
    )


def _active_provider_binding(db: Session, auth: models.BoundedAuthorization, now: datetime):
    if not auth.mandate_id:
        return None
    return db.query(models.PaymentInstrumentBinding).filter(
        models.PaymentInstrumentBinding.mandate_id == auth.mandate_id,
        models.PaymentInstrumentBinding.org_id == auth.org_id,
        models.PaymentInstrumentBinding.status == "active",
    ).filter(
        (models.PaymentInstrumentBinding.expires_at.is_(None))
        | (models.PaymentInstrumentBinding.expires_at > now)
    ).first()


def _consume_agentic_settlement(db: Session, *, auth: models.BoundedAuthorization,
                                agent: models.Agent, txn: models.ProviderTransaction,
                                parent: models.ParentAuthority | None,
                                agentic, llm_causal: dict) -> schemas.ConsumeAuthorizationResponse:
    """Execute only through a provider-native autonomous capability.

    In autonomous mode there is deliberately NO fallback to a normal checkout
    order. If the provider capability is unavailable, the authorization is
    already consumed and the transaction fails closed (or becomes UNKNOWN on a
    transport timeout). A regular Razorpay order is a human-checkout product and
    is therefore not an autonomous payment.
    """
    now = _now()
    from app.audit import record_audit
    binding = _active_provider_binding(db, auth, now)
    if not binding:
        try:
            transition_txn(txn, "FAILED")
        except IllegalTransitionError:
            pass
        txn.last_error = "Autonomous mode requires an active provider payment-instrument binding"
        db.commit()
        raise HTTPException(status_code=409, detail=txn.last_error)

    validation = agentic.validate_mandate(binding.provider_mandate_ref)
    if not validation.get("valid"):
        try:
            transition_txn(txn, "FAILED")
        except IllegalTransitionError:
            pass
        txn.last_error = f"Provider mandate is not valid: {validation.get('reason') or validation.get('status') or 'unknown'}"
        db.commit()
        raise HTTPException(status_code=409, detail="Provider mandate is not active for autonomous payment")

    auth_result = agentic.authorize_payment(
        authorization_id=auth.authorization_id,
        provider_mandate_ref=binding.provider_mandate_ref,
        amount_minor_units=auth.amount_minor_units,
        currency=auth.currency,
        merchant_reference=auth.merchant,
        idempotency_key=f"{auth.authorization_id}:agentic",
    )
    provider_payment_ref = auth_result.get("provider_payment_ref") or auth_result.get("id")
    if not provider_payment_ref:
        raise RuntimeError("Provider autonomous authorization returned no payment reference")

    # The provider has received the autonomous debit request; there is no
    # browser checkout or ordinary order object in this path.
    old_state = txn.state
    transition_txn(txn, "PROVIDER_SUBMITTED")
    txn.razorpay_payment_id = provider_payment_ref  # legacy column; proof bundle exposes provider_payment_id
    provenance = getattr(agentic, "provenance", None)
    if callable(provenance):
        for _k, _v in provenance().items():
            if hasattr(txn, _k):
                setattr(txn, _k, _v)
    elif txn.provider_environment in (None, "unknown"):
        txn.provider_environment = "unknown"
    txn.updated_at = now

    record_audit(db, transaction_id=auth.transaction_id, agent_id=agent.agent_id,
                 parent_id=parent.parent_id if parent else None,
                 kind="authorization_consumed",
                 detail={"authorization_id": auth.authorization_id,
                         "remaining_uses": 0,
                         "previous_state": old_state,
                         "current_state": "PROVIDER_SUBMITTED",
                         "settlement_mode": "provider-native-autonomous",
                         **llm_causal}, org_id=auth.org_id)
    record_audit(db, transaction_id=auth.transaction_id, agent_id=agent.agent_id,
                 parent_id=parent.parent_id if parent else None,
                 kind="provider_submitted",
                 detail={"authorization_id": auth.authorization_id,
                         "provider_payment_ref": provider_payment_ref,
                         "amount_minor_units": auth.amount_minor_units,
                         "currency": auth.currency,
                         "previous_state": old_state,
                         "current_state": "PROVIDER_SUBMITTED",
                         "settlement_source": "agentic",
                         **llm_causal}, org_id=auth.org_id)
    db.flush()

    try:
        capture_result = agentic.capture_payment(
            provider_payment_ref=provider_payment_ref,
            amount_minor_units=auth.amount_minor_units,
            currency=auth.currency,
            idempotency_key=f"{auth.authorization_id}:capture",
        )
    except Exception as exc:
        try:
            transition_txn(txn, "PROVIDER_UNKNOWN")
        except IllegalTransitionError:
            pass
        txn.last_error = f"Agentic capture outcome unknown: {exc}"[:2000]
        db.commit()
        return schemas.ConsumeAuthorizationResponse(
            authorization_id=auth.authorization_id, consumed=True, remaining_uses=0,
            state=txn.state, razorpay_order_id=None, razorpay_payment_id=provider_payment_ref,
        )

    capture_status = str(capture_result.get("status", "")).lower()
    if capture_status in {"captured", "already_captured"}:
        transition_txn(txn, "PROVIDER_AUTHORIZED")
        transition_txn(txn, "CAPTURED")
    elif capture_status in {"authorized", "pending", "processing", "created"}:
        transition_txn(txn, "PROVIDER_AUTHORIZED")
        txn.last_error = f"Provider capture pending: {capture_result.get('status')}"[:2000]
        db.commit()
        return schemas.ConsumeAuthorizationResponse(
            authorization_id=auth.authorization_id, consumed=True, remaining_uses=0,
            state=txn.state, razorpay_order_id=None, razorpay_payment_id=provider_payment_ref,
        )
    elif capture_status in {"failed", "declined", "cancelled", "canceled"}:
        transition_txn(txn, "FAILED" if capture_status == "failed" else "DECLINED")
        txn.last_error = f"Provider capture returned terminal failure: {capture_result.get('status')}"[:2000]
        db.commit()
        return schemas.ConsumeAuthorizationResponse(
            authorization_id=auth.authorization_id, consumed=True, remaining_uses=0,
            state=txn.state, razorpay_order_id=None, razorpay_payment_id=provider_payment_ref,
        )
    else:
        transition_txn(txn, "PROVIDER_UNKNOWN")
        txn.last_error = f"Provider capture outcome is unknown: {capture_result.get('status')!r}"[:2000]
        db.commit()
        return schemas.ConsumeAuthorizationResponse(
            authorization_id=auth.authorization_id, consumed=True, remaining_uses=0,
            state=txn.state, razorpay_order_id=None, razorpay_payment_id=provider_payment_ref,
        )

    payment_data = agentic.get_payment(provider_payment_ref)
    corroborated = (str(payment_data.get("status", "")).lower() == "captured"
                    and int(payment_data.get("amount", -1)) == auth.amount_minor_units
                    and str(payment_data.get("currency", "")).upper() == auth.currency.upper())
    if not corroborated:
        txn.last_error = "Provider readback did not corroborate captured amount/currency; reconciliation required"
        db.commit()
        return schemas.ConsumeAuthorizationResponse(
            authorization_id=auth.authorization_id, consumed=True, remaining_uses=0,
            state=txn.state, razorpay_order_id=None, razorpay_payment_id=provider_payment_ref,
        )

    transition_txn(txn, "PAID")
    txn.updated_at = _now()
    record_audit(db, transaction_id=auth.transaction_id, agent_id=agent.agent_id,
                 parent_id=parent.parent_id if parent else None,
                 kind="agentic_settlement",
                 detail={"authorization_id": auth.authorization_id,
                         "provider_payment_ref": provider_payment_ref,
                         "amount_minor_units": auth.amount_minor_units,
                         "currency": auth.currency,
                         "previous_state": "PROVIDER_SUBMITTED",
                         "current_state": "PAID",
                         "settlement_source": "provider-native-agentic",
                         **llm_causal}, org_id=auth.org_id)
    db.commit()
    return schemas.ConsumeAuthorizationResponse(
        authorization_id=auth.authorization_id, consumed=True, remaining_uses=0,
        state=txn.state, razorpay_order_id=None,
        razorpay_payment_id=provider_payment_ref,
    )


@router.post("/authorizations/{authorization_id}/consume", response_model=schemas.ConsumeAuthorizationResponse)
def consume_authorization(authorization_id: str, req: schemas.ConsumeAuthorizationRequest,
                          request: Request, x_paari_proof: str = Header(default=""),
                          authorization: str = Header(default=""), db: Session = Depends(get_db)):
    auth = db.query(models.BoundedAuthorization).filter_by(authorization_id=authorization_id).first()
    if not auth:
        raise HTTPException(status_code=404, detail="Authorization not found")
    token = _resolve_session_token(req.session_token, authorization)
    _authenticate(db, token, expected_agent_id=auth.agent_id, request=request, proof=x_paari_proof)
    agent = _revalidate_execution(db, auth)

    reserved = db.execute(
        update(models.BoundedAuthorization)
        .where(models.BoundedAuthorization.authorization_id == authorization_id,
               models.BoundedAuthorization.usage_count < models.BoundedAuthorization.max_usage)
        .values(usage_count=models.BoundedAuthorization.usage_count + 1)
    ).rowcount
    if reserved != 1:
        db.rollback()
        raise HTTPException(status_code=409, detail="Authorization already used or revoked")

    txn = db.query(models.ProviderTransaction).filter_by(authorization_id=authorization_id).first()
    if txn is None:
        txn = _record_provider_txn(db, auth)
    txn.attempts += 1
    txn.updated_at = _now()
    db.commit()

    from app.audit import record_audit, causal_labels
    from app.providers.agentic import get_agentic_provider, AgenticProviderUnavailable
    from app.config import mandate_policy, MandateMode
    parent = _parent_for(db, agent)
    llm_causal = causal_labels(db, auth.intent_id)

    try:
        agentic = get_agentic_provider(auth.org_id)
        policy = mandate_policy()

        # A configured provider-native adapter is always preferred when it is
        # capable: no ordinary order is created before the autonomous path.
        # In explicit autonomous mode there is NO fallback to human checkout.
        if agentic.supports_autonomous_settlement():
            try:
                return _consume_agentic_settlement(
                    db, auth=auth, agent=agent, txn=txn, parent=parent,
                    agentic=agentic, llm_causal=llm_causal,
                )
            except httpx.TimeoutException as exc:
                try:
                    transition_txn(txn, "PROVIDER_UNKNOWN")
                except IllegalTransitionError:
                    pass
                txn.last_error = f"Provider autonomous payment timeout: {exc}"[:2000]
                db.commit()
                return JSONResponse(status_code=502, content={
                    "authorization_id": authorization_id,
                    "consumed": True,
                    "remaining_uses": 0,
                    "state": "PROVIDER_UNKNOWN",
                    "detail": "Autonomous provider execution outcome is unknown; reconciliation required",
                })
            except HTTPException:
                raise
            except Exception as exc:
                try:
                    transition_txn(txn, "FAILED")
                except IllegalTransitionError:
                    pass
                txn.last_error = f"Autonomous provider execution failed: {exc}"[:2000]
                db.commit()
                raise HTTPException(status_code=502,
                                    detail="Autonomous provider execution failed; authorization remains spent and requires reconciliation") from exc

        if policy.mode is MandateMode.AUTONOMOUS:
            try:
                transition_txn(txn, "FAILED")
            except IllegalTransitionError:
                pass
            txn.last_error = (
                "Autonomous payment requested but no provider-native agentic "
                "settlement capability is configured for this organization"
            )
            db.commit()
            raise HTTPException(status_code=503, detail=txn.last_error)

        # Standard mode remains the human-checkout-compatible path only when
        # no provider-native autonomous capability is configured.
        provider = _provider_for(db, auth.org_id)
        order = provider.create_payment(
            authorization_id=authorization_id,
            amount_minor_units=auth.amount_minor_units,
            currency=auth.currency,
            notes={"paari_transaction_id": auth.transaction_id, "paari_agent_id": agent.agent_id},
        )
        if not _provider_order_matches(auth, order):
            transition_txn(txn, "FAILED")
            txn.last_error = "Provider order did not match authorization bounds"
            db.commit()
            raise HTTPException(status_code=502, detail="Provider order failed Paari authorization integrity checks")
        txn.razorpay_order_id = order.get("id")
        provenance = getattr(provider, "provenance", None)
        if callable(provenance):
            for _k, _v in provenance().items():
                setattr(txn, _k, _v)
        elif txn.provider_environment in (None, "unknown"):
            txn.provider_environment = "unknown"
        old_state = txn.state
        transition_txn(txn, "PROVIDER_SUBMITTED")
        txn.updated_at = _now()
        record_audit(db, transaction_id=auth.transaction_id, agent_id=agent.agent_id,
                     parent_id=parent.parent_id if parent else None,
                     kind="authorization_consumed",
                     detail={"authorization_id": authorization_id, "remaining_uses": 0,
                             "previous_state": old_state, "current_state": "PROVIDER_SUBMITTED",
                             **llm_causal}, org_id=auth.org_id)
        record_audit(db, transaction_id=auth.transaction_id, agent_id=agent.agent_id,
                     parent_id=parent.parent_id if parent else None,
                     kind="order_submitted",
                     detail={"authorization_id": authorization_id, "razorpay_order_id": order["id"],
                             "amount_minor_units": auth.amount_minor_units, "currency": auth.currency,
                             "previous_state": old_state, "current_state": "PROVIDER_SUBMITTED",
                             **llm_causal}, org_id=auth.org_id)
        db.commit()
        return schemas.ConsumeAuthorizationResponse(
            authorization_id=authorization_id, consumed=True, remaining_uses=0,
            state=txn.state, razorpay_order_id=txn.razorpay_order_id,
            razorpay_payment_id=txn.razorpay_payment_id,
        )
    except HTTPException:
        raise
    except httpx.TimeoutException as exc:
        try:
            transition_txn(txn, "PROVIDER_UNKNOWN")
        except IllegalTransitionError:
            pass
        txn.last_error = f"Provider timeout: {exc}"[:2000]
        txn.updated_at = _now()
        db.commit()
        return JSONResponse(status_code=502, content={"authorization_id": authorization_id, "consumed": True, "remaining_uses": 0, "state": "PROVIDER_UNKNOWN", "detail": "Provider execution outcome is unknown; reconciliation required"})
    except RazorpayConfigError as exc:
        try:
            transition_txn(txn, "FAILED")
        except IllegalTransitionError:
            pass
        txn.last_error = str(exc)[:2000]
        db.commit()
        raise HTTPException(status_code=502, detail="Payment provider is not configured for this organization") from exc
    except AgenticProviderUnavailable:
        try:
            transition_txn(txn, "FAILED")
        except IllegalTransitionError:
            pass
        txn.last_error = "Agentic provider configuration is unavailable"
        db.commit()
        raise HTTPException(status_code=503, detail=txn.last_error)
    except Exception as exc:
        try:
            transition_txn(txn, "FAILED")
        except IllegalTransitionError:
            pass
        txn.last_error = str(exc)[:2000]
        txn.updated_at = _now()
        db.commit()
        raise HTTPException(status_code=502, detail="Provider execution failed; authorization remains spent") from exc


@router.post("/webhooks/razorpay")
def razorpay_webhook(request: Request, x_razorpay_signature: str = Header(default=""), db: Session = Depends(get_db)):
    import hashlib
    raw = request.scope.get("_body")
    # FastAPI does not expose a cached raw-body field by default. Read it now.
    if raw is None:
        import asyncio
        # sync route: Request.body() is async, so use a conservative direct call
        # through the request's receive channel.
        async def _read(): return await request.body()
        raw = asyncio.run(_read()) if not hasattr(request, "_body") else request._body
    if not raw:
        raise HTTPException(status_code=400, detail="Empty webhook body")

    try:
        event = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid webhook JSON") from exc

    order_id = (((event.get("payload") or {}).get("payment") or {}).get("entity") or {}).get("order_id")
    txn = db.query(models.ProviderTransaction).filter_by(razorpay_order_id=order_id).first() if order_id else None
    try:
        provider = _provider_for(db, txn.org_id if txn else "default")
    except RazorpayConfigError as exc:
        raise HTTPException(status_code=500, detail="Webhook secret is not configured") from exc
    if not provider.verify_webhook(raw, x_razorpay_signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    event_type = str(event.get("event") or "")
    payment = (((event.get("payload") or {}).get("payment") or {}).get("entity") or {})
    order_id = payment.get("order_id") or order_id
    if not order_id:
        return {"status": "ignored"}
    txn = db.query(models.ProviderTransaction).filter_by(razorpay_order_id=order_id).first()
    if not txn:
        return {"status": "ignored", "reason": "unknown order"}
    auth = db.query(models.BoundedAuthorization).filter_by(authorization_id=txn.authorization_id).first()
    if not auth:
        return {"status": "ignored", "reason": "unknown authorization"}

    actual_account_id = (
        (((event.get("payload") or {}).get("account") or {}).get("id"))
        or event.get("account_id")
    )
    # Razorpay signs events with the webhook secret and nests the merchant
    # account as `acc_*`, which lives in a different namespace than the API
    # `rzp_*` key_id. Only enforce the org guard when the event actually
    # carries a key_id; an `acc_*` account id is not comparable to a key_id
    # (signature + amount/currency checks below still settle safely).
    if actual_account_id and actual_account_id.startswith("rzp_"):
        try:
            expected_provider = _provider_for(db, txn.org_id)
        except RazorpayConfigError:
            expected_provider = None
        if expected_provider is not None:
            expected_key_id = getattr(expected_provider, "key_id", "") or ""
            if expected_key_id and actual_account_id != expected_key_id:
                from app.audit import record_audit
                record_audit(
                    db,
                    transaction_id=auth.transaction_id,
                    agent_id=auth.agent_id,
                    parent_id=None,
                    kind="webhook_rejected_org_mismatch",
                    detail={
                        "from_state": txn.state,
                        "to_state": txn.state,
                        "expected_key_id": expected_key_id,
                        "actual_account_id": actual_account_id,
                        "order_id": order_id,
                        "payment_id": payment.get("id"),
                        "event_type": event_type,
                    },
                    org_id=txn.org_id,
                )
                db.commit()
                raise PaariHTTPException(
                    status_code=403,
                    code=PaariErrorCode.WEBHOOK_ORG_MISMATCH,
                    detail="Webhook event org does not match authorization owner",
                )

    event_id = event.get("id") or hashlib.sha256(raw).hexdigest()
    if txn.webhook_event_id == event_id or db.query(models.ProviderTransaction).filter_by(webhook_event_id=event_id).first():
        return {"status": "duplicate_ignored"}

    if event_type in {"payment.authorized", "payment.captured", "payment.failed"}:
        # Provider value is authenticated but still must match the exact
        # Paari authorization. Never let a validly signed provider event
        # settle a different amount/currency.
        provider_amount = payment.get("amount")
        provider_currency = payment.get("currency")
        value_mismatch = (
            provider_amount is None
            or provider_currency is None
            or int(provider_amount) != auth.amount_minor_units
            or str(provider_currency).upper() != auth.currency.upper()
        )
        if value_mismatch:
            from app.audit import record_audit
            record_audit(db, transaction_id=auth.transaction_id, agent_id=auth.agent_id, parent_id=None,
                         kind="webhook_rejected_value_mismatch",
                         detail={"event_type": event_type, "order_id": order_id,
                                 "provider_amount": provider_amount, "provider_currency": provider_currency,
                                 "authorized_amount": auth.amount_minor_units, "authorized_currency": auth.currency},
                         org_id=auth.org_id)
            db.commit()
            return {"status": "rejected_value_mismatch"}

        # Phase 9: a webhook announces an event; it does not confirm settlement.
        # `payment.captured` therefore lands in CAPTURED and PAID is reached only
        # after confirm_capture() corroborates it with a direct provider read.
        # This mapping has no PAID entry on purpose - if one is ever added, the
        # webhook handler can mint a terminal settlement on a single inbound
        # message again, and tests/test_phase9_state_machine.py will fail first.
        target = {
            "payment.authorized": "PROVIDER_AUTHORIZED",
            "payment.captured": "CAPTURED",
            "payment.failed": "FAILED",
        }[event_type]
        try:
            old_state = txn.state
            transition_txn(txn, target)
        except IllegalTransitionError:
            # Terminal/illegal repeats are acknowledged but never mutate money state.
            return {"status": "ignored", "reason": f"illegal transition {txn.state}->{target}"}
        txn.webhook_event_id = event_id
        if event_type == "payment.captured":
            txn.razorpay_payment_id = payment.get("id")
        txn.updated_at = _now()
        from app.audit import record_audit, causal_labels
        agent = db.query(models.Agent).filter_by(agent_id=txn.agent_id).first()
        parent = _parent_for(db, agent) if agent else None
        record_audit(db, transaction_id=auth.transaction_id, agent_id=txn.agent_id,
                     parent_id=parent.parent_id if parent else None,
                     kind="webhook_applied",
                     # Causal continuity past the provider boundary: without
                     # these, the chain reads as an LLM-attributed payment right
                     # up to order_submitted and then goes anonymous exactly at
                     # the settlement step - which is where an auditor looks.
                     detail={"event_type": event_type, "event_id": event_id, "from_state": old_state, "to_state": txn.state,
                             "order_id": order_id, "payment_id": payment.get("id"),
                             "amount_minor_units": auth.amount_minor_units, "currency": auth.currency,
                             "provider_environment": txn.provider_environment,
                             **causal_labels(db, txn.intent_id)}, org_id=txn.org_id)
        db.commit()
        applied_state = txn.state
        if target == "CAPTURED":
            # Corroborate before calling it settled. Failure here is not an
            # error: CAPTURED is non-terminal precisely so the reconciliation
            # worker promotes the row on its next pass.
            from app.reconcile import confirm_capture
            applied_state = confirm_capture(db, provider, txn, txn.authorization_id)
        return {"status": "applied", "state": applied_state}

    return {"status": "ignored", "reason": "unsupported event"}


@router.post("/authorizations/{authorization_id}/refund")
def refund_authorization(authorization_id: str, req: schemas.RefundRequest,
                         request: Request, x_paari_proof: str = Header(default=""),
                         authorization: str = Header(default=""), db: Session = Depends(get_db)):
    txn = db.query(models.ProviderTransaction).filter_by(authorization_id=authorization_id).first()
    if not txn:
        raise HTTPException(status_code=404, detail="Authorization not found")
    token = _resolve_session_token(req.session_token, authorization)
    _authenticate(db, token, expected_agent_id=txn.agent_id, request=request, proof=x_paari_proof)
    if txn.state != "PAID":
        raise HTTPException(status_code=409, detail=f"Cannot refund a payment in state {txn.state}")
    if not txn.razorpay_payment_id:
        raise HTTPException(status_code=409, detail="No provider payment id recorded for this transaction")

    auth = db.query(models.BoundedAuthorization).filter_by(authorization_id=authorization_id).first()
    amount = req.amount_minor_units if req.amount_minor_units is not None else (auth.amount_minor_units if auth else 0)
    if amount <= 0:
        raise HTTPException(status_code=400, detail="Refund amount must be positive")

    provider = _provider_for(db, txn.org_id)
    try:
        result = provider.refund(txn.razorpay_payment_id, amount)
    except Exception as exc:
        txn.last_error = str(exc)[:2000]
        db.commit()
        raise HTTPException(status_code=502, detail=f"Provider refund failed: {exc}") from exc

    try:
        old_state = txn.state
        transition_txn(txn, "REFUNDED")
    except IllegalTransitionError:
        raise HTTPException(status_code=409, detail=f"Cannot transition from {txn.state} to REFUNDED")

    txn.updated_at = _now()
    from app.audit import record_audit, causal_labels
    agent = db.query(models.Agent).filter_by(agent_id=txn.agent_id).first()
    parent = _parent_for(db, agent) if agent else None
    record_audit(db, transaction_id=auth.transaction_id if auth else txn.authorization_id,
                 agent_id=txn.agent_id, parent_id=parent.parent_id if parent else None,
                 kind="refund_issued",
                 detail={"authorization_id": authorization_id, "payment_id": txn.razorpay_payment_id,
                         "amount_minor_units": amount, "from_state": old_state, "to_state": "REFUNDED",
                         "provider_environment": txn.provider_environment,
                         **causal_labels(db, txn.intent_id)},
                 org_id=txn.org_id)
    db.commit()
    return {"status": "refunded", "state": txn.state, "provider_refund_id": result.get("id")}
