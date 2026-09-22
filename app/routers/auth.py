"""
Phase 2 - Agent Authentication.

Flow implemented here:

  1. POST /auth/challenge  {agent_id}
       -> Paari generates a single-use, short-lived nonce.

  2. Agent signs the raw nonce string with its Ed25519 PRIVATE key
     (never sent to Paari) and calls:

  3. POST /auth/verify  {agent_id, nonce, signature_b64, credential_jwt}
       -> Paari checks, in order:
          a. Agent exists and is ACTIVE (not revoked)
          b. Credential JWT is valid, unexpired, issued by Paari, and
             not marked revoked in the DB
          c. Nonce exists, belongs to this agent, is unexpired and unused
          d. Signature over the nonce verifies against the agent's
             registered public key (proof-of-possession)
       -> On success: nonce is marked used (anti-replay) and a short-lived
          session token is issued. This session token - not the long-lived
          credential - is what the Phase 3 governance engine should require
          on every payment request.
"""
import jwt as pyjwt
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, schemas, security, crypto_utils

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/challenge", response_model=schemas.ChallengeResponse)
def create_challenge(req: schemas.ChallengeRequest, db: Session = Depends(get_db)):
    agent = db.query(models.Agent).filter_by(agent_id=req.agent_id).first()
    if not agent or agent.status != models.AgentStatus.ACTIVE:
        # Deliberately vague error - don't reveal whether the agent_id exists
        raise HTTPException(status_code=401, detail="Agent not eligible to authenticate")

    now = datetime.now(timezone.utc)
    nonce = models.AuthNonce(
        agent_id=agent.agent_id,
        expires_at=now + security.CHALLENGE_NONCE_TTL,
    )
    db.add(nonce)
    db.commit()
    db.refresh(nonce)

    return schemas.ChallengeResponse(nonce=nonce.nonce, expires_at=nonce.expires_at)


@router.post("/verify", response_model=schemas.VerifyResponse)
def verify_challenge(req: schemas.VerifyRequest, db: Session = Depends(get_db)):
    agent = db.query(models.Agent).filter_by(agent_id=req.agent_id).first()
    if not agent or agent.status != models.AgentStatus.ACTIVE:
        raise HTTPException(status_code=401, detail="Agent not eligible to authenticate")

    # --- credential check ---
    try:
        claims = security.decode_credential_jwt(req.credential_jwt)
    except pyjwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired credential")

    if claims["sub"] != agent.agent_id:
        raise HTTPException(status_code=401, detail="Credential does not match agent")

    credential = db.query(models.Credential).filter_by(credential_id=claims["jti"]).first()
    if not credential or credential.revoked:
        raise HTTPException(status_code=401, detail="Credential has been revoked")

    # P1 fix: the JWT's own `exp` was being checked (decode_credential_jwt
    # raises on that), but the DB row's expires_at - which can be tighter,
    # e.g. clamped to the delegation's expiry at issuance - was never
    # checked. A credential whose JWT still looked valid but whose
    # delegation had since expired was being accepted anyway.
    now_check = datetime.now(timezone.utc)
    if credential.expires_at < now_check:
        raise HTTPException(status_code=401, detail="Credential has expired")

    # --- nonce check (anti-replay) ---
    nonce = db.query(models.AuthNonce).filter_by(nonce=req.nonce, agent_id=req.agent_id).first()
    now = datetime.now(timezone.utc)
    if not nonce or nonce.used or nonce.expires_at < now:
        raise HTTPException(status_code=401, detail="Challenge invalid, expired, or already used")

    # --- proof-of-possession check ---
    # Current key always verifies. The previous key verifies only inside
    # the rotation grace window (key_sunset_at); afterwards it fails closed.
    key_ok = crypto_utils.verify_signature(agent.public_key_pem, req.nonce, req.signature_b64)
    authenticated_key_fingerprint = crypto_utils.public_key_fingerprint(agent.public_key_pem)
    if not key_ok and agent.old_public_key_pem and agent.key_sunset_at:
        if agent.key_sunset_at > datetime.now(timezone.utc):
            key_ok = crypto_utils.verify_signature(agent.old_public_key_pem, req.nonce, req.signature_b64)
            authenticated_key_fingerprint = crypto_utils.public_key_fingerprint(agent.old_public_key_pem)
    if not key_ok:
        raise HTTPException(status_code=401, detail="Signature verification failed")

    # Success: burn the nonce so it can never be replayed, then issue a session token.
    nonce.used = True
    db.commit()

    from app.audit import record_audit
    agent_parent = db.query(models.ParentAuthority).filter_by(id=agent.parent_pk).first()
    record_audit(db, transaction_id=f"auth:{req.nonce}", agent_id=agent.agent_id,
                 parent_id=agent_parent.parent_id if agent_parent else None,
                 kind="challenge_verified", detail={"credential_id": credential.credential_id})
    db.commit()

    session_token, expires_at = security.issue_session_token(
        agent_id=agent.agent_id,
        credential_id=credential.credential_id,
        capabilities=agent.granted_capabilities,
        payment_limit=agent.payment_limit_minor_units,
        key_fingerprint=authenticated_key_fingerprint,
        protocol_version=agent.protocol_version or "legacy",
    )

    return schemas.VerifyResponse(
        authenticated=True,
        session_token=session_token,
        expires_at=expires_at,
        granted_capabilities=agent.granted_capabilities,
        payment_limit_minor_units=agent.payment_limit_minor_units,
    )
