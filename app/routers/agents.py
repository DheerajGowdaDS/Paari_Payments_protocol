import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, schemas, security, crypto_utils
from app.protocol.errors import PaariHTTPException, PaariErrorCode
from app.trust import get_trust_provider

router = APIRouter(prefix="/agents", tags=["agents"])

# How much clock skew we tolerate on a parent-signed revocation's issued_at
# before treating it as stale. Combined with the one-time revocation_id
# check below, this bounds how long a captured-but-not-yet-used signed
# revocation stays valid, without needing a shared clock.
REVOCATION_MAX_AGE_SECONDS = 5 * 60


def _build_agent_card(agent: models.Agent, parent: models.ParentAuthority | None, credential_id: str) -> schemas.AgentCard:
    """
    Builds the Agent Card AND signs it with Paari's own key (P1 fix - the
    card used to be an unsigned response object). The signature covers
    every field a relying party would actually check, so the card remains
    verifiable if it's cached or relayed downstream rather than read
    straight off this response.
    """
    fields = {
        "agent_id": agent.agent_id,
        "name": agent.name,
        "agent_type": agent.agent_type,
        "parent_id": parent.parent_id if parent else "",
        "parent_name": parent.name if parent else "",
        "identity_status": agent.status.value,
        "public_key_reference": agent.public_key_pem,
        "granted_capabilities": agent.granted_capabilities,
        "payment_limit_minor_units": agent.payment_limit_minor_units,
        "currency": agent.currency,
        "valid_until": agent.valid_until.isoformat() if agent.valid_until else None,
        "credential_id": credential_id,
        "paari_endpoint": "/agents",
    }
    signature = security.sign_agent_card(fields)
    return schemas.AgentCard(
        **fields,
        card_signature_b64=signature,
        paari_public_key_pem=security.paari_public_key_pem(),
    )


@router.post("/register", response_model=schemas.AgentRegistrationResponse)
def register_agent(req: schemas.AgentRegistrationRequest, db: Session = Depends(get_db)):
    delegation = req.delegation

    # --- 1. Parent must exist and be an active (verified) trust root ---
    parent = db.query(models.ParentAuthority).filter_by(parent_id=delegation.parent_id).first()
    if not parent or parent.status != models.ParentStatus.ACTIVE:
        raise PaariHTTPException(status_code=401, code=PaariErrorCode.PARENT_REVOKED, detail="Unknown, unverified, or revoked parent authority")
    trust_result = get_trust_provider().verify(db, parent)
    if not trust_result.approved:
        raise PaariHTTPException(status_code=401, code=PaariErrorCode.PARENT_REVOKED, detail=trust_result.reason)

    # --- 2. Delegation must be genuinely signed by that parent's key ---
    # Both sides must serialize the document identically before signing/verifying.
    delegation_json = crypto_utils.canonical_json(delegation.model_dump(mode="json"))
    if not crypto_utils.verify_signature(parent.public_key_pem, delegation_json, req.delegation_signature_b64):
        raise HTTPException(status_code=401, detail="Delegation signature verification failed")

    # --- 3. Delegation must not be expired ---
    now = datetime.now(timezone.utc)
    delegation_expires_at = datetime.fromtimestamp(delegation.expires_at, tz=timezone.utc)
    if delegation_expires_at < now:
        raise HTTPException(status_code=401, detail="Delegation has expired")

    # --- 4. Delegation must be bound to THIS agent's specific public key ---
    fingerprint = crypto_utils.public_key_fingerprint(req.public_key_pem)
    if delegation.agent_public_key_fingerprint != fingerprint:
        raise HTTPException(status_code=401, detail="Delegation is not bound to this agent's public key")

    # --- 5. Delegation must not have been used before (anti-replay for delegations) ---
    existing = db.query(models.DelegationRecord).filter_by(delegation_id=delegation.delegation_id).first()
    if existing is not None:
        raise HTTPException(status_code=409, detail="Delegation has already been consumed")

    db.add(models.DelegationRecord(
        delegation_id=delegation.delegation_id,
        parent_pk=parent.id,
        agent_public_key_fingerprint=fingerprint,
        granted_capabilities=delegation.granted_capabilities,
        payment_limit_minor_units=delegation.payment_limit_minor_units,
        currency=delegation.currency,
        issued_at=datetime.fromtimestamp(delegation.issued_at, tz=timezone.utc),
        expires_at=delegation_expires_at,
        consumed=True,
        consumed_at=now,
    ))

    # --- Everything checked out: bind the agent, with capabilities/limits
    #     coming ONLY from the verified delegation, never from self-request.
    #     The agent inherits its parent's org (tenancy is assigned, never
    #     self-declared) ---
    agent = models.Agent(
        name=req.name,
        agent_type=req.agent_type,
        purpose=req.purpose,
        parent_pk=parent.id,
        org_id=parent.org_id,
        delegation_id=delegation.delegation_id,
        public_key_pem=req.public_key_pem,
        granted_capabilities=delegation.granted_capabilities,
        payment_limit_minor_units=delegation.payment_limit_minor_units,
        currency=delegation.currency,
        status=models.AgentStatus.ACTIVE,
        valid_until=delegation_expires_at,
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)

    jwt_token, credential_id, expires_at = security.issue_credential_jwt(
        agent_id=agent.agent_id,
        capabilities=agent.granted_capabilities,
        payment_limit=agent.payment_limit_minor_units,
        currency=agent.currency,
    )
    # Credential should never outlive the delegation that authorized it.
    credential_expires_at = min(expires_at, delegation_expires_at)

    credential = models.Credential(
        credential_id=credential_id,
        agent_pk=agent.id,
        signed_jwt=jwt_token,
        expires_at=credential_expires_at,
    )
    db.add(credential)
    db.commit()

    from app.audit import record_audit
    record_audit(db, transaction_id=f"delegation:{delegation.delegation_id}",
                 agent_id=agent.agent_id, parent_id=parent.parent_id,
                 kind="delegation_consumed",
                 detail={"delegation_id": delegation.delegation_id})
    record_audit(db, transaction_id=f"delegation:{delegation.delegation_id}",
                 agent_id=agent.agent_id, parent_id=parent.parent_id,
                 kind="credential_issued", detail={"credential_id": credential_id})
    db.commit()

    card = _build_agent_card(agent, parent, credential.credential_id)
    return schemas.AgentRegistrationResponse(
        agent_card=card,
        credential_jwt=jwt_token,
        credential_expires_at=credential_expires_at,
    )


@router.get("/{agent_id}/card", response_model=schemas.AgentCard)
def get_agent_card(agent_id: str, db: Session = Depends(get_db)):
    agent = db.query(models.Agent).filter_by(agent_id=agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    parent = db.query(models.ParentAuthority).filter_by(id=agent.parent_pk).first()

    active_credential = (
        db.query(models.Credential)
        .filter_by(agent_pk=agent.id, revoked=False)
        .order_by(models.Credential.issued_at.desc())
        .first()
    )

    return _build_agent_card(agent, parent, active_credential.credential_id if active_credential else "")


@router.post("/{agent_id}/revoke", response_model=schemas.RevokeResponse)
def revoke_agent(
    agent_id: str,
    req: schemas.AgentRevokeRequest = schemas.AgentRevokeRequest(),
    db: Session = Depends(get_db),
    x_admin_api_key: str = Header(default=""),
):
    """
    P0 fix: this endpoint used to have no authorization at all - anyone
    who knew an agent_id could revoke it. It now accepts exactly two
    authorities:

      1. Admin: a valid X-Admin-Api-Key header.
      2. The agent's own parent authority: a signed revocation document
         (`{action: "revoke_agent", agent_id, parent_id, revocation_id,
         issued_at}`, canonical_json'd and signed with the parent's
         private key), so a parent can revoke its own agent without
         needing the platform admin key. The revocation_id is checked
         against RevocationRecord for one-time use, and issued_at must be
         within REVOCATION_MAX_AGE_SECONDS of now.
    """
    agent = db.query(models.Agent).filter_by(agent_id=agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    is_admin = security.is_admin_key(x_admin_api_key)

    if not is_admin:
        if not (req.revocation_id and req.issued_at and req.parent_signature_b64):
            raise HTTPException(
                status_code=401,
                detail="Revocation requires admin credentials or a parent-signed revocation document",
            )

        parent = db.query(models.ParentAuthority).filter_by(id=agent.parent_pk).first()
        if not parent:
            raise HTTPException(status_code=401, detail="Parent authority not found for this agent")

        now_ts = int(time.time())
        if abs(now_ts - req.issued_at) > REVOCATION_MAX_AGE_SECONDS:
            raise HTTPException(status_code=401, detail="Revocation signature has expired - request a fresh one")

        already_used = db.query(models.RevocationRecord).filter_by(revocation_id=req.revocation_id).first()
        if already_used is not None:
            raise HTTPException(status_code=409, detail="Revocation document has already been used")

        payload = crypto_utils.canonical_json({
            "action": "revoke_agent",
            "agent_id": agent.agent_id,
            "parent_id": parent.parent_id,
            "revocation_id": req.revocation_id,
            "issued_at": req.issued_at,
        })
        if not crypto_utils.verify_signature(parent.public_key_pem, payload, req.parent_signature_b64):
            raise HTTPException(status_code=401, detail="Revocation signature verification failed")

        db.add(models.RevocationRecord(revocation_id=req.revocation_id, agent_id=agent.agent_id))

    agent.status = models.AgentStatus.REVOKED
    db.query(models.Credential).filter_by(agent_pk=agent.id).update({"revoked": True})
    db.commit()

    return schemas.RevokeResponse(agent_id=agent.agent_id, status=agent.status.value)
