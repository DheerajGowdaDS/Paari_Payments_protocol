"""Parent authority lifecycle and trust-root controls."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, schemas, security
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

router = APIRouter(prefix="/parents", tags=["parents"])


@router.post("/register", response_model=schemas.ParentStatusResponse)
def register_parent(req: schemas.ParentRegistrationRequest, db: Session = Depends(get_db)):
    if req.parent_type not in {"company", "developer", "platform", "agent", "idp"}:
        raise HTTPException(status_code=400, detail="Invalid parent_type")
    if "@" not in req.contact and not req.contact.startswith("http"):
        raise HTTPException(status_code=400, detail="Contact must be a verifiable email or URL")
    try:
        if not req.public_key_pem.strip():
            raise ValueError("empty key")
        key = serialization.load_pem_public_key(req.public_key_pem.encode())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("parent key must be Ed25519")
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid parent public key; expected Ed25519 PEM") from exc
    parent = models.ParentAuthority(name=req.name, parent_type=req.parent_type, contact=req.contact,
                                    public_key_pem=req.public_key_pem,
                                    status=models.ParentStatus.PENDING_VERIFICATION,
                                    trust_tier="self_asserted")
    db.add(parent); db.commit(); db.refresh(parent)
    return schemas.ParentStatusResponse(parent_id=parent.parent_id, status=parent.status.value, trust_tier=parent.trust_tier)


@router.post("/{parent_id}/approve", response_model=schemas.ParentStatusResponse)
def approve_parent(parent_id: str, db: Session = Depends(get_db), x_admin_api_key: str = Header(default="")):
    parent = db.query(models.ParentAuthority).filter_by(parent_id=parent_id).first()
    if not parent: raise HTTPException(status_code=404, detail="Parent authority not found")
    security.require_admin_org(x_admin_api_key, parent.org_id)
    if parent.status == models.ParentStatus.REVOKED: raise HTTPException(status_code=409, detail="Parent authority has been revoked")
    parent.status = models.ParentStatus.ACTIVE; parent.trust_tier = "admin_approved"; parent.verified_at = datetime.now(timezone.utc)
    db.commit()
    return schemas.ParentStatusResponse(parent_id=parent.parent_id, status=parent.status.value, trust_tier=parent.trust_tier)


@router.post("/{parent_id}/reject", response_model=schemas.ParentStatusResponse)
def reject_parent(parent_id: str, db: Session = Depends(get_db), x_admin_api_key: str = Header(default="")):
    parent = db.query(models.ParentAuthority).filter_by(parent_id=parent_id).first()
    if not parent: raise HTTPException(status_code=404, detail="Parent authority not found")
    security.require_admin_org(x_admin_api_key, parent.org_id)
    parent.status = models.ParentStatus.REJECTED; db.commit()
    return schemas.ParentStatusResponse(parent_id=parent.parent_id, status=parent.status.value, trust_tier=parent.trust_tier)


@router.post("/{parent_id}/revoke", response_model=schemas.ParentStatusResponse)
def revoke_parent(parent_id: str, db: Session = Depends(get_db), x_admin_api_key: str = Header(default="")):
    parent = db.query(models.ParentAuthority).filter_by(parent_id=parent_id).first()
    if not parent: raise HTTPException(status_code=404, detail="Parent authority not found")
    security.require_admin_org(x_admin_api_key, parent.org_id)
    parent.status = models.ParentStatus.REVOKED
    # Revoke live credentials immediately; payment execution also rechecks parent status.
    for agent in db.query(models.Agent).filter_by(parent_pk=parent.id).all():
        for cred in db.query(models.Credential).filter_by(agent_pk=agent.id, revoked=False).all():
            cred.revoked = True
    db.commit()
    return schemas.ParentStatusResponse(parent_id=parent.parent_id, status=parent.status.value, trust_tier=parent.trust_tier)
