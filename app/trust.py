"""Parent trust verification abstraction.

The protocol keeps the trust root pluggable: the reference implementation
ships an admin-controlled verifier, while a deployment may later connect a
real KYB/KYC, business registry or enterprise IdP without changing agent or
payment protocol semantics.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sqlalchemy.orm import Session

from app import models


@dataclass(frozen=True)
class TrustVerification:
    approved: bool
    trust_tier: str
    provider: str
    provider_ref: str | None
    reason: str


class ParentTrustProvider(Protocol):
    name: str

    def verify(self, db: Session, parent: models.ParentAuthority) -> TrustVerification:
        ...


class AdminApprovedTrustProvider:
    """Reference provider for Phase 7.

    It treats a Paari-admin approval as the verified control point. The
    interface intentionally matches a future external KYB provider.
    """
    name = "paari-admin"

    def verify(self, db: Session, parent: models.ParentAuthority) -> TrustVerification:
        if parent.status != models.ParentStatus.ACTIVE:
            return TrustVerification(False, parent.trust_tier, self.name, parent.kyb_provider_ref,
                                     "parent is not active")
        return TrustVerification(True, parent.trust_tier, self.name, parent.kyb_provider_ref,
                                 "parent is active under the configured Paari trust control")


_default_provider = AdminApprovedTrustProvider()


def get_trust_provider() -> AdminApprovedTrustProvider:
    return _default_provider
