"""Structured governance policy results for audit-hardening."""
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
