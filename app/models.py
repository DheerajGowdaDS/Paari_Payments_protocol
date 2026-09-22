"""
Core data model.

Phase 1-2: Agent, Credential, AuthNonce (unchanged in shape).
  - ParentAuthority: a registered, independently-keyed trust root. An agent
    is only as trustworthy as the parent that vouches for it. Registration
    now lands in PENDING_VERIFICATION, not ACTIVE (see P0 fix note below).
  - DelegationRecord: tracks each signed delegation document a parent has
    issued, so a delegation can never be replayed to register a second
    agent or reused after registration.
  - PaymentIntent: one row per payment request evaluated by the Phase 3
    governance engine - the audit trail of what was decided and why.
  - BoundedAuthorization: the single-use, short-lived authorization Phase 4
    produces on ALLOW, which is what actually gets handed to Razorpay.
  - MFAChallenge: a server-issued, single-use nonce binding a specific
    REVIEW-ed payment intent to a step-up approval that must be signed by
    the *parent's* key (a distinct key from the agent's) before the intent
    can be promoted to ALLOW. Replaces the old client-supplied
    `mfa_verified: bool`.
  - RevocationRecord: anti-replay for parent-signed agent revocations, the
    same pattern DelegationRecord uses for delegations.

P0 fix: every timestamp column below uses `UTCDateTime` (app/database.py)
instead of a plain `DateTime(timezone=True)`, which SQLite silently stores
as naive and which caused the offset-naive/offset-aware crash in Phase 2.
"""
import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    String, Boolean, JSON, ForeignKey, Enum, Integer, Text, UniqueConstraint
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, UTCDateTime


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AgentStatus(str, enum.Enum):
    PENDING = "pending"
    ACTIVE = "active"
    REVOKED = "revoked"


class ParentStatus(str, enum.Enum):
    PENDING_VERIFICATION = "pending_verification"
    ACTIVE = "active"
    REJECTED = "rejected"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class GovernanceDecision(str, enum.Enum):
    ALLOW = "allow"
    REVIEW = "review"
    DENY = "deny"


# ---------------------------------------------------------------------------
# Multi-tenancy (Phase 6 Task 8): every tenant-scoped row carries org_id.
# Python-side default "default" keeps old seeds/tests working; migration
# 0008 backfills existing rows and flips the columns to NOT NULL.
# ---------------------------------------------------------------------------

class Organization(Base):
    """A tenant. Parents belong to exactly one org; agents inherit it."""
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)


class ProviderAccount(Base):
    """Marker row: org_id has its own Razorpay keys (secrets stay in env,
    resolved as RAZORPAY_KEY_ID__{ORG}; the row only says 'look there').
    Absent row -> shared default keys. is_default marks the fallback row."""
    __tablename__ = "provider_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    key_id_label: Mapped[str] = mapped_column(String(200), default="default")
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)


# ---------------------------------------------------------------------------
# Parent / Authority
# ---------------------------------------------------------------------------

class ParentAuthority(Base):
    """
    A trust root: a company, developer, platform, another agent, or an IdP
    that can vouch for and delegate authority to agents. Parents hold their
    own Ed25519 key pair (private key never given to Paari) and sign
    delegation documents with it.

    P0 fix: registration no longer grants ParentStatus.ACTIVE immediately.
    Every new parent starts PENDING_VERIFICATION and cannot delegate to any
    agent (agent registration and payment governance both hard-require
    ACTIVE) until an administrator approves it via POST
    /parents/{parent_id}/approve. This is where real identity-proofing
    (KYB, business-registry lookup, domain verification, IdP federation)
    plugs in - the admin-approval gate is the minimum viable version of
    that step, not a replacement for it.
    """
    __tablename__ = "parent_authorities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    parent_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), default="default")

    name: Mapped[str] = mapped_column(String(200))
    parent_type: Mapped[str] = mapped_column(String(50))  # company | developer | platform | agent | idp
    contact: Mapped[str] = mapped_column(String(200))

    public_key_pem: Mapped[str] = mapped_column(String(2000))
    status: Mapped[ParentStatus] = mapped_column(Enum(ParentStatus), default=ParentStatus.PENDING_VERIFICATION)
    # Production trust tier: how this parent was verified.
    # self_asserted (registered, nothing checked) -> admin_approved (human
    # gate) -> kyb_verified (KYB vendor reference recorded, no vendor call).
    trust_tier: Mapped[str] = mapped_column(String(20), default="self_asserted")
    kyb_provider_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    agents: Mapped[list["Agent"]] = relationship(back_populates="parent")


class DelegationRecord(Base):
    """
    Tracks a signed delegation document once it has been consumed by an
    agent registration, so the exact same delegation can never be replayed
    to bind a second agent or re-register the same one.
    """
    __tablename__ = "delegation_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    delegation_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    org_id: Mapped[str] = mapped_column(String(64), default="default")
    parent_pk: Mapped[int] = mapped_column(ForeignKey("parent_authorities.id"))

    agent_public_key_fingerprint: Mapped[str] = mapped_column(String(64))
    granted_capabilities: Mapped[list] = mapped_column(JSON)
    payment_limit_minor_units: Mapped[int] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(10))

    issued_at: Mapped[datetime] = mapped_column(UTCDateTime)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)
    consumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class RevocationRecord(Base):
    """
    Anti-replay for parent-signed agent revocations (see routers/agents.py).
    A given revocation_id can only ever be consumed once, exactly like a
    DelegationRecord - otherwise a captured signed revocation could be
    replayed, or (worse) a stale one could be replayed to knock out an
    agent's *new* credential after re-registration.
    """
    __tablename__ = "revocation_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    revocation_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    org_id: Mapped[str] = mapped_column(String(64), default="default")
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    consumed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)


# ---------------------------------------------------------------------------
# Agent / Credential / Auth (Phase 1-2)
# ---------------------------------------------------------------------------

class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), default="default")

    name: Mapped[str] = mapped_column(String(200))
    agent_type: Mapped[str] = mapped_column(String(100))
    purpose: Mapped[str] = mapped_column(String(500))

    parent_pk: Mapped[int] = mapped_column(ForeignKey("parent_authorities.id"))
    parent: Mapped["ParentAuthority"] = relationship(back_populates="agents")
    delegation_id: Mapped[str] = mapped_column(String(64))  # which delegation bound this agent

    public_key_pem: Mapped[str] = mapped_column(String(2000))
    # Rotation: previous key stays verifiable until key_sunset_at (24h
    # grace for in-flight clients), then fails closed.
    old_public_key_pem: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    key_sunset_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    # Granted by the parent's delegation - never self-requested by the agent.
    granted_capabilities: Mapped[list] = mapped_column(JSON, default=list)
    payment_limit_minor_units: Mapped[int] = mapped_column(Integer, default=0)
    currency: Mapped[str] = mapped_column(String(10), default="INR")

    status: Mapped[AgentStatus] = mapped_column(Enum(AgentStatus), default=AgentStatus.PENDING)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    valid_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    # Protocol version this agent onboarded with ("1.0" for v1; NULL = legacy).
    protocol_version: Mapped[str | None] = mapped_column(String(10), nullable=True)

    credentials: Mapped[list["Credential"]] = relationship(back_populates="agent")


class Credential(Base):
    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    credential_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), default="default")

    agent_pk: Mapped[int] = mapped_column(ForeignKey("agents.id"))
    agent: Mapped["Agent"] = relationship(back_populates="credentials")

    signed_jwt: Mapped[str] = mapped_column(String(4000))
    issued_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    # Rotation chain: superseded_by points at the replacing credential.
    superseded_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rotates_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class AuthNonce(Base):
    __tablename__ = "auth_nonces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    nonce: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), default="default")
    agent_id: Mapped[str] = mapped_column(String(64), index=True)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


# ---------------------------------------------------------------------------
# Payment Governance (Phase 3) / Bounded Authorization (Phase 4)
# ---------------------------------------------------------------------------

class PaymentIntent(Base):
    """
    One row per payment request evaluated - the governance audit trail.

    P1 fix: idempotency is now scoped to (agent_id, idempotency_key), with
    a real unique constraint, instead of a bare idempotency_key that any
    caller could collide with (or race) regardless of which agent it
    belonged to.
    """
    __tablename__ = "payment_intents"
    __table_args__ = (
        UniqueConstraint("agent_id", "idempotency_key", name="uq_payment_intents_agent_idem"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    intent_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), default="default")

    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.agent_id"), index=True)
    transaction_id: Mapped[str] = mapped_column(String(100), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(100), index=True)

    merchant: Mapped[str] = mapped_column(String(200))
    amount_minor_units: Mapped[int] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(10))
    action: Mapped[str] = mapped_column(String(50))
    purpose: Mapped[str] = mapped_column(String(500), default="")

    decision: Mapped[GovernanceDecision] = mapped_column(Enum(GovernanceDecision))
    reasons: Mapped[list] = mapped_column(JSON, default=list)  # every check result, for audit
    mfa_required: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    # Task 2: velocity REVIEWs park for REVIEW_TTL instead of forever. A
    # resubmission is accepted once this passes; NULL means "not a
    # velocity-parked intent" (ALLOW/DENY rows and MFA-step-up REVIEWs).
    review_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)


class MFAChallenge(Base):
    """
    Phase 3 step-up MFA - P0 fix for the `mfa_verified: bool` trust
    problem.

    A payment intent that lands on REVIEW because it needs step-up MFA is
    NOT allowed to self-certify. Instead:

      1. The caller requests a challenge for that specific intent_id.
      2. Paari mints a single-use nonce bound to that intent's exact
         context (agent, transaction, merchant, amount, currency) and
         returns the canonical string that must be signed.
      3. The *parent authority* (a different key than the agent's) signs
         that exact string with its private key - out-of-band, e.g. a
         human approver at the parent org - and the signature is submitted
         back to Paari.
      4. Paari verifies the signature against the parent's registered
         public key, burns the challenge, and only then promotes the
         intent to ALLOW and mints a BoundedAuthorization.

    This is a genuine second factor (a distinct key holder, not the agent
    re-proving the same key) and it is bound to the specific transaction,
    so a captured approval can't be replayed against a different amount.
    """
    __tablename__ = "mfa_challenges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    challenge_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)

    # Not unique: an expired-but-unused challenge for an intent is
    # invalidated (marked used) before a fresh one is issued, so retries
    # after a lost response don't get stuck behind a DB uniqueness error.
    intent_id: Mapped[str] = mapped_column(ForeignKey("payment_intents.intent_id"), index=True)
    org_id: Mapped[str] = mapped_column(String(64), default="default")
    nonce: Mapped[str] = mapped_column(String(64), default=_uuid)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class BoundedAuthorization(Base):
    """
    The Phase 4 artifact: a single-use, short-lived authorization handed to
    the payment provider layer. Never gives the agent standing/reusable
    payment authority.
    """
    __tablename__ = "bounded_authorizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    authorization_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String(64), default="default")

    intent_id: Mapped[str] = mapped_column(ForeignKey("payment_intents.intent_id"), index=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.agent_id"), index=True)
    transaction_id: Mapped[str] = mapped_column(String(100))
    merchant: Mapped[str] = mapped_column(String(200))
    amount_minor_units: Mapped[int] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(10))

    token: Mapped[str] = mapped_column(Text)  # signed JWT encoding the same bounds, for the provider layer
    issued_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    max_usage: Mapped[int] = mapped_column(Integer, default=1)
    usage_count: Mapped[int] = mapped_column(Integer, default=0)


class ProviderTransaction(Base):
    """
    Phase 5 execution state for one bounded authorization.

    States: AUTHORIZED -> PROVIDER_SUBMITTED -> PAYMENT_PENDING -> PAID / FAILED
    (REFUNDED reserved for a later refund path; never set here).
    One row per authorization_id; Razorpay order/event ids are unique
    so retries and webhook replays stay idempotent.
    """
    __tablename__ = "provider_transactions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    authorization_id: Mapped[str] = mapped_column(ForeignKey("bounded_authorizations.authorization_id"), unique=True, index=True)
    intent_id: Mapped[str] = mapped_column(ForeignKey("payment_intents.intent_id"), index=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.agent_id"), index=True)
    org_id: Mapped[str] = mapped_column(String(64), default="default")

    state: Mapped[str] = mapped_column(String(30), default="AUTHORIZED")
    razorpay_order_id: Mapped[str | None] = mapped_column(String(100), unique=True, nullable=True)
    razorpay_payment_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    webhook_event_id: Mapped[str | None] = mapped_column(String(100), unique=True, nullable=True)

    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    reconciled_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class AuditEvent(Base):
    """
    Phase 6 Task 4: append-only, hash-chained audit log. One row per
    security-relevant fact (intent decided, authorization minted/consumed,
    order submitted, webhook applied, reconciled, delegation consumed,
    credential issued, challenge verified). Rows are keyed by a trace id
    (payment transaction_id for money flows) and linked via
    prev_hash/event_hash so tampering with any row breaks verification.
    Rows are never updated or deleted - only appended.
    """
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[str] = mapped_column(String(64), default="default")
    transaction_id: Mapped[str] = mapped_column(String(100), index=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    parent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    kind: Mapped[str] = mapped_column(String(40))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)


class RequestProof(Base):
    """Consumed per-request proof JTIs. Durable replay protection for
    sender-constrained Paari-Proof-JWT requests across workers/restarts."""
    __tablename__ = "request_proofs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    jti: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.agent_id"), index=True)
    org_id: Mapped[str] = mapped_column(String(64), default="default")
    issued_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)


class RateBucket(Base):
    """
    Phase 6 Task 7: shared rate-limit counters. Table-backed (not in-memory)
    so N uvicorn workers share one counter; one row per (scope, window).
    Rows for dead windows are pruned lazily inside check_rate.
    """
    __tablename__ = "rate_buckets"
    __table_args__ = (
        UniqueConstraint("scope", "window_start", name="uq_rate_buckets_scope_window"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[str] = mapped_column(String(64), default="default")
    scope: Mapped[str] = mapped_column(String(100), index=True)
    window_start: Mapped[datetime] = mapped_column(UTCDateTime)
    count: Mapped[int] = mapped_column(Integer, default=0)
