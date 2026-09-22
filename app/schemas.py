from datetime import datetime
from pydantic import BaseModel, Field


# ---------- Parent Authority ----------

class ParentRegistrationRequest(BaseModel):
    name: str
    parent_type: str = Field(..., description="company | developer | platform | agent | idp")
    contact: str
    public_key_pem: str = Field(..., description="Parent's Ed25519 public key, PEM-encoded")


class ParentStatusResponse(BaseModel):
    parent_id: str
    status: str
    trust_tier: str = "self_asserted"


# ---------- Delegation ----------

class DelegationDocument(BaseModel):
    """
    The exact fields the parent signs over. Both sides must build this
    struct identically and serialize it with crypto_utils.canonical_json()
    before signing/verifying - field order and types must match exactly.

    issued_at/expires_at are integer Unix timestamps rather than ISO
    strings deliberately: an int round-trips through JSON parse/re-encode
    byte-for-byte, so re-serializing the parsed model for verification can
    never accidentally produce different bytes than what the parent signed.
    """
    delegation_id: str
    parent_id: str
    agent_public_key_fingerprint: str
    granted_capabilities: list[str]
    payment_limit_minor_units: int
    currency: str
    issued_at: int
    expires_at: int


# ---------- Agent Registration ----------

class AgentRegistrationRequest(BaseModel):
    name: str
    agent_type: str
    purpose: str = Field(..., max_length=500)
    public_key_pem: str = Field(..., description="Agent's Ed25519 public key, PEM-encoded")

    delegation: DelegationDocument
    delegation_signature_b64: str = Field(
        ..., description="Parent's Ed25519 signature over canonical_json(delegation)"
    )


class AgentCard(BaseModel):
    agent_id: str
    name: str
    agent_type: str
    parent_id: str
    parent_name: str
    identity_status: str
    public_key_reference: str
    granted_capabilities: list[str]
    payment_limit_minor_units: int
    currency: str
    valid_until: datetime | None
    credential_id: str
    paari_endpoint: str

    # P1 fix: the card itself is now integrity-protected. `card_signature_b64`
    # is Paari's Ed25519 signature over the canonical JSON of every field
    # above (see security.sign_agent_card); `paari_public_key_pem` is
    # included so a relying party can verify it without a separate
    # discovery call.
    card_signature_b64: str = ""
    paari_public_key_pem: str = ""


class V1AgentCard(BaseModel):
    """Canonical Paari Protocol v1 discovery card.

    The card is signed by Paari for integrity/discovery. It is deliberately
    not an authorization artifact; delegation, credential and bounded
    authorization remain separate security objects.
    """
    protocol: str = "paari"
    protocol_version: str = "1.0"
    issuer: str = "paari"
    agent_id: str
    name: str
    agent_type: str
    parent_id: str
    status: str
    public_key: str
    capabilities: list[str]
    limits: dict
    credential_id: str
    expires_at: datetime | None
    endpoints: dict[str, str]
    card_signature_b64: str
    paari_public_key_pem: str


class AgentRegistrationResponse(BaseModel):
    agent_card: AgentCard
    credential_jwt: str
    credential_expires_at: datetime


class AgentRevokeRequest(BaseModel):
    """
    Agent revocation accepts EITHER admin auth (X-Admin-Api-Key header,
    body may be omitted) OR a parent-signed revocation document, so a
    parent authority can revoke its own agent's without needing the admin
    key. All four fields below are required for the parent-signed path.
    """
    revocation_id: str | None = Field(
        default=None, description="Fresh UUID chosen by the caller; single-use, replay-checked server-side."
    )
    issued_at: int | None = Field(default=None, description="Unix timestamp the parent signed at.")
    parent_signature_b64: str | None = Field(
        default=None,
        description="Parent's Ed25519 signature over canonical_json({action, agent_id, parent_id, revocation_id, issued_at})",
    )


class RevokeResponse(BaseModel):
    agent_id: str
    status: str


# ---------- Authentication ----------

class ChallengeRequest(BaseModel):
    agent_id: str


class ChallengeResponse(BaseModel):
    nonce: str
    expires_at: datetime


class VerifyRequest(BaseModel):
    agent_id: str
    nonce: str
    signature_b64: str
    credential_jwt: str


class VerifyResponse(BaseModel):
    authenticated: bool
    session_token: str
    expires_at: datetime
    granted_capabilities: list[str]
    payment_limit_minor_units: int


# ---------- Payment Governance (Phase 3) / Bounded Authorization (Phase 4) ----------

class PaymentIntentRequest(BaseModel):
    # Preferred transport is Authorization: Bearer <session>; body field is retained for compatibility.
    # agent_id is optional for legacy compatibility; when supplied on v1 it MUST
    # equal the authenticated session subject.
    session_token: str = ""
    agent_id: str = ""
    transaction_id: str
    idempotency_key: str
    merchant: str
    amount_minor_units: int
    currency: str
    action: str = Field(..., description="e.g. make_payment, issue_refund_request")
    purpose: str = ""
    # NOTE: there is deliberately no `mfa_verified` field here anymore.
    # That was a P0 vulnerability - the caller could simply claim MFA had
    # happened. Step-up MFA is now a separate, cryptographically verified
    # flow: see MFAChallengeRequest / MFAVerifyRequest below.


class V1PaymentIntentRequest(BaseModel):
    """Normative v1 payment intent. Identity is explicit in the wire body
    and must match the authenticated session; the body token is compatibility
    only and new clients should use Authorization: Bearer."""
    agent_id: str
    session_token: str = ""
    transaction_id: str
    idempotency_key: str
    merchant: str
    amount_minor_units: int
    currency: str
    action: str
    purpose: str = ""


class PaymentIntentResponse(BaseModel):
    intent_id: str
    transaction_id: str = ""
    decision: str
    reasons: list[str]
    mfa_required: bool
    authorization: dict | None = None  # present only when decision == allow
    # Present only on velocity-parked REVIEWs: resubmission accepted after.
    review_expires_at: datetime | None = None


class ConsumeAuthorizationRequest(BaseModel):
    """
    P0 fix: consuming a bounded authorization now requires proof that the
    caller is the same authenticated agent the authorization was issued
    to - a valid, unexpired session token for that agent - rather than
    being reachable by anyone who merely knows the authorization_id.
    """
    session_token: str = ""


class ConsumeAuthorizationResponse(BaseModel):
    authorization_id: str
    consumed: bool
    remaining_uses: int
    # Phase 5 provider execution state.
    state: str = "PROVIDER_SUBMITTED"
    razorpay_order_id: str | None = None
    razorpay_payment_id: str | None = None


# ---------- Step-up MFA (replaces client-supplied mfa_verified) ----------

class MFAChallengeRequest(BaseModel):
    intent_id: str
    # Phase 5: requesting a step-up challenge requires proof that the
    # caller is the same authenticated agent the intent belongs to.
    session_token: str


class MFAChallengeResponse(BaseModel):
    challenge_id: str
    intent_id: str
    nonce: str
    context_to_sign: str = Field(
        ..., description="canonical_json string the PARENT authority must sign with its private key"
    )
    expires_at: datetime


class MFAVerifyRequest(BaseModel):
    intent_id: str
    challenge_id: str
    parent_signature_b64: str = Field(
        ..., description="Parent's Ed25519 signature (base64) over `context_to_sign` from the challenge"
    )


class ReconcileRequest(BaseModel):
    """Manual reconcile trigger. The preferred transport is Authorization:
    Bearer <session-token>; the body field remains for compatibility."""

    session_token: str = ""
