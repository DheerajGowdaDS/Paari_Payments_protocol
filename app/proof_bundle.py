"""Proof-bundle collector: read-only assembly of the 14 stage artifacts.

Queries only; never mutates state. Callers own the session lifecycle.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app import models
from app.audit import verify_chain
from app.protocol.discovery import document as discovery_document
from app.transitions import TERMINAL_STATES

PROTOCOL = "paari"
PROTOCOL_VERSION = "1.0"


def _settlement_source(environment) -> str:
    """Map a recorded provider environment onto what it actually attests.

    Total, and deliberately non-upward-rounding: an unrecognised or absent
    environment becomes `unattributed`, never `provider`. The field exists so a
    reader can tell whether a money claim came from the provider or from Paari's
    own harness; a default that guessed "provider" would destroy the one thing
    it records.
    """
    if environment in ("test", "live"):
        return "provider"
    if environment == "simulated":
        return "simulator"
    return "unattributed"


def _base() -> dict:
    return {"protocol": PROTOCOL, "protocol_version": PROTOCOL_VERSION}


def collect_proof_bundle(db: Session, transaction_id: str) -> dict:
    matches = (
        db.query(models.PaymentIntent)
        .filter_by(transaction_id=transaction_id)
        .order_by(models.PaymentIntent.id)
        .all()
    )
    if not matches:
        raise ValueError(f"unknown transaction_id: {transaction_id}")
    if len(matches) > 1:
        raise ValueError(f"ambiguous transaction_id: {transaction_id}")
    intent = matches[0]

    mandate = None
    mandate_signature = None
    if intent.mandate_id:
        mandate = db.query(models.UserPaymentMandate).filter_by(mandate_id=intent.mandate_id).first()
        if mandate is not None and mandate.signature_b64:
            # Recomputed here, not read from a stored verdict: the bundle must
            # never present a broken or tampered mandate as valid evidence.
            from app.mandate_signing import verify_mandate_signature
            mandate_signature = verify_mandate_signature(mandate)

    agent = db.query(models.Agent).filter_by(agent_id=intent.agent_id).first()
    if agent is None:
        raise ValueError(f"unknown agent for transaction: {transaction_id}")
    parent = agent.parent
    if parent is None:
        raise ValueError(f"unknown parent for agent {agent.agent_id}")

    delegation = (
        db.query(models.DelegationRecord)
        .filter_by(delegation_id=agent.delegation_id)
        .first()
    )
    if delegation is None:
        raise ValueError(f"unknown delegation for agent {agent.agent_id}")

    credential = (
        db.query(models.Credential)
        .join(models.Agent, models.Credential.agent_pk == models.Agent.id)
        .filter(models.Agent.agent_id == agent.agent_id)
        .order_by(models.Credential.issued_at.desc())
        .first()
    )
    if credential is None:
        raise ValueError(f"unknown credential for agent {agent.agent_id}")

    events = (
        db.query(models.AuditEvent)
        .filter_by(transaction_id=transaction_id)
        .order_by(models.AuditEvent.id)
        .all()
    )

    policy_results: list = []
    for e in events:
        if e.kind == "intent_decided" and isinstance(e.detail, dict):
            policy_results = e.detail.get("policy_results") or []
            break

    auth = (
        db.query(models.BoundedAuthorization)
        .filter_by(intent_id=intent.intent_id)
        .one_or_none()
    )

    provider_txn = None
    if auth is not None:
        provider_txn = (
            db.query(models.ProviderTransaction)
            .filter_by(authorization_id=auth.authorization_id)
            .one_or_none()
        )

    revocation = (
        db.query(models.RevocationRecord)
        .filter_by(agent_id=agent.agent_id)
        .one_or_none()
    )

    credential_status = (
        "revoked"
        if credential.revoked
        else ("superseded" if credential.superseded_by else "active")
    )

    audit_events = []
    for e in events:
        detail = e.detail if isinstance(e.detail, dict) else {}
        audit_events.append(
            {
                "event_id": str(e.id),
                "kind": e.kind,
                "event_type": e.kind,
                "actor": e.agent_id,
                "transaction_id": e.transaction_id,
                "detail": detail,
                "previous_state": detail.get(
                    "previous_state", detail.get("from_state")
                ),
                "current_state": detail.get(
                    "current_state", detail.get("to_state")
                ),
                "reasons": detail.get("reasons", []),
                "prev_hash": e.prev_hash,
                "event_hash": e.event_hash,
            }
        )

    if auth is None:
        bounded_authorization = None
        payment_execution = None
        payment_result = None
    else:
        bounded_authorization = {
            "authorization_id": auth.authorization_id,
            "agent_id": auth.agent_id,
            "transaction_id": auth.transaction_id,
            "merchant": auth.merchant,
            "amount_minor_units": auth.amount_minor_units,
            "currency": auth.currency,
            "mandate_id": auth.mandate_id,
            "expires_at": auth.expires_at.isoformat(),
            "max_usage": auth.max_usage,
        }
        if provider_txn is None:
            payment_execution = None
            payment_result = None
        else:
            # Which world produced this object. `unknown` is a real answer and
            # is never upgraded to imply a provider attested anything.
            environment = getattr(provider_txn, "provider_environment", None) or "unknown"
            source = _settlement_source(environment)
            payment_execution = {
                **_base(),
                "authorization_id": provider_txn.authorization_id,
                "state": provider_txn.state,
                "razorpay_order_id": provider_txn.razorpay_order_id,
                "provider_environment": environment,
            }
            provider_base = getattr(provider_txn, "provider_api_base", None) or ""
            provider_name = "reference-autonomous" if str(provider_base).startswith("in-memory://") else "razorpay"
            payment_result = {
                **_base(),
                "authorization_id": provider_txn.authorization_id,
                "transaction_id": intent.transaction_id,
                "provider": provider_name,
                "provider_payment_id": provider_txn.razorpay_payment_id,
                "provider_environment": environment,
                "provider_key_id_prefix": getattr(provider_txn, "provider_key_id_prefix", None),
                "provider_api_base": getattr(provider_txn, "provider_api_base", None),
                # `webhook_verified` keeps its narrow, accurate meaning: a
                # delivery arrived whose signature verified. It does NOT claim
                # the money moved in the real world - `settlement_source` does.
                "provider_order_id": provider_txn.razorpay_order_id,
                "webhook_event": provider_txn.webhook_event_id,
                "webhook_verified": provider_txn.webhook_event_id is not None,
                "settlement_source": source,
                "final_state": provider_txn.state,
                "terminal": provider_txn.state in TERMINAL_STATES,
            }

    # Real discovery document (not a placeholder) — satisfies paari-discovery.v1.schema.json
    discovery = discovery_document("https://paari.example")

    # Real authentication evidence: the most recent used nonce for this agent, plus credential state
    last_nonce = (
        db.query(models.AuthNonce)
        .filter_by(agent_id=agent.agent_id, used=True)
        .order_by(models.AuthNonce.created_at.desc())
        .first()
    )

    # Real signed Agent Card (verifiable) — use the same constructor the v1 endpoint uses
    from app.routers.v1 import _signed_card as _build_signed_card

    signed_card_obj = _build_signed_card(agent, parent, credential.credential_id)
    # V1AgentCard is a Pydantic model; dump to plain dict with JSON-compatible datetime
    try:
        agent_card_dict = signed_card_obj.model_dump(mode="json")
    except AttributeError:
        agent_card_dict = dict(signed_card_obj)

    artifacts = {
        "discovery": discovery,
        "parent_trust": {
            **_base(),
            "parent_id": parent.parent_id,
            "status": parent.status.value,
            "trust_tier": parent.trust_tier,
        },
        "delegation": {
            **_base(),
            "delegation_id": delegation.delegation_id,
            "parent_id": parent.parent_id,
            "agent_public_key_fingerprint": delegation.agent_public_key_fingerprint,
            "granted_capabilities": delegation.granted_capabilities,
            "payment_limit_minor_units": delegation.payment_limit_minor_units,
            "currency": delegation.currency,
            "issued_at": int(delegation.issued_at.timestamp()),
            "expires_at": int(delegation.expires_at.timestamp()),
            # Paari verifies the parent signature at registration and does not retain it
            "signature_b64": None,
        },
        "agent_identity": {
            **_base(),
            "agent_id": agent.agent_id,
            "public_key_pem": agent.public_key_pem,
            "status": agent.status.value,
            "delegation_id": agent.delegation_id,
            "parent_id": agent.parent.parent_id,
        },
        "agent_card": agent_card_dict,
        "credential": {
            **_base(),
            "credential_id": credential.credential_id,
            "agent_id": agent.agent_id,
            "issued_at": credential.issued_at.isoformat(),
            "expires_at": credential.expires_at.isoformat(),
            "revoked": credential.revoked,
            "superseded_by": credential.superseded_by,
            "status": credential_status,
            "capabilities": list(agent.granted_capabilities or []),
            "payment_limit_minor_units": agent.payment_limit_minor_units,
            "currency": agent.currency,
        },
        "authentication": {
            **_base(),
            "agent_id": agent.agent_id,
            "authenticated": bool(last_nonce is not None and credential_status == "active" and agent.status.value == "active"),
            "credential_id": credential.credential_id,
            "credential_status": credential_status,
            "nonce_id": last_nonce.nonce if last_nonce else None,
            "nonce_used": bool(last_nonce.used) if last_nonce else False,
            "nonce_expires_at": last_nonce.expires_at.isoformat() if last_nonce else None,
        },
        "payment_intent": {
            **_base(),
            "intent_id": intent.intent_id,
            "agent_id": intent.agent_id,
            "transaction_id": intent.transaction_id,
            "decision": intent.decision.value,
            "reasons": list(intent.reasons or []),
            "mfa_required": intent.mfa_required,
            "mandate_id": intent.mandate_id,
            "merchant_category": intent.merchant_category,
        },
        # Phase 10: the causal chain as a structured, queryable artifact.
        #
        # Every identifier the Blueprint names is already a durable column on
        # PaymentIntent / BoundedAuthorization / ProviderTransaction, but the
        # bundle exposed none of the `llm_*` ones in a structured field, so the
        # question "which model run caused this provider payment" could only be
        # answered by digging through free-text audit `detail` JSON. Saying the
        # causal chain is one of Paari's differentiators requires an artifact
        # that demonstrates it without a JSON scrape.
        #
        # `llm_attributed` is included deliberately: these labels are
        # client-asserted trace metadata, and an auditor must be able to tell a
        # claimed attribution from an absent one rather than reading empty
        # strings as a refutation.
        "causal_provenance": {
            **_base(),
            "llm_attributed": bool(getattr(intent, "llm_attributed", False)),
            "llm_run_id": getattr(intent, "llm_run_id", None),
            "llm_model": getattr(intent, "llm_model", None),
            "llm_tool_call_id": getattr(intent, "llm_tool_call_id", None),
            "llm_tool_name": getattr(intent, "llm_tool_name", None),
            "agent_id": intent.agent_id,
            "mandate_id": intent.mandate_id,
            "transaction_id": intent.transaction_id,
            "intent_id": intent.intent_id,
            "authorization_id": auth.authorization_id,
            "provider_order_id": getattr(provider_txn, "razorpay_order_id", None) if provider_txn else None,
            "provider_payment_id": getattr(provider_txn, "razorpay_payment_id", None) if provider_txn else None,
            "provider_environment": getattr(provider_txn, "provider_environment", None) if provider_txn else None,
        },
        "governance_decision": {
            **_base(),
            "intent_id": intent.intent_id,
            "agent_id": intent.agent_id,
            "transaction_id": intent.transaction_id,
            "merchant": intent.merchant,
            "decision": intent.decision.value,
            "reasons": list(intent.reasons or []),
            "policy_results": policy_results,
            "mfa_required": intent.mfa_required,
            "mandate_id": intent.mandate_id,
        },
        "user_payment_mandate": (
            {
                **_base(),
                "mandate_id": mandate.mandate_id,
                "user_id": mandate.user_id,
                "agent_id": mandate.agent_id,
                "status": mandate.status.value,
                "max_per_transaction": mandate.max_per_transaction,
                "max_daily_amount": mandate.max_daily_amount,
                # The three Sprint 6 budget dimensions used to be missing here
                # entirely, so the evidence bundle could not prove which
                # constraints actually governed the payment - the very limits
                # that did the work were invisible to an auditor.
                "max_per_hour": mandate.max_per_hour,
                "max_per_merchant_per_day": mandate.max_per_merchant_per_day,
                "max_category_per_day": mandate.max_category_per_day,
                "currency": mandate.currency,
                "allowed_merchants": list(mandate.allowed_merchants or []),
                "allowed_categories": list(mandate.allowed_categories or []),
                "require_review_above": mandate.require_review_above,
                "valid_from": mandate.valid_from.isoformat(),
                "expires_at": mandate.expires_at.isoformat(),
                # Signature evidence: an offline verifier must be able to
                # re-derive canonical_json(mandate_payload) from the stored
                # row, which needs the signer public key and the signature.
                "signing_key_id": mandate.signing_key_id,
                "signature_b64": mandate.signature_b64,
                "user_public_key_pem": mandate.user_public_key_pem,
                "signed_at": mandate.signed_at.isoformat() if mandate.signed_at else None,
                "signature_valid": (mandate_signature.signature_valid
                                    if mandate_signature else None),
                "signature_reasons": list(mandate_signature.reasons) if mandate_signature else [],
            } if mandate is not None else None
        ),
        "bounded_authorization": bounded_authorization,
        "payment_execution": payment_execution,
        "payment_result": payment_result,
        "audit_record": {
            **_base(),
            "transaction_id": transaction_id,
            # Recompute every link so the bundle never presents a broken chain
            # as intact evidence.
            "chain_verified": verify_chain(db, transaction_id),
            "events": audit_events,
        },
        "revocation": {
            **_base(),
            "agent_id": agent.agent_id,
            # Admin-key revocations never write a RevocationRecord, so the
            # agent status is the authoritative signal; the record only proves
            # the parent-signed path.
            "revoked": (agent.status == models.AgentStatus.REVOKED
                        or revocation is not None),
            "revocation_id": revocation.revocation_id if revocation else None,
        },
    }

    return {
        "protocol": PROTOCOL,
        "protocol_version": PROTOCOL_VERSION,
        "bundle_id": f"bundle-{transaction_id}",
        "transaction_id": transaction_id,
        "created_at": intent.created_at.isoformat(),
        "artifacts": artifacts,
    }
