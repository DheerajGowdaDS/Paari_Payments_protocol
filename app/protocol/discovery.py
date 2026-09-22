"""Paari protocol discovery document."""
from app import security

PROTOCOL_VERSION = "1.0"


def document(base_url: str) -> dict:
    base = base_url.rstrip("/")
    return {
        "protocol": "paari",
        "protocol_version": PROTOCOL_VERSION,
        "issuer": "paari",
        "service": "agentic-payment",
        "base_url": base,
        "discovery": {"well_known": f"{base}/.well-known/paari"},
        "agent_registration": f"{base}/v1/agents/register",
        "agent_card": f"{base}/v1/agents/{{agent_id}}/card",
        "authentication": {
            "challenge": f"{base}/v1/auth/challenge",
            "verify": f"{base}/v1/auth/verify",
        },
        "payment": {
            "intent": f"{base}/v1/payments/intent",
            "consume": f"{base}/v1/payments/authorizations/{{authorization_id}}/consume",
            "mfa_challenge": f"{base}/v1/payments/mfa/challenge",
            "mfa_verify": f"{base}/v1/payments/mfa/verify",
            "reconcile": f"{base}/v1/reconcile/{{authorization_id}}",
            "proof": f"{base}/v1/proof/{{transaction_id}}",
            "webhook": f"{base}/v1/payments/webhooks/razorpay",
        },
        "security": {
            "credential_type": "JWT-EdDSA",
            "request_proof": "Paari-Proof-JWT",
            "proof_binding": "agent-public-key",
            "mfa": "parent-authority-signature",
        },
        "algorithms": {"agent_keys": ["Ed25519"], "paari_signatures": ["Ed25519"]},
        "provider_boundary": {"execution": "Paari-controlled", "providers": ["razorpay"]},
        "conformance": {
            "spec": f"{base}/docs/PROTOCOL.md",
            "tests": f"{base}/docs/CONFORMANCE.md",
            "sdk": "sdk/paari_agent",
        },
        "paari_public_key_pem": security.paari_public_key_pem(),
        "rules": {
            "private_keys_never_sent_to_paari": True,
            "agent_authority_comes_from_signed_delegation": True,
            "payment_authorization_is_single_use": True,
            "settlement_requires_provider_verification": True,
        },
    }
