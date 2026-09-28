"""Minimal independent-agent example for Paari Protocol v1.0.

This file intentionally uses only the SDK package plus HTTP/crypto dependencies.
A parent-signed delegation must be supplied by the agent operator.
"""
import os
import uuid
from datetime import datetime, timedelta, timezone

from paari_agent import PaariAgentClient, generate_keypair, fingerprint, sign_delegation

BASE_URL = os.environ.get("PAARI_BASE_URL", "http://127.0.0.1:8000")


def build_delegation(parent_id: str, parent_private_key: str, agent_public_key: str) -> tuple[dict, str]:
    now = datetime.now(timezone.utc)
    delegation = {
        "delegation_id": str(uuid.uuid4()),
        "parent_id": parent_id,
        "agent_public_key_fingerprint": fingerprint(agent_public_key),
        "granted_capabilities": ["make_payment"],
        "payment_limit_minor_units": 500000,
        "currency": "INR",
        "issued_at": int(now.timestamp()),
        "expires_at": int((now + timedelta(days=30)).timestamp()),
    }
    return delegation, sign_delegation(parent_private_key, delegation)


def main():
    # Parent registration/approval is intentionally omitted from this example:
    # the parent authority is expected to have completed that trust step.
    parent_id = os.environ["PAARI_PARENT_ID"]
    parent_private = os.environ["PAARI_PARENT_PRIVATE_KEY_PEM"]
    agent_private, agent_public = generate_keypair()
    agent = PaariAgentClient(BASE_URL, agent_private, agent_public)
    print(agent.discover())
    delegation, signature = build_delegation(parent_id, parent_private, agent_public)
    agent.register(name="Independent SDK Agent", agent_type="assistant",
                   purpose="protocol conformance", delegation=delegation,
                   delegation_signature_b64=signature)
    agent.authenticate()
    intent = agent.payment_intent(transaction_id=f"TX-{uuid.uuid4()}",
                                  idempotency_key=f"idem-{uuid.uuid4()}",
                                  merchant="Example Merchant", amount_minor_units=100,
                                  currency="INR")
    print(intent)
    if intent.get("authorization"):
        print(agent.consume(intent["authorization"]["authorization_id"]))


if __name__ == "__main__":
    main()
