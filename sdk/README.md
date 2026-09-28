# Paari Agent SDK — Protocol v1.0

This directory is the reference client for an **external/foreign AI agent**.
It intentionally imports no Paari server modules. The agent owns its private
Ed25519 key; Paari receives only the public key and signed proofs.

## Minimal flow

```python
from paari_agent import PaariAgentClient, generate_keypair

private_key, public_key = generate_keypair()
agent = PaariAgentClient("https://paari.example", private_key, public_key)

agent.discover()
agent.register(
    name="Example Agent",
    agent_type="assistant",
    purpose="payment",
    delegation=parent_signed_delegation,
    delegation_signature_b64=parent_signature,
)
agent.authenticate()
result = agent.payment_intent(
    transaction_id="TX-001",
    idempotency_key="idem-TX-001",
    merchant="Example Merchant",
    amount_minor_units=100,
    currency="INR",
)
agent.consume(result["authorization"]["authorization_id"])
```

For a production integration, pin `protocol_version == 1.0`, verify the
signed Agent Card locally, use `Authorization: Bearer` plus `X-Paari-Proof`,
and never send the private key to Paari.
