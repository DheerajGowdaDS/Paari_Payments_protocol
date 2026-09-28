"""
Cryptographic helpers for Layer 1 (Agent Trust).

Algorithm choice: Ed25519.
- Small keys (32 bytes) and signatures (64 bytes) - cheap to store/transmit.
- Deterministic, fast to verify, no parameter footguns (unlike RSA padding
  choices or raw ECDSA nonce reuse risk).
- Widely supported as the modern default for identity/signing use cases.

Paari NEVER generates or holds an agent's private key. The agent generates
its own Ed25519 key pair, keeps the private key, and registers only the
public key with Paari. `generate_agent_keypair` below exists purely so the
demo client can simulate an agent - a real agent would do this on its own
side, out of Paari's reach.
"""
import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_agent_keypair() -> tuple[str, str]:
    """Simulate what an agent does on its own side. Returns (private_pem, public_pem)."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


def sign_with_private_key(private_pem: str, message: str) -> str:
    """Agent-side: sign a message, return base64 signature."""
    private_key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    signature = private_key.sign(message.encode())
    return base64.b64encode(signature).decode()


def verify_signature(public_pem: str, message: str, signature_b64: str) -> bool:
    """Paari-side: verify a signature was made by the holder of the matching private key."""
    import binascii
    public_key = serialization.load_pem_public_key(public_pem.encode())
    try:
        signature = base64.b64decode(signature_b64)
    except (binascii.Error, ValueError):
        return False
    try:
        public_key.verify(signature, message.encode())
        return True
    except (InvalidSignature, ValueError):
        return False


def canonical_json(payload: dict) -> str:
    """
    Deterministic JSON encoding so the same logical document always produces
    the same bytes to sign/verify, regardless of dict key insertion order.
    Both the parent (signing) and Paari (verifying) must use this exact
    function on the exact same fields.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def public_key_fingerprint(public_pem: str) -> str:
    """SHA-256 hex digest of the PEM bytes - used to bind a delegation to one specific key."""
    return hashlib.sha256(public_pem.encode()).hexdigest()
