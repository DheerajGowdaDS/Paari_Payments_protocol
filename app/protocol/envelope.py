"""Paari Protocol v1.0 wire envelope.

The envelope is the signed, replay-resistant transport container for every
protocol message. The signed bytes are canonical JSON of the envelope
without the signature field. Payloads themselves are also typed through the
message constructors in messages.py.
"""
from __future__ import annotations

import base64
import hashlib
import time
import uuid
from typing import Any

from app import crypto_utils

PROTOCOL = "paari"
VERSION = "1.0"
MAX_CLOCK_SKEW_SECONDS = 60
MAX_ENVELOPE_TTL_SECONDS = 300


def _b64(signature: bytes) -> str:
    return base64.b64encode(signature).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def sign_envelope(private_key_pem: str, type: str, headers: dict | None,
                  payload: dict, ttl_seconds: int = 120) -> dict:
    """Compatibility helper used by the reference client/tests. Agents sign
    the envelope with their private key; Paari never receives that key."""
    now = int(time.time())
    receiver = (headers or {}).get("receiver", "paari")
    sender = (headers or {}).get("sender", "agent")
    unsigned = {
        "protocol": PROTOCOL, "version": VERSION, "type": type,
        "message_id": str(uuid.uuid4()), "sender": sender, "receiver": receiver,
        "issued_at": now, "expires_at": now + int(ttl_seconds), "payload": payload,
    }
    sig = crypto_utils.sign_with_private_key(private_key_pem, crypto_utils.canonical_json(unsigned))
    return {**unsigned, "signature": sig}

def build_signed_envelope(*, type: str, sender: str, receiver: str,
                          payload: dict[str, Any], signature_b64: str,
                          message_id: str | None = None,
                          issued_at: int | None = None,
                          expires_at: int | None = None) -> dict:
    now = int(time.time()) if issued_at is None else int(issued_at)
    expiry = now + 120 if expires_at is None else int(expires_at)
    if expiry <= now or expiry - now > MAX_ENVELOPE_TTL_SECONDS:
        raise ValueError("invalid envelope expiry")
    return {
        "protocol": PROTOCOL,
        "version": VERSION,
        "type": type,
        "message_id": message_id or str(uuid.uuid4()),
        "sender": sender,
        "receiver": receiver,
        "issued_at": now,
        "expires_at": expiry,
        "payload": payload,
        "signature": signature_b64,
    }


def signing_bytes(envelope: dict) -> bytes:
    unsigned = {k: v for k, v in envelope.items() if k != "signature"}
    return crypto_utils.canonical_json(unsigned).encode("utf-8")


def verify_envelope(sender_public_key_pem: str, envelope: dict,
                    *, expected_receiver: str = "paari", now: int | None = None) -> bool:
    """Verify protocol, sender binding, freshness and Ed25519 signature."""
    if not isinstance(envelope, dict):
        return False
    required = {"protocol", "version", "type", "message_id", "sender",
                "receiver", "issued_at", "expires_at", "payload", "signature"}
    if not required.issubset(envelope):
        return False
    if envelope.get("protocol") != PROTOCOL or envelope.get("version") != VERSION:
        return False
    if expected_receiver and envelope.get("receiver") != expected_receiver:
        return False
    if not isinstance(envelope.get("payload"), dict):
        return False
    if not envelope.get("message_id") or not envelope.get("sender"):
        return False
    try:
        issued = int(envelope["issued_at"])
        expires = int(envelope["expires_at"])
    except (TypeError, ValueError):
        return False
    now_ts = int(time.time()) if now is None else int(now)
    if issued > now_ts + MAX_CLOCK_SKEW_SECONDS:
        return False
    if expires < now_ts - MAX_CLOCK_SKEW_SECONDS:
        return False
    if expires <= issued or expires - issued > MAX_ENVELOPE_TTL_SECONDS:
        return False
    signature_b64 = envelope.get("signature")
    if not isinstance(signature_b64, str):
        return False
    try:
        return crypto_utils.verify_signature(sender_public_key_pem, signing_bytes(envelope).decode("utf-8"), signature_b64)
    except Exception:
        return False


def envelope_fingerprint(envelope: dict) -> str:
    """Stable digest used for audit/correlation, not as an authority token."""
    return hashlib.sha256(signing_bytes(envelope)).hexdigest()
