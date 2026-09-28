"""Cryptographic primitives for an external Paari v1 agent.

This package intentionally has no dependency on the Paari server's ``app``
modules. An independent agent can use it as the protocol reference client.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PROTOCOL = "paari"
VERSION = "1.0"


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def generate_keypair() -> tuple[str, str]:
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


def fingerprint(public_key_pem: str) -> str:
    return hashlib.sha256(public_key_pem.encode("utf-8")).hexdigest()


def sign_text(private_key_pem: str, text: str) -> str:
    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    return base64.b64encode(key.sign(text.encode("utf-8"))).decode("ascii")


def sign_delegation(private_key_pem: str, delegation: dict[str, Any]) -> str:
    return sign_text(private_key_pem, canonical_json(delegation))


def build_envelope(private_key_pem: str, *, sender: str, payload: dict[str, Any], message_type: str,
                   ttl_seconds: int = 120, receiver: str = "paari") -> dict[str, Any]:
    now = int(time.time())
    if ttl_seconds <= 0 or ttl_seconds > 300:
        raise ValueError("ttl_seconds must be between 1 and 300")
    envelope = {
        "protocol": PROTOCOL,
        "version": VERSION,
        "type": message_type,
        "message_id": str(uuid.uuid4()),
        "sender": sender,
        "receiver": receiver,
        "issued_at": now,
        "expires_at": now + ttl_seconds,
        "payload": payload,
    }
    envelope["signature"] = sign_text(private_key_pem, canonical_json(envelope))
    return envelope


def build_request_proof(private_key_pem: str, *, agent_id: str, access_token: str,
                        method: str, path: str, jti: str | None = None,
                        issued_at: int | None = None) -> str:
    issued = int(time.time()) if issued_at is None else int(issued_at)
    ath = base64.urlsafe_b64encode(hashlib.sha256(access_token.encode()).digest()).rstrip(b"=").decode()
    claims = {
        "typ": "paari-proof",
        "alg": "EdDSA",
        "sub": agent_id,
        "htm": method.upper(),
        "htu": path,
        "iat": issued,
        "jti": jti or str(uuid.uuid4()),
        "ath": ath,
    }
    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    header = {"alg": "EdDSA", "typ": "paari-proof+jwt", "kid": "agent"}
    return jwt.encode(claims, key, algorithm="EdDSA", headers=header)


def verify_paari_card(card: dict[str, Any]) -> bool:
    """Verify a Paari-signed Agent Card using the key embedded in the card."""
    signature = card.get("card_signature_b64", "")
    paari_public = card.get("paari_public_key_pem", "")
    if not signature or not paari_public:
        return False
    signed_fields = {k: v for k, v in card.items() if k not in {"card_signature_b64", "paari_public_key_pem"}}
    try:
        key = serialization.load_pem_public_key(paari_public.encode())
        key.verify(base64.b64decode(signature, validate=True), canonical_json(signed_fields).encode())
        return True
    except Exception:
        return False
