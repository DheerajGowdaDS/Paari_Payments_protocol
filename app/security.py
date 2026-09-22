"""Paari signing, credentials, sender-constrained sessions and admin auth."""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Header, HTTPException
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from app import crypto_utils

_KEY_PATH = os.environ.get("PAARI_SIGNING_KEY_PATH", "paari_signing_key.pem")
CREDENTIAL_TTL = timedelta(days=90)
SESSION_TOKEN_TTL = timedelta(minutes=15)
CHALLENGE_NONCE_TTL = timedelta(minutes=2)
BOUNDED_AUTHORIZATION_TTL = timedelta(minutes=2)
MFA_CHALLENGE_TTL = timedelta(minutes=5)
REQUEST_PROOF_TTL = timedelta(seconds=90)
CLOCK_SKEW_LEEWAY_SECONDS = 60
ISSUER = "paari"
AUDIENCE = "paari-payment"


def _load_or_create_signing_key() -> Ed25519PrivateKey:
    if os.path.exists(_KEY_PATH):
        with open(_KEY_PATH, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    if os.environ.get("PAARI_LIVE") == "1" and not os.environ.get("PAARI_SIGNING_KEY_PATH"):
        raise RuntimeError("PAARI_LIVE=1 requires PAARI_SIGNING_KEY_PATH")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    parent = os.path.dirname(os.path.abspath(_KEY_PATH))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(_KEY_PATH, "wb") as f:
        f.write(pem)
    try:
        os.chmod(_KEY_PATH, 0o600)
    except OSError:
        pass
    return key


_signing_key = _load_or_create_signing_key()
_private_pem = _signing_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
_public_pem = _signing_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def paari_public_key_pem() -> str:
    return _public_pem


def issue_credential_jwt(agent_id: str, capabilities: list[str], payment_limit: int, currency: str, *, protocol_version: str = "1.0") -> tuple[str, str, datetime]:
    credential_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires_at = now + CREDENTIAL_TTL
    payload = {
        "iss": ISSUER, "aud": AUDIENCE, "sub": agent_id, "jti": credential_id,
        "iat": int(now.timestamp()), "exp": int(expires_at.timestamp()),
        "typ": "paari_credential", "protocol_version": protocol_version,
        "capabilities": list(capabilities), "payment_limit_minor_units": int(payment_limit), "currency": currency,
    }
    token = jwt.encode(payload, _private_pem, algorithm="EdDSA", headers={"kid": "paari-1"})
    return token, credential_id, expires_at


def decode_credential_jwt(token: str) -> dict:
    claims = jwt.decode(token, _public_pem, algorithms=["EdDSA"], issuer=ISSUER,
                        audience=AUDIENCE, leeway=CLOCK_SKEW_LEEWAY_SECONDS,
                        options={"require": ["iss", "aud", "sub", "jti", "iat", "exp"]})
    if claims.get("typ") != "paari_credential":
        raise jwt.InvalidTokenError("wrong token type")
    return claims


def issue_session_token(agent_id: str, credential_id: str, capabilities: list[str], payment_limit: int,
                        *, key_fingerprint: str = "", protocol_version: str = "1.0") -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    expires_at = now + SESSION_TOKEN_TTL
    payload = {
        "iss": ISSUER, "aud": AUDIENCE, "sub": agent_id, "jti": str(uuid.uuid4()),
        "credential_id": credential_id, "iat": int(now.timestamp()), "exp": int(expires_at.timestamp()),
        "typ": "paari_session", "protocol_version": protocol_version,
        "capabilities": list(capabilities), "payment_limit_minor_units": int(payment_limit),
        "cnf": {"jkt": key_fingerprint} if key_fingerprint else {},
    }
    token = jwt.encode(payload, _private_pem, algorithm="EdDSA", headers={"kid": "paari-1"})
    return token, expires_at


def decode_session_token(token: str) -> dict:
    claims = jwt.decode(token, _public_pem, algorithms=["EdDSA"], issuer=ISSUER,
                        audience=AUDIENCE, leeway=CLOCK_SKEW_LEEWAY_SECONDS,
                        options={"require": ["iss", "aud", "sub", "jti", "iat", "exp"]})
    if claims.get("typ") != "paari_session":
        raise jwt.InvalidTokenError("wrong token type")
    return claims


def issue_bounded_authorization_jwt(authorization_id: str, agent_id: str, intent_id: str,
                                    transaction_id: str, merchant: str, amount_minor_units: int,
                                    currency: str) -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    expires_at = now + BOUNDED_AUTHORIZATION_TTL
    payload = {
        "iss": ISSUER, "aud": AUDIENCE, "sub": agent_id, "jti": authorization_id,
        "iat": int(now.timestamp()), "exp": int(expires_at.timestamp()),
        "typ": "paari_bounded_authorization", "intent_id": intent_id,
        "transaction_id": transaction_id, "merchant": merchant,
        "amount_minor_units": int(amount_minor_units), "currency": currency, "max_usage": 1,
    }
    token = jwt.encode(payload, _private_pem, algorithm="EdDSA", headers={"kid": "paari-1"})
    return token, expires_at


def decode_bounded_authorization_jwt(token: str) -> dict:
    claims = jwt.decode(token, _public_pem, algorithms=["EdDSA"], issuer=ISSUER,
                        audience=AUDIENCE, leeway=CLOCK_SKEW_LEEWAY_SECONDS,
                        options={"require": ["iss", "aud", "sub", "jti", "iat", "exp"]})
    if claims.get("typ") != "paari_bounded_authorization":
        raise jwt.InvalidTokenError("wrong token type")
    return claims


def sign_agent_card(card_fields: dict) -> str:
    return base64.b64encode(_signing_key.sign(crypto_utils.canonical_json(card_fields).encode())).decode("ascii")


def verify_agent_card(card_fields: dict, signature_b64: str) -> bool:
    return crypto_utils.verify_signature(_public_pem, crypto_utils.canonical_json(card_fields), signature_b64)


def request_proof_payload(*, method: str, path: str, access_token: str, agent_id: str,
                          jti: str, issued_at: int) -> dict:
    token_hash = hashlib.sha256(access_token.encode("utf-8")).digest()
    ath = base64.urlsafe_b64encode(token_hash).rstrip(b"=").decode("ascii")
    return {"typ": "paari-proof", "alg": "EdDSA", "sub": agent_id, "htm": method.upper(),
            "htu": path, "iat": int(issued_at), "jti": jti, "ath": ath}


def encode_request_proof(private_key_pem: str, *, method: str, path: str, access_token: str,
                         agent_id: str, jti: str, issued_at: int | None = None) -> str:
    issued = int(datetime.now(timezone.utc).timestamp()) if issued_at is None else int(issued_at)
    payload = request_proof_payload(method=method, path=path, access_token=access_token,
                                    agent_id=agent_id, jti=jti, issued_at=issued)
    return jwt.encode(payload, private_key_pem, algorithm="EdDSA", headers={"typ": "paari-proof+jwt", "kid": "agent"})


def verify_request_proof(proof_jwt: str, access_token: str, *, agent_id: str, public_key_pem: str,
                         method: str, path: str, db=None, org_id: str | None = None) -> dict:
    """Verify a DPoP-inspired Paari proof and burn its jti in the DB when
    a RequestProof model/session is supplied. Proofs are sender-constrained
    to the session token and exact HTTP method/path."""
    header = jwt.get_unverified_header(proof_jwt)
    if header.get("alg") != "EdDSA":
        raise jwt.InvalidTokenError("unsupported proof algorithm")
    claims = jwt.decode(proof_jwt, public_key_pem, algorithms=["EdDSA"], options={"verify_aud": False})
    if claims.get("typ") != "paari-proof" or claims.get("sub") != agent_id:
        raise jwt.InvalidTokenError("invalid proof identity/type")
    now = int(datetime.now(timezone.utc).timestamp())
    iat = int(claims.get("iat", 0))
    if abs(now - iat) > int(REQUEST_PROOF_TTL.total_seconds()) + CLOCK_SKEW_LEEWAY_SECONDS:
        raise jwt.InvalidTokenError("proof too old or too far in the future")
    if claims.get("htm") != method.upper() or claims.get("htu") != path:
        raise jwt.InvalidTokenError("proof is not bound to this request")
    expected_ath = base64.urlsafe_b64encode(hashlib.sha256(access_token.encode("utf-8")).digest()).rstrip(b"=").decode("ascii")
    if not secrets.compare_digest(str(claims.get("ath", "")), expected_ath):
        raise jwt.InvalidTokenError("proof is not bound to this session token")
    jti = claims.get("jti")
    if not jti:
        raise jwt.InvalidTokenError("proof missing jti")
    if db is not None:
        from app import models
        existing = db.query(models.RequestProof).filter_by(jti=jti).first()
        if existing is not None:
            raise jwt.InvalidTokenError("request proof replayed")
        db.add(models.RequestProof(jti=jti, agent_id=agent_id, org_id=org_id or "default",
                                   issued_at=datetime.fromtimestamp(iat, tz=timezone.utc),
                                   expires_at=datetime.fromtimestamp(iat, tz=timezone.utc) + REQUEST_PROOF_TTL))
        db.flush()
    return claims


_ADMIN_API_KEY = os.environ.get("PAARI_ADMIN_API_KEY")
if not _ADMIN_API_KEY:
    _ADMIN_API_KEY = secrets.token_urlsafe(32)
    print("PAARI_ADMIN_API_KEY not set; using an ephemeral development key for this process.")


def is_admin_key(candidate: str) -> bool:
    return bool(candidate) and secrets.compare_digest(candidate, _ADMIN_API_KEY)


def require_admin(x_admin_api_key: str = Header(default="")) -> None:
    if not is_admin_key(x_admin_api_key):
        raise HTTPException(status_code=401, detail="Missing or invalid admin credentials")


def require_admin_org(x_admin_api_key: str, target_org: str | None) -> None:
    if not is_admin_key(x_admin_api_key):
        raise HTTPException(status_code=401, detail="Missing or invalid admin credentials")
    bound_org = os.environ.get("PAARI_ADMIN_ORG", "")
    if bound_org and bound_org != (target_org or ""):
        raise HTTPException(status_code=403, detail="Admin key is not authorized for this organization")
