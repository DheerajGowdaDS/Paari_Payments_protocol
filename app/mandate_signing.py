"""Paari v2 Sprint 5: cryptographically signed user payment mandates.

A mandate stops being a database row and becomes a portable authorization
artifact:

    UserPaymentMandate
        -> canonical JSON payload (signature excluded)
        -> Ed25519 signature by the user's / trusted surface's key
        -> verifiable offline

The same primitives used for parent delegations are reused:
crypto_utils.canonical_json / sign_with_private_key / verify_signature /
public_key_fingerprint. The canonical payload excludes the signature itself,
and the signer signs exactly the bytes canonical_json produces.

Verification is fail-closed: an unsigned mandate verifies as False, a valid
signature does NOT make an expired or revoked mandate valid, and signature
validity is independent of mandate status (the caller must check both).
"""
from __future__ import annotations

from dataclasses import dataclass

from app import crypto_utils, models


@dataclass(frozen=True)
class MandateSignatureResult:
    signature_valid: bool
    reasons: tuple[str, ...] = ()


def mandate_payload(mandate: models.UserPaymentMandate) -> dict:
    """The exact canonical structure the user key signs.

    issued_at/expires_at are epoch seconds (matching the delegation
    document convention: ints round-trip through JSON byte-for-byte).
    The signature fields themselves are deliberately excluded - the
    signer signs this payload, not the result of signing it.
    """
    return {
        "purpose": "paari_user_payment_mandate",
        "mandate_version": 1,
        "mandate_id": mandate.mandate_id,
        "user_id": mandate.user_id,
        "agent_id": mandate.agent_id,
        "org_id": mandate.org_id,
        "constraints": {
            "currency": mandate.currency,
            "max_per_transaction": int(mandate.max_per_transaction),
            "max_daily_amount": int(mandate.max_daily_amount),
            "max_per_hour": (int(mandate.max_per_hour) if mandate.max_per_hour is not None else None),
            "max_per_merchant_per_day": (
                int(mandate.max_per_merchant_per_day)
                if mandate.max_per_merchant_per_day is not None else None
            ),
            "max_category_per_day": (
                int(mandate.max_category_per_day)
                if mandate.max_category_per_day is not None else None
            ),
            "allowed_merchants": sorted(str(m) for m in (mandate.allowed_merchants or [])),
            "allowed_categories": sorted(str(c) for c in (mandate.allowed_categories or [])),
            "require_review_above": (
                int(mandate.require_review_above)
                if mandate.require_review_above is not None else None
            ),
        },
        "issued_at": (int(mandate.valid_from.timestamp()) if mandate.valid_from else
                      (int(mandate.created_at.timestamp()) if mandate.created_at else None)),
        "expires_at": int(mandate.expires_at.timestamp()) if mandate.expires_at else None,
    }


def canonical_payload_bytes(mandate: models.UserPaymentMandate) -> str:
    """The exact string the user's key signs over."""
    return crypto_utils.canonical_json(mandate_payload(mandate))


def sign_mandate(mandate: models.UserPaymentMandate, user_private_key_pem: str,
                 *, signing_key_id: str = "user-key-1") -> str:
    """Trusted-surface side: produce the signature to store on the mandate.

    Mutates the mandate in place (signing_key_id / signature_b64 / the
    signer public key / signed_at) so the stored row carries its own
    verification material without a second table.
    """
    from datetime import datetime, timezone

    payload = canonical_payload_bytes(mandate)
    signature_b64 = crypto_utils.sign_with_private_key(user_private_key_pem, payload)
    public_key_pem = _public_pem_from_private(user_private_key_pem)
    mandate.signing_key_id = signing_key_id
    mandate.signature_b64 = signature_b64
    mandate.user_public_key_pem = public_key_pem
    mandate.signed_at = datetime.now(timezone.utc)
    return signature_b64


def verify_mandate_signature(mandate: models.UserPaymentMandate) -> MandateSignatureResult:
    """Recompute the payload from the stored row and verify the signature.

    Signature validity says nothing about mandate liveness: an expired or
    revoked mandate with a valid signature is still not spendable. Callers
    must combine this result with the status/window checks in
    app.mandates.evaluate_mandate.
    """
    if not mandate.signature_b64:
        return MandateSignatureResult(False, reasons=("mandate is unsigned",))
    if not mandate.user_public_key_pem:
        return MandateSignatureResult(False, reasons=("mandate has no stored signer public key",))
    recomputed = canonical_payload_bytes(mandate)
    if crypto_utils.verify_signature(mandate.user_public_key_pem, recomputed, mandate.signature_b64):
        return MandateSignatureResult(True)
    return MandateSignatureResult(False, reasons=("mandate signature verification failed",))


def _public_pem_from_private(private_pem: str) -> str:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
