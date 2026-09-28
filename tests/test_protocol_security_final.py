import base64
import time
from datetime import datetime, timezone, timedelta

import jwt
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from app.protocol.envelope import build_signed_envelope, signing_bytes, verify_envelope
from app.protocol.messages import MESSAGE_TYPES, make_message
from app import crypto_utils


def pem_pair():
    k = Ed25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    pub = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, pub


def test_envelope_roundtrip_and_tamper():
    priv, pub = pem_pair()
    now = int(time.time())
    unsigned = {"protocol": "paari", "version": "1.0", "type": "payment.intent", "message_id": "m1",
                "sender": "agent-1", "receiver": "paari", "issued_at": now, "expires_at": now + 60,
                "payload": {"amount_minor_units": 100}}
    sig = crypto_utils.sign_with_private_key(priv, crypto_utils.canonical_json(unsigned))
    env = build_signed_envelope(type=unsigned["type"], sender=unsigned["sender"], receiver="paari",
                                payload=unsigned["payload"], signature_b64=sig,
                                message_id="m1", issued_at=now, expires_at=now+60)
    assert verify_envelope(pub, env)
    env["payload"]["amount_minor_units"] = 101
    assert not verify_envelope(pub, env)


def test_envelope_rejects_old_or_future():
    priv, pub = pem_pair(); now = int(time.time())
    unsigned = {"protocol":"paari","version":"1.0","type":"payment.intent","message_id":"m1","sender":"agent","receiver":"paari","issued_at":now-1000,"expires_at":now-900,"payload":{}}
    sig=crypto_utils.sign_with_private_key(priv, crypto_utils.canonical_json(unsigned))
    env=build_signed_envelope(type=unsigned["type"],sender=unsigned["sender"],receiver="paari",payload={},signature_b64=sig,message_id="m1",issued_at=now-1000,expires_at=now-900)
    assert not verify_envelope(pub,env)
    assert len(MESSAGE_TYPES) >= 16


def test_message_constructor_rejects_unknown():
    try:
        make_message("no.such.type")
        assert False
    except ValueError:
        assert True
