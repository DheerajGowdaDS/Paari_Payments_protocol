def test_verify_webhook_signature_accepts_valid_hmac():
    import hashlib, hmac
    from app.providers.razorpay import verify_webhook_signature
    secret = "whsec_test"
    body = b'{"event":"payment.captured"}'
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert verify_webhook_signature(body, sig, secret) is True
    assert verify_webhook_signature(body, "0" * 64, secret) is False
