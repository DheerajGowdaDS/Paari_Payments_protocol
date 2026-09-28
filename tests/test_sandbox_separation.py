"""Task F1: sandbox/prod env profiles with required-secret guards."""
import os

import pytest


def test_sandbox_allows_missing_secrets(monkeypatch):
    monkeypatch.setenv("PAARI_ENV", "sandbox")
    for key in [
        "RAZORPAY_KEY_ID",
        "RAZORPAY_KEY_SECRET",
        "RAZORPAY_WEBHOOK_SECRET",
        "PAARI_ADMIN_API_KEY",
        "PAARI_SIGNING_KEY_PATH",
        "DATABASE_URL",
    ]:
        monkeypatch.delenv(key, raising=False)
    from app.config import load_config

    cfg = load_config()
    assert cfg["env"].value == "sandbox"


def test_prod_requires_all_secrets(monkeypatch):
    monkeypatch.delenv("PAARI_LIVE", raising=False)
    monkeypatch.setenv("PAARI_ENV", "prod")
    for key in [
        "RAZORPAY_KEY_ID",
        "RAZORPAY_KEY_SECRET",
        "RAZORPAY_WEBHOOK_SECRET",
        "PAARI_ADMIN_API_KEY",
        "PAARI_SIGNING_KEY_PATH",
        "DATABASE_URL",
    ]:
        monkeypatch.delenv(key, raising=False)
    from app.config import load_config

    with pytest.raises(RuntimeError, match="prod"):
        load_config()
