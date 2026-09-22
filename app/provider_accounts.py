"""Strict per-organization provider routing.

A non-default tenant MUST have its own configured provider credentials. Paari
never silently falls back to another tenant's/default Razorpay account.
"""
import os
import re
from sqlalchemy.orm import Session
from app import models
from app.providers.razorpay import RazorpayAdapter, RazorpayConfigError


def _env_tag(org_id: str) -> str:
    return re.sub(r"\W", "", org_id).upper()


def get_provider_for_org(db: Session, org_id: str | None):
    resolved = org_id or "default"
    if resolved == "default":
        return RazorpayAdapter()
    acct = db.query(models.ProviderAccount).filter_by(org_id=resolved).first()
    if acct is None:
        raise RazorpayConfigError(f"No payment provider account is configured for organization {resolved}")
    tag = _env_tag(resolved)
    key_id = os.environ.get(f"RAZORPAY_KEY_ID__{tag}", "")
    key_secret = os.environ.get(f"RAZORPAY_KEY_SECRET__{tag}", "")
    webhook_secret = os.environ.get(f"RAZORPAY_WEBHOOK_SECRET__{tag}", "")
    if not key_id or not key_secret:
        raise RazorpayConfigError(f"Razorpay credentials are missing for organization {resolved}")
    if not webhook_secret:
        raise RazorpayConfigError(f"Razorpay webhook secret is missing for organization {resolved}")
    return RazorpayAdapter(key_id=key_id, key_secret=key_secret, webhook_secret=webhook_secret)
