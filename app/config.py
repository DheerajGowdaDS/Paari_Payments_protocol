"""Environment profiles for Paari."""
from __future__ import annotations

import os
from enum import StrEnum


class PaariEnv(StrEnum):
    SANDBOX = "sandbox"
    PROD = "prod"
    PROD_LIVE = "prod-live"


def load_config() -> dict:
    env = PaariEnv(os.environ.get("PAARI_ENV", "sandbox"))
    is_live = os.environ.get("PAARI_LIVE") == "1"
    required = [
        "RAZORPAY_KEY_ID",
        "RAZORPAY_KEY_SECRET",
        "RAZORPAY_WEBHOOK_SECRET",
        "PAARI_ADMIN_API_KEY",
        "PAARI_SIGNING_KEY_PATH",
        "DATABASE_URL",
    ]
    if env != PaariEnv.SANDBOX or is_live:
        missing = [k for k in required if not os.environ.get(k)]
        if missing:
            raise RuntimeError(
                f"{'PAARI_LIVE=1' if is_live else env.value} requires {', '.join(missing)}"
            )
    api_base = os.environ.get("RAZORPAY_API_BASE", "")
    if env == PaariEnv.SANDBOX and not api_base:
        os.environ.setdefault("RAZORPAY_API_BASE", "https://api.razorpay.com/v1")
    return {
        "env": env,
        "is_live": is_live,
        "database_url": os.environ.get("DATABASE_URL", "sqlite:///./paari.db"),
    }
