"""Environment profiles and the single source of truth for governance posture.

The mandate posture used to be defined in three places at once (a dead
`_mandate_mode()` in routers/v1.py, an inline re-implementation in
routers/payments.py, and a `require_user_payment_mandate` key in load_config
that nothing read). Any of them could drift and the failure direction was
always fail-OPEN: a typo in PAARI_MODE silently downgraded "mandate required"
to "mandate optional".

`mandate_policy()` is now the only definition. It is validated against a
literal set of modes, it is read per call (tests monkeypatch the environment
after import), and an unrecognised value raises instead of degrading.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum

from fastapi import HTTPException

from app.database import resolve_database_url


class PaariEnv(StrEnum):
    SANDBOX = "sandbox"
    PROD = "prod"
    PROD_LIVE = "prod-live"
    TEST = "test"


class MandateMode(StrEnum):
    """standard    - legacy v1 behaviour: a mandate is enforced whenever one
                    exists, but its absence does not block a payment.
    autonomous   - the posture for autonomous-agent settlement: an active,
                    valid user mandate is REQUIRED for every payment intent."""
    STANDARD = "standard"
    AUTONOMOUS = "autonomous"


_VALID_MODES = {m.value for m in MandateMode}


@dataclass(frozen=True)
class MandatePolicy:
    mode: MandateMode
    require_signed_mandate: bool

    @property
    def mandate_required(self) -> bool:
        return self.mode is MandateMode.AUTONOMOUS


def mandate_policy() -> MandatePolicy:
    """Resolve the governance posture. Raises on an unknown PAARI_MODE rather
    than silently falling back to `standard` (which would make the mandate
    optional - the fail-open direction)."""
    raw = os.environ.get("PAARI_MODE", MandateMode.STANDARD.value).strip().lower()
    if raw not in _VALID_MODES:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Invalid PAARI_MODE {raw!r}; expected one of {sorted(_VALID_MODES)}. "
                "Refusing to start with an ambiguous governance posture."
            ),
        )
    mode = MandateMode(raw)
    # PAARI_REQUIRE_USER_MANDATE=1 is the legacy alias for autonomous mode and
    # is still honoured; it can only ever *strengthen* enforcement.
    if os.environ.get("PAARI_REQUIRE_USER_MANDATE") == "1" and mode is MandateMode.STANDARD:
        mode = MandateMode.AUTONOMOUS
    return MandatePolicy(
        mode=mode,
        require_signed_mandate=os.environ.get("PAARI_REQUIRE_SIGNED_MANDATE") == "1",
    )


def load_config() -> dict:
    env = PaariEnv(os.environ.get("PAARI_ENV", "sandbox"))
    is_live = os.environ.get("PAARI_LIVE") == "1"
    database_url = resolve_database_url()
    required = [
        "RAZORPAY_KEY_ID",
        "RAZORPAY_KEY_SECRET",
        "RAZORPAY_WEBHOOK_SECRET",
        "PAARI_ADMIN_API_KEY",
        "PAARI_SIGNING_KEY_PATH",
    ]
    if env not in (PaariEnv.SANDBOX, PaariEnv.TEST) or is_live:
        missing = [k for k in required if not os.environ.get(k)]
        if not database_url:
            missing.append("DATABASE_URL (or PAARI_DATABASE_URL)")
        if missing:
            raise RuntimeError(
                f"{'PAARI_LIVE=1' if is_live else env.value} requires {', '.join(missing)}"
            )
    api_base = os.environ.get("RAZORPAY_API_BASE", "")
    if env in (PaariEnv.SANDBOX, PaariEnv.TEST) and not api_base:
        os.environ.setdefault("RAZORPAY_API_BASE", "https://api.razorpay.com/v1")
    policy = mandate_policy()
    return {
        "env": env,
        "is_live": is_live,
        "database_url": database_url,
        # Surfaced on /health so an operator can see the active posture
        # instead of having to infer it from the environment.
        "mandate_mode": policy.mode.value,
        "mandate_required": policy.mandate_required,
        "require_signed_mandate": policy.require_signed_mandate,
    }
