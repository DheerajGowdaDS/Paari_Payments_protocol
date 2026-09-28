"""User payment-mandate policy evaluation for Paari v2.

The mandate is deliberately separate from agent delegation:
- user/trusted-surface mandate = what the user allows the agent to spend;
- parent delegation = what the parent allows the agent to do;
- bounded authorization = what Paari allows for this exact transaction.

This module does not implement a payment-provider mandate. Provider-native
instrument/mandate integration remains behind app.providers.agentic and must
use provider-issued references/tokens rather than raw payment credentials.

Three invariants this module owns, each of which was previously violated:

1. LAPSED != NEVER-EXISTED. An expired or revoked mandate used to resolve to
   `None`, indistinguishable from "this agent never had a mandate" - so a
   lapsed spending cap silently became *no* cap and payments were ALLOWed with
   `reasons: ["all checks passed"]`. Resolution is now a tri-state
   (`MandateState`) and LAPSED fails closed in every mode.

2. TIGHTEST WINS. `active_mandate` used to order by `expires_at DESC`, which
   selected the longest-lived mandate regardless of its limits - so a broad
   long mandate silently overrode a narrow short one. All active mandates are
   now evaluated and the effective policy is their INTERSECTION.

3. WINDOWS ROLL. Budgets used to reset on calendar boundaries (UTC midnight /
   the top of the hour), which a caller could straddle to spend a full budget
   twice within seconds. Windows are now rolling and anchored to the mandate's
   own validity start.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Sequence

from sqlalchemy import func
from sqlalchemy.orm import Session

from app import models
from app.serialization import acquire_gate

HOUR = timedelta(hours=1)
DAY = timedelta(hours=24)


class MandateState(str, enum.Enum):
    """Tri-state result of resolving an agent's user payment authority."""
    NONE = "none"        # this agent never had a mandate
    LAPSED = "lapsed"    # a mandate existed but is expired/revoked/out-of-window
    ACTIVE = "active"    # at least one mandate is live and in-window


@dataclass(frozen=True)
class MandateDecision:
    ok: bool
    review: bool = False
    reasons: tuple[str, ...] = ()
    mandate: models.UserPaymentMandate | None = None
    state: MandateState = MandateState.NONE
    # Every active mandate that was evaluated, tightest first.
    evaluated: tuple[str, ...] = ()


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------

def _scope_query(db: Session, agent_id: str, org_id: str):
    return db.query(models.UserPaymentMandate).filter(
        models.UserPaymentMandate.agent_id == agent_id,
        models.UserPaymentMandate.org_id == org_id,
    )


def active_mandates(db: Session, *, agent_id: str, org_id: str,
                    now: datetime | None = None) -> list[models.UserPaymentMandate]:
    """Every live, in-window mandate for the agent, TIGHTEST FIRST.

    Ordered by ascending per-transaction cap, then ascending daily cap, then
    mandate_id for determinism. `found[0]` is the governing mandate;
    `evaluate_mandate` still enforces every mandate in the list, so ordering
    only decides which one is named in the audit trail.
    """
    now = now or _now()
    rows: Sequence[models.UserPaymentMandate] = (
        _scope_query(db, agent_id, org_id)
        .filter(
            models.UserPaymentMandate.status == models.MandateStatus.ACTIVE,
            models.UserPaymentMandate.valid_from <= now,
            models.UserPaymentMandate.expires_at > now,
        )
        .all()
    )
    return sorted(
        rows,
        key=lambda m: (m.max_per_transaction, m.max_daily_amount, m.mandate_id),
    )


def active_mandate(db: Session, *, agent_id: str, org_id: str,
                   now: datetime | None = None) -> models.UserPaymentMandate | None:
    """The governing (tightest) active mandate, or None. Prefer `resolve_state`
    + `evaluate_mandate`; this helper cannot express LAPSED."""
    found = active_mandates(db, agent_id=agent_id, org_id=org_id, now=now)
    return found[0] if found else None


def mandate_history_exists(db: Session, *, agent_id: str, org_id: str) -> bool:
    """True when this agent has EVER had a mandate, in any status.

    This is what separates MandateState.NONE from MandateState.LAPSED.
    """
    return _scope_query(db, agent_id, org_id).count() > 0


def resolve_state(db: Session, *, agent_id: str, org_id: str,
                  now: datetime | None = None) -> MandateState:
    """Tri-state resolution of the agent's user payment authority."""
    now = now or _now()
    if active_mandates(db, agent_id=agent_id, org_id=org_id, now=now):
        return MandateState.ACTIVE
    if mandate_history_exists(db, agent_id=agent_id, org_id=org_id):
        return MandateState.LAPSED
    return MandateState.NONE


# ---------------------------------------------------------------------------
# Spending aggregation (rolling windows, case-normalized dimensions)
# ---------------------------------------------------------------------------

def _window_start(now: datetime, delta: timedelta,
                  mandate: models.UserPaymentMandate) -> datetime:
    """Rolling window start, never earlier than the mandate's own validity
    start - a mandate must not be charged for spend that predates it."""
    start = now - delta
    if mandate.valid_from and mandate.valid_from > start:
        start = mandate.valid_from
    return start


def daily_spend(db: Session, mandate: models.UserPaymentMandate, now: datetime) -> int:
    """Non-denied intent amounts in the rolling 24h window (clamped to
    `valid_from`), narrowed to the mandate's org/agent/currency."""
    return _spend_since(db, mandate, _window_start(now, DAY, mandate), now)


def hourly_spend(db: Session, mandate: models.UserPaymentMandate, now: datetime) -> int:
    """Non-denied intent amounts in the rolling 1h window."""
    return _spend_since(db, mandate, _window_start(now, HOUR, mandate), now)


def merchant_daily_spend(db: Session, mandate: models.UserPaymentMandate, merchant: str,
                         now: datetime) -> int:
    """Rolling-24h non-denied spend for one merchant, case-normalized."""
    return _spend_since(db, mandate, _window_start(now, DAY, mandate), now,
                        merchant=merchant)


def category_daily_spend(db: Session, mandate: models.UserPaymentMandate,
                         merchant_category: str, now: datetime) -> int:
    """Rolling-24h non-denied spend for one category, case-normalized."""
    return _spend_since(db, mandate, _window_start(now, DAY, mandate), now,
                        merchant_category=merchant_category)


def _spend_since(db: Session, mandate: models.UserPaymentMandate, start: datetime,
                 now: datetime, *, merchant: str | None = None,
                 merchant_category: str | None = None) -> int:
    """Shared aggregation: non-denied intent amounts for (org, agent, currency)
    since `start`, optionally narrowed to one merchant or category.

    Denials never consume budget; ALLOW/REVIEW intents always do, which keeps
    a fast agent from racing many approvals between governance and settlement.

    Merchant and category are compared case-insensitively. The allowlists in
    `_check_one` are case-insensitive too, so a case-sensitive aggregation
    here let `AMAZON` and `amazon` each start a fresh per-merchant budget
    while both passing the same allowlist entry.
    """
    query = db.query(models.PaymentIntent.amount_minor_units).filter(
        models.PaymentIntent.org_id == mandate.org_id,
        models.PaymentIntent.agent_id == mandate.agent_id,
        models.PaymentIntent.created_at >= start,
        models.PaymentIntent.created_at <= now,
        models.PaymentIntent.decision != models.GovernanceDecision.DENY,
        models.PaymentIntent.currency == mandate.currency,
    )
    if merchant is not None:
        query = query.filter(
            func.lower(models.PaymentIntent.merchant) == merchant.casefold())
    if merchant_category is not None:
        query = query.filter(
            func.lower(models.PaymentIntent.merchant_category) == merchant_category.casefold())
    rows = query.all()
    return sum(int(amount or 0) for (amount,) in rows)


def acquire_mandate_serialization(db: Session, mandate_id: str,
                                  timeout_seconds: int = 5) -> bool:
    """Serialize concurrent mandate evaluations across workers.

    Two simultaneous intent submissions must not both pass a budget check
    against the same stale totals. All spending aggregation in
    evaluate_mandate runs while this gate is held, and the intent row (which
    carries the amount) commits on the same connection before the gate is
    released, so the next evaluator necessarily observes the earlier spend.

    Any pending work on the session is committed first: the gate must wrap a
    transaction that begins BEFORE the aggregation reads and ends AFTER the
    spend-record commit, so call this before performing writes you need
    atomic with the spend record.

    Returns True when the gate was acquired; False means 'do not evaluate
    now' (the caller must fail closed). The dialect-specific mechanics -
    SQLite BEGIN IMMEDIATE, Postgres pg_try_advisory_xact_lock, both committed
    under a sha256-derived signed-bigint key - live in app.serialization.
    """
    return acquire_gate(db, f"paari:mandate:{mandate_id}", timeout_seconds)


def acquire_all_mandate_gates(db: Session, mandate_ids: Sequence[str],
                              timeout_seconds: int = 5) -> bool:
    """Lock every active mandate in a stable (sorted) order.

    Sorted acquisition is deadlock-free when two requests contend on
    overlapping sets. All-or-nothing: any failure reports False so the caller
    denies rather than evaluating against partially-unlocked totals.
    """
    for mandate_id in sorted(set(mandate_ids)):
        if not acquire_mandate_serialization(db, mandate_id, timeout_seconds):
            return False
    return True


def release_mandate_serialization(db: Session) -> None:
    """Release the gate. SQLite: commit/rollback ends the immediate
    transaction. Postgres: the advisory lock is transaction-scoped, so this
    only needs to end the transaction - which the caller's commit/rollback
    does anyway. Kept as an explicit no-op hook for symmetry and future
    dialects."""
    return None


# ---------------------------------------------------------------------------
# Signature enforcement
# ---------------------------------------------------------------------------

def check_mandate_signature(mandate: models.UserPaymentMandate, *,
                            require_signed: bool) -> tuple[bool, tuple[str, ...]]:
    """Enforce the Ed25519 mandate signature in the AUTHORIZATION path.

    The signature used to be verified exactly once, at creation time, and
    never again - so it was write-once decoration and a direct DB edit could
    freely raise a *signed* mandate's limits. Now:

    - a mandate that CARRIES a signature must always verify (fail closed);
    - an unsigned mandate is rejected only when PAARI_REQUIRE_SIGNED_MANDATE=1,
      which preserves the legacy unsigned admin-bootstrap path.
    """
    if not mandate.signature_b64:
        if require_signed:
            return False, ("user payment mandate is unsigned and "
                           "PAARI_REQUIRE_SIGNED_MANDATE=1 requires a signed mandate",)
        return True, ()
    from app.mandate_signing import verify_mandate_signature
    result = verify_mandate_signature(mandate)
    if not result.signature_valid:
        return False, (f"user mandate signature verification failed: "
                       f"{'; '.join(result.reasons)}",)
    return True, ()


# ---------------------------------------------------------------------------
# Constraint evaluation
# ---------------------------------------------------------------------------

def _check_one(db: Session, mandate: models.UserPaymentMandate, *,
               merchant: str, amount_minor_units: int, currency: str,
               merchant_category: str | None, now: datetime,
               require_signed: bool) -> MandateDecision:
    """Evaluate one mandate against one proposed payment."""
    def deny(*reasons: str) -> MandateDecision:
        return MandateDecision(False, reasons=reasons, mandate=mandate,
                               state=MandateState.ACTIVE)

    ok, sig_reasons = check_mandate_signature(mandate, require_signed=require_signed)
    if not ok:
        return deny(*sig_reasons)

    if currency.upper() != mandate.currency.upper():
        return deny(f"currency {currency} does not match user mandate currency "
                    f"{mandate.currency}")

    if amount_minor_units > mandate.max_per_transaction:
        return deny(f"amount {amount_minor_units} exceeds user mandate "
                    f"per-transaction limit {mandate.max_per_transaction}")

    allowed_merchants = [str(x).casefold() for x in (mandate.allowed_merchants or [])]
    if allowed_merchants and merchant.casefold() not in allowed_merchants:
        return deny(f"merchant {merchant!r} is not permitted by the user mandate")

    allowed_categories = [str(x).casefold() for x in (mandate.allowed_categories or [])]
    if allowed_categories:
        if not merchant_category:
            return deny("merchant category is required by the user mandate")
        if merchant_category.casefold() not in allowed_categories:
            return deny(f"merchant category {merchant_category!r} is not permitted "
                        f"by the user mandate")

    # Sprint 6: finer-grained spending windows. NULL limit = not enforced.
    if mandate.max_per_hour is not None:
        hour_spent = hourly_spend(db, mandate, now=now)
        if amount_minor_units > mandate.max_per_hour - hour_spent:
            return deny(f"amount {amount_minor_units} exceeds remaining hourly "
                        f"mandate budget {max(mandate.max_per_hour - hour_spent, 0)}")

    remaining = mandate.max_daily_amount - daily_spend(db, mandate, now=now)
    if amount_minor_units > remaining:
        return deny(f"amount {amount_minor_units} exceeds remaining daily mandate "
                    f"budget {max(remaining, 0)}")

    if mandate.max_per_merchant_per_day is not None:
        spent = merchant_daily_spend(db, mandate, merchant, now=now)
        if amount_minor_units > mandate.max_per_merchant_per_day - spent:
            return deny(f"amount {amount_minor_units} exceeds remaining daily budget "
                        f"for merchant {merchant!r} "
                        f"({max(mandate.max_per_merchant_per_day - spent, 0)})")

    if mandate.max_category_per_day is not None:
        if not merchant_category:
            # Fail closed: a per-category budget cannot be enforced without
            # knowing the category, same rule as the category allowlist.
            return deny("merchant category is required by the user mandate "
                        "(per-category budget)")
        spent = category_daily_spend(db, mandate, merchant_category, now=now)
        if amount_minor_units > mandate.max_category_per_day - spent:
            return deny(f"amount {amount_minor_units} exceeds remaining daily budget "
                        f"for category {merchant_category!r} "
                        f"({max(mandate.max_category_per_day - spent, 0)})")

    if mandate.require_review_above is not None and amount_minor_units > mandate.require_review_above:
        return MandateDecision(
            True, review=True,
            reasons=(f"user mandate requires review above "
                     f"{mandate.require_review_above}; current amount "
                     f"{amount_minor_units}",),
            mandate=mandate, state=MandateState.ACTIVE)

    return MandateDecision(True, review=False, reasons=(
        "user mandate is active and all mandate constraints passed",
    ), mandate=mandate, state=MandateState.ACTIVE)


# ---------------------------------------------------------------------------
# Public evaluation entry point
# ---------------------------------------------------------------------------

_LAPSED_REASON = ("no active user payment mandate: a mandate exists for this agent but "
                  "it has expired, been revoked, or is outside its validity window")


def evaluate_mandate(
    db: Session,
    *,
    agent: models.Agent,
    merchant: str,
    amount_minor_units: int,
    currency: str,
    merchant_category: str | None = None,
    now: datetime | None = None,
    require_signed: bool = False,
) -> MandateDecision:
    """Resolve and enforce the agent's user payment authority.

    The returned `state` is authoritative for the caller:
    - `LAPSED` means a mandate existed and is no longer spendable. The caller
      MUST deny in EVERY mode. Silently continuing (the old behaviour) turned
      an expired spending cap into no cap at all, and the payment was ALLOWed
      with `reasons: ["all checks passed"]` and a null mandate_id.
    - `NONE` means the agent never had a mandate; only `mandate_required`
      mode denies.
    """
    now = now or _now()

    active = active_mandates(db, agent_id=agent.agent_id, org_id=agent.org_id, now=now)
    if not active:
        lapsed = mandate_history_exists(db, agent_id=agent.agent_id, org_id=agent.org_id)
        return MandateDecision(
            False,
            reasons=(_LAPSED_REASON,) if lapsed else ("no active user payment mandate",),
            state=MandateState.LAPSED if lapsed else MandateState.NONE,
        )

    # Serialize the aggregation window across EVERY active mandate:
    # concurrent submissions must not both pass on stale totals. Re-resolve
    # under the gate in case a mandate was revoked/expired in between.
    if not acquire_all_mandate_gates(db, [m.mandate_id for m in active]):
        return MandateDecision(
            False,
            reasons=("mandate evaluation is contended; retry the request",),
            mandate=active[0], state=MandateState.ACTIVE)

    active = active_mandates(db, agent_id=agent.agent_id, org_id=agent.org_id, now=now)
    if not active:
        return MandateDecision(False, reasons=(_LAPSED_REASON,),
                               state=MandateState.LAPSED)

    evaluated = tuple(m.mandate_id for m in active)
    decisions = [
        _check_one(db, m, merchant=merchant, amount_minor_units=amount_minor_units,
                   currency=currency, merchant_category=merchant_category, now=now,
                   require_signed=require_signed)
        for m in active
    ]
    # Intersection semantics: EVERY active mandate must permit the payment, so
    # the effective policy is the tightest one. A broad long-dated mandate can
    # never widen a narrow one (it used to, via expires_at DESC ordering).
    for decision in decisions:
        if not decision.ok:
            return MandateDecision(False, reasons=decision.reasons,
                                   mandate=decision.mandate,
                                   state=MandateState.ACTIVE, evaluated=evaluated)
    review_reasons = tuple(r for d in decisions if d.review for r in d.reasons)
    if review_reasons:
        return MandateDecision(True, review=True, reasons=review_reasons,
                               mandate=active[0], state=MandateState.ACTIVE,
                               evaluated=evaluated)
    return MandateDecision(
        True, review=False,
        reasons=("user mandate is active and all mandate constraints passed",),
        mandate=active[0], state=MandateState.ACTIVE, evaluated=evaluated)


# ---------------------------------------------------------------------------
# Lifecycle sweepers
# ---------------------------------------------------------------------------

def sweep_expired_mandates(db: Session, now: datetime | None = None) -> int:
    """Transition ACTIVE mandates past `expires_at` to EXPIRED.

    `MandateStatus.EXPIRED` used to be an unreachable enum member: expiry was
    inferred from the clock at read time only, so the lifecycle was never
    recorded. Recording it makes expiry explicit and auditable. Resolving to
    LAPSED does NOT depend on this having run - it is belt and braces behind
    the tri-state check.
    """
    from app.audit import record_audit
    now = now or _now()
    rows = (
        db.query(models.UserPaymentMandate)
        .filter(models.UserPaymentMandate.status == models.MandateStatus.ACTIVE,
                models.UserPaymentMandate.expires_at <= now)
        .all()
    )
    for mandate in rows:
        mandate.status = models.MandateStatus.EXPIRED
        record_audit(db, transaction_id=f"mandate:{mandate.mandate_id}",
                     agent_id=mandate.agent_id, parent_id=None,
                     kind="user_mandate_expired",
                     detail={"mandate_id": mandate.mandate_id,
                             "expired_at": mandate.expires_at.isoformat()},
                     org_id=mandate.org_id)
    if rows:
        db.commit()
    return len(rows)


def expire_stale_reviews(db: Session, now: datetime | None = None) -> int:
    """Move parked REVIEW intents past `review_expires_at` to DENY.

    `_spend_since` counts every non-DENY intent against the mandate budget, so
    a velocity-parked intent that is never step-up approved used to consume
    budget for the rest of the window with no recovery path - a user could lock
    themselves out of their own agent. Denying on expiry releases the
    reservation. Nothing read `review_expires_at` before this.
    """
    from app.audit import record_audit
    now = now or _now()
    rows = (
        db.query(models.PaymentIntent)
        .filter(
            models.PaymentIntent.decision == models.GovernanceDecision.REVIEW,
            models.PaymentIntent.review_expires_at.isnot(None),
            models.PaymentIntent.review_expires_at <= now,
        )
        .all()
    )
    for intent in rows:
        intent.decision = models.GovernanceDecision.DENY
        intent.reasons = list(intent.reasons or []) + [
            "review window expired without step-up approval; budget reservation released"]
        record_audit(db, transaction_id=intent.transaction_id, agent_id=intent.agent_id,
                     parent_id=None, kind="intent_review_expired",
                     detail={"intent_id": intent.intent_id,
                             "previous_state": "review", "current_state": "deny",
                             "review_expires_at": intent.review_expires_at.isoformat()},
                     org_id=intent.org_id)
    if rows:
        db.commit()
    return len(rows)


def run_sweepers(db: Session, now: datetime | None = None) -> dict:
    """Run both lifecycle sweepers. Safe for a maintenance job or admin
    endpoint; both are idempotent."""
    return {
        "expired_mandates": sweep_expired_mandates(db, now=now),
        "expired_reviews": expire_stale_reviews(db, now=now),
    }
