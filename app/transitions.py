"""Central transition table for ProviderTransaction.state.

Every state change in the codebase must go through transition_txn - the
table below is the whole machine, so illegal jumps (including a PAID
regression or an AUTHORIZED skip straight to PAID) fail loudly instead of
silently corrupting execution state.

Phase 9: the plan's vocabulary is now the implementation's vocabulary
---------------------------------------------------------------
The v2 plan asked for AUTHORIZED -> PROVIDER_SUBMITTED -> PROVIDER_AUTHORIZED
-> CAPTURED -> PAID so that "the provider authorised", "the provider captured"
and "Paari confirms settlement" could never be collapsed into one word. Those
states used to be argued away on the grounds that a provider might never send
an intermediate signal.

That argument is now dead, not because anyone conceded it but because a live
Razorpay Test-Mode settlement delivered BOTH events, separately and each with
its own valid HMAC signature:

    payment.authorized   PROVIDER_SUBMITTED -> PROVIDER_AUTHORIZED
    payment.captured     PROVIDER_AUTHORIZED -> CAPTURED -> PAID

So the distinction is observable in the wire data and the states are real.
`PAYMENT_PENDING` is retired in favour of `PROVIDER_AUTHORIZED` (migration
c3d4e5f6a7b8 rewrites existing rows); a provider that sends only
`payment.captured` still lands legally, because PROVIDER_SUBMITTED -> CAPTURED
is a permitted edge.

What PAID now means
-------------------
A signed webhook is provider *attestation of an event*. PAID is Paari's own
terminal confirmation, and reaching it requires the capture to be corroborated
by an independent read of the provider's API. `payment.captured` therefore
moves the row to CAPTURED, and PAID follows only when
`app.reconcile.confirm_capture` agrees. If that read cannot be made - provider
unreachable, no such method, transient error - the row stays CAPTURED and the
reconciliation worker promotes it later. A payment is never marked settled on
evidence Paari could not double-check, and nothing is lost by waiting:
CAPTURED is non-terminal precisely so the reconciler keeps working on it.

Consequently the webhook handler cannot mint PAID at all. That is enforced in
`app/routers/payments.py` and pinned by tests, because the graph alone cannot
express it: PROVIDER_SUBMITTED/PAYMENT_PENDING/PROVIDER_UNKNOWN -> PAID edges
exist for the *reconciliation* path, which is the corroborating read.
"""

TRANSITION_TABLE = {
    # Pre-provider exits: the authorization can die before any provider
    # object exists.
    "AUTHORIZED": ("PROVIDER_SUBMITTED", "FAILED", "PROVIDER_UNKNOWN", "EXPIRED", "CANCELLED"),
    # A provider object now exists. PAID is reachable from here only through
    # reconciliation of a missed webhook, never from the webhook handler.
    "PROVIDER_SUBMITTED": ("PROVIDER_AUTHORIZED", "CAPTURED", "PAID",
                           "FAILED", "DECLINED", "PROVIDER_UNKNOWN"),
    # Provider authorised; money is not yet captured and can still fail.
    "PROVIDER_AUTHORIZED": ("CAPTURED", "PAID", "FAILED", "DECLINED", "PROVIDER_UNKNOWN"),
    # Captured but not yet corroborated. Non-terminal by design: this is the
    # state the reconciliation worker is for.
    # PROVIDER_UNKNOWN is reachable from here when the provider later denies
    # the capture it announced - an indeterminate money state, not a failure.
    "CAPTURED": ("PAID", "PROVIDER_UNKNOWN"),
    # Legacy spelling, kept so a row written before migration c3d4e5f6a7b8, or
    # an out-of-order webhook replay, still has a legal exit. New code writes
    # PROVIDER_AUTHORIZED instead.
    "PAYMENT_PENDING": ("CAPTURED", "PAID", "FAILED", "DECLINED", "PROVIDER_UNKNOWN"),
    # Timeouts resolve late: the order may still exist provider-side.
    "PROVIDER_UNKNOWN": ("PROVIDER_AUTHORIZED", "CAPTURED", "PAID",
                         "FAILED", "DECLINED", "PROVIDER_SUBMITTED"),
    # A pre-capture FAILED (e.g. order call threw after the provider
    # persisted) is superseded by the money actually arriving.
    "FAILED": ("CAPTURED", "PAID"),
    # PAID is terminal except for post-settlement exits (refund/reversal),
    # which never reopen the payment itself.
    "PAID": ("REFUNDED", "REVERSED"),
    "REFUNDED": (),
    "REVERSED": (),
    "EXPIRED": (),
    "CANCELLED": (),
    "DECLINED": (),
}

# States with no outgoing adoption: the reconciler reports them as-is and stops
# scanning them. DECLINED belongs here - it was reachable but absent, so every
# declined row was re-reconciled forever.
TERMINAL_STATES = frozenset({"PAID", "REFUNDED", "REVERSED", "EXPIRED",
                             "CANCELLED", "DECLINED"})

# Non-terminal states that mean "the provider has said it captured this".
# Kept separate from TERMINAL_STATES because the reconciler must still visit
# them to promote CAPTURED -> PAID.
CAPTURED_STATES = frozenset({"CAPTURED"})


class IllegalTransitionError(ValueError):
    pass


def transition_txn(txn, to_state: str) -> None:
    allowed = TRANSITION_TABLE.get(txn.state, ())
    if to_state not in allowed:
        raise IllegalTransitionError(f"Illegal transaction transition {txn.state} -> {to_state}")
    txn.state = to_state
