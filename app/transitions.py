"""Central transition table for ProviderTransaction.state.

Every state change in the codebase must go through transition_txn - the
table below is the whole machine, so illegal jumps (including a PAID
regression or an AUTHORIZED skip straight to PAID) fail loudly instead of
silently corrupting execution state.
"""

TRANSITION_TABLE = {
    # Pre-provider exits: the authorization can die before any provider
    # object exists (expiry/cancellation producers land in later tasks).
    "AUTHORIZED": ("PROVIDER_SUBMITTED", "FAILED", "PROVIDER_UNKNOWN", "EXPIRED", "CANCELLED"),
    "PROVIDER_SUBMITTED": ("PAYMENT_PENDING", "PAID", "FAILED", "PROVIDER_UNKNOWN"),
    "PAYMENT_PENDING": ("PAID", "FAILED", "PROVIDER_UNKNOWN"),
    # Timeouts resolve late: the order may still exist provider-side.
    "PROVIDER_UNKNOWN": ("PAID", "FAILED", "PROVIDER_SUBMITTED"),
    # A pre-capture FAILED (e.g. order call threw after the provider
    # persisted) is superseded by the money actually arriving.
    "FAILED": ("PAID",),
    # PAID is terminal except for post-settlement exits (refund/reversal),
    # which never reopen the payment itself.
    "PAID": ("REFUNDED", "REVERSED"),
    "REFUNDED": (),
    "REVERSED": (),
    "EXPIRED": (),
    "CANCELLED": (),
}

# States with no outgoing adoption: the reconciler reports them as-is.
TERMINAL_STATES = frozenset({"PAID", "REFUNDED", "REVERSED", "EXPIRED", "CANCELLED"})


class IllegalTransitionError(ValueError):
    pass


def transition_txn(txn, to_state: str) -> None:
    allowed = TRANSITION_TABLE.get(txn.state, ())
    if to_state not in allowed:
        raise IllegalTransitionError(f"Illegal transaction transition {txn.state} -> {to_state}")
    txn.state = to_state
