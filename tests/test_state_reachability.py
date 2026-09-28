"""The transition table must not read as a list of capabilities.

`app/transitions.py` contains states that no code path can currently produce -
REVERSED. Two reviewers independently read that as "Paari handles reversals"
and it is not true: no reversal path exists yet.

This file turns that ambiguity into an enforced, checked-in fact. It derives the
set of states the application can actually enter by scanning the source for
transitions, and pins it. Add a producer without deciding what this file should
say, and the suite tells you. Remove one, and it tells you too - which matters
more, because a silently-deleted settlement path is how money goes missing.

It also pins the two structural properties the Blueprint's Phase 9 was really
about: the distinction between Paari authorization and provider settlement must
be unambiguous, and the settlement states must not be reachable by skipping it.
"""
import pathlib
import re

import pytest

from app.transitions import TRANSITION_TABLE, TERMINAL_STATES, transition_txn

REPO = pathlib.Path(__file__).resolve().parents[1]

# States the application can currently reach by an explicit transition. Derived
# by scanning the source below, then asserted against this list - so adding or
# removing a producer is a decision someone has to make deliberately.
REACHABLE_BY_TRANSITION = {
    "PROVIDER_SUBMITTED", "PROVIDER_AUTHORIZED", "CAPTURED", "PAID",
    "FAILED", "PROVIDER_UNKNOWN",
    "EXPIRED", "CANCELLED", "REFUNDED", "DECLINED",
}

# `AUTHORIZED` is the row's initial state rather than the target of a
# transition, so it is never produced by a `transition_txn` call.
INITIAL_STATES = {"AUTHORIZED"}

# Declared in the table but with NO producer anywhere in `app/`. Reserved is the
# honest word for them; "supported" is not.
UNREACHABLE_BY_DESIGN = {"REVERSED"}


def _states_written_by_the_app() -> set[str]:
    """Every state string the app assigns to a transaction's state.

    Covers both shapes the code uses: `transition_txn(txn, "X")` and the
    provider-event target maps (`{"payment.captured": "PAID", ...}`).
    """
    produced: set[str] = set()
    transition_call = re.compile(r"transition_txn\(\s*\w+\s*,\s*[\"']([A-Z_]+)[\"']")
    assignment = re.compile(r"[\"']([A-Z_]+)[\"']\s*(?:\]|,|\))")
    for path in sorted((REPO / "app").rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        produced.update(transition_call.findall(source))
        # The event->state dictionaries in the webhook and reconciler.
        for match in re.finditer(
                r"\{[^{}]*\"payment\.(?:authorized|captured|failed)\"[^{}]*\}", source, re.S):
            produced.update(assignment.findall(match.group(0)))
    return produced & set(TRANSITION_TABLE)


def test_only_documented_states_are_producible():
    produced = _states_written_by_the_app()
    assert produced, "the scan found no state producers at all - it has rotted"
    assert produced == REACHABLE_BY_TRANSITION, (
        f"producers changed shape: gained {sorted(produced - REACHABLE_BY_TRANSITION)}, "
        f"lost {sorted(REACHABLE_BY_TRANSITION - produced)}. Decide what the "
        "capability claim is before updating this list.")
    assert produced & UNREACHABLE_BY_DESIGN == set(), (
        f"a reserved-with-no-producer state now has one: {sorted(produced & UNREACHABLE_BY_DESIGN)}")


def test_reserved_states_have_no_producer_and_cannot_be_reached_accidentally():
    """An unreachable-but-declared state is documentation. One that is also
    unreachable FROM the table would be dead weight in the wrong direction: the
    reconciler reports terminal states as-is, so a typo here could strand rows."""
    for state in UNREACHABLE_BY_DESIGN:
        assert TRANSITION_TABLE[state] == (), f"{state} unexpectedly has exits"
        assert state in TERMINAL_STATES, f"{state} is reserved terminal but not in TERMINAL_STATES"


def test_provider_settlement_cannot_bypass_the_provider_submitted_step():
    """The ambiguity Phase 9 existed to remove: a Paari authorization must never
    turn into a settled payment without a provider object in between."""
    from app.transitions import IllegalTransitionError

    assert "PAID" not in TRANSITION_TABLE["AUTHORIZED"]
    # Recovery from a timeout is legitimate: the order exists provider-side and
    # the provider later says it was paid. What is NOT legitimate is minting
    # PAID from an authorization that never produced an order.
    class _Row:
        state = "AUTHORIZED"
        last_error = None

    with pytest.raises(IllegalTransitionError):
        transition_txn(_Row(), "PAID")


def test_provider_submitted_may_reach_captured_without_an_authorization_event():
    """Providers that never send `payment.authorized` must still be settleable.

    Phase 9 added PROVIDER_AUTHORIZED, but it is not a mandatory stop: a provider
    whose first and only event is `payment.captured` goes straight to CAPTURED.
    Demanding the intermediate state would reject real money.
    """
    assert "CAPTURED" in TRANSITION_TABLE["PROVIDER_SUBMITTED"]
    assert "PROVIDER_AUTHORIZED" in TRANSITION_TABLE["PROVIDER_SUBMITTED"]


def test_captured_is_a_real_stop_on_the_way_to_paid():
    """The distinction Phase 9 existed to create, expressed as graph shape.

    CAPTURED sits between the provider's announcement and Paari's confirmation,
    and has exactly two exits: settle, or become indeterminate if the provider
    later contradicts itself. It is not terminal, which is what keeps the
    reconciler working on it.
    """
    assert TRANSITION_TABLE["CAPTURED"] == ("PAID", "PROVIDER_UNKNOWN")
    assert "CAPTURED" not in TERMINAL_STATES
    assert "DECLINED" in TERMINAL_STATES, (
        "a dead-end state missing from TERMINAL_STATES is re-reconciled forever")


def test_reconciliation_may_still_settle_a_row_the_webhook_never_reached():
    """PROVIDER_SUBMITTED -> PAID stays legal, and why.

    That edge is how a missed webhook gets settled: reconciliation reads
    `captured` from the provider's own API, and that read is itself the
    corroboration. The webhook handler is barred from taking this shortcut by its
    own event->state mapping rather than by the graph, since the graph cannot see
    which caller asked. The behavioural half of that rule lives in
    tests/test_phase9_state_machine.py::test_webhook_mapping_contains_no_terminal_state.
    """
    assert "PAID" in TRANSITION_TABLE["PROVIDER_SUBMITTED"]
    assert "PAID" in TRANSITION_TABLE["PROVIDER_UNKNOWN"]


def test_illegal_jumps_still_raise():
    from app.transitions import IllegalTransitionError

    for start, target in [("PAID", "FAILED"), ("REFUNDED", "PAID"),
                          ("PROVIDER_SUBMITTED", "EXPIRED")]:
        class _Row:
            state = start
            last_error = None

        with pytest.raises(IllegalTransitionError):
            transition_txn(_Row(), target)


def test_unknown_state_fails_closed():
    """A row carrying a state string the table does not know must not be
    permitted to move anywhere: an unrecognised state is the moment at which the
    machine stops protecting the money."""
    class _Row:
        state = "SOMETHING_UNEXPECTED"
        last_error = None

    with pytest.raises(Exception):
        transition_txn(_Row(), "PAID")
