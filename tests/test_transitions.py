"""Task 2: transition table + REVIEW exits (Amendment 2)."""
import pytest

from app.transitions import IllegalTransitionError, transition_txn


def _txn(state):
    import app.models as models
    return models.ProviderTransaction(
        authorization_id="a", intent_id="i", agent_id="g", state=state
    )


def test_failed_superseded_by_late_capture():
    txn = _txn("FAILED")
    transition_txn(txn, "PAID")
    assert txn.state == "PAID"


def test_paid_is_terminal():
    txn = _txn("PAID")
    with pytest.raises(IllegalTransitionError):
        transition_txn(txn, "FAILED")


def test_unknown_exits_to_submitted_and_paid():
    txn = _txn("PROVIDER_UNKNOWN")
    transition_txn(txn, "PROVIDER_SUBMITTED")
    assert txn.state == "PROVIDER_SUBMITTED"
    transition_txn(txn, "PAID")
    assert txn.state == "PAID"


def test_authorized_cannot_skip_to_paid():
    txn = _txn("AUTHORIZED")
    with pytest.raises(IllegalTransitionError):
        transition_txn(txn, "PAID")


def test_velocity_review_expires(paari_client):
    from datetime import datetime, timezone
    import app.models as models
    from tests.conftest import make_intent

    ctx = paari_client
    # 5 intents inside the velocity window, then the 6th parks on REVIEW.
    for n in range(5):
        body = make_intent(ctx, suffix=f"t2-park-{n}")
        assert body["decision"] == "allow", body
    parked = make_intent(ctx, suffix="t2-park-5")
    assert parked["decision"] == "review", parked
    assert parked["review_expires_at"] is not None

    # While the park is live, a resubmission stays parked (no extension).
    again = make_intent(ctx, suffix="t2-park-live")
    assert again["decision"] == "review", again

    # Expire the park in the DB: the window is still hot, so the next
    # submission re-parks - but as a FRESH park (new intent, new expiry),
    # proving the expired park no longer pins submissions forever.
    db = ctx.Session()
    row = db.query(models.PaymentIntent).filter_by(intent_id=parked["intent_id"]).first()
    row.review_expires_at = datetime.now(timezone.utc)
    db.commit()
    db.close()
    freed = make_intent(ctx, suffix="t2-park-freed")
    assert freed["decision"] == "review", freed
    assert freed["intent_id"] != parked["intent_id"]
    assert freed["review_expires_at"] is not None
    assert freed["review_expires_at"] != parked["review_expires_at"]
