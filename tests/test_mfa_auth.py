"""Phase 5 MFA: requesting a step-up challenge requires the caller's own session.

RED expectations (pre-fix): MFAChallengeRequest has no session_token field,
so these requests either 422 unexpectedly or - worse - succeed without auth.
"""
from tests.conftest import make_intent


def _review_intent(ctx):
    # 450000 / 500000 = 90% of limit -> REVIEW + step-up MFA.
    body = make_intent(ctx, amount=450000, suffix="mfa-review")
    assert body["decision"] == "review", body
    assert body["mfa_required"] is True
    return body["intent_id"]


def test_challenge_without_session_token_rejected(paari_client):
    ctx = paari_client
    intent_id = _review_intent(ctx)
    r = ctx.client.post("/payments/mfa/challenge", json={"intent_id": intent_id})
    assert r.status_code == 422, r.text


def test_challenge_with_other_agents_session_rejected(paari_client):
    ctx = paari_client
    intent_id = _review_intent(ctx)
    _, other_token, _, _ = ctx.register_extra_agent(suffix="-other")
    r = ctx.client.post(
        "/payments/mfa/challenge",
        json={"intent_id": intent_id, "session_token": other_token},
    )
    assert r.status_code == 403, r.text


def test_challenge_with_own_session_succeeds(paari_client):
    ctx = paari_client
    intent_id = _review_intent(ctx)
    r = ctx.client.post(
        "/payments/mfa/challenge",
        json={"intent_id": intent_id, "session_token": ctx.session_token},
    )
    assert r.status_code == 200, r.text
    assert r.json()["intent_id"] == intent_id
