"""Offline tests for the LLM payment broker.

The claim under test is narrow and security-relevant: a non-deterministic model is
allowed to *propose* payments but must never be able to sign one, overshoot its
delegation, or confirm an authorization it did not earn.
"""
from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT, ROOT / "sdk"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from llm_agent.broker import PaariBroker
from llm_agent.loop import run_goal
from llm_agent.model import Reply, ToolCall
from llm_agent.tools import TOOL_SCHEMAS, tool_names

CAP = 500000


class SpyClient:
    """Stands in for PaariAgentClient and records every call the broker attempts."""

    def __init__(self, intent=None, consume=None, proof=None):
        self.agent_id = "agent-spy"
        # Marker stands in for a real Ed25519 private key: it must never surface in
        # anything sent to the model.
        self.private_key_pem = "-----BEGIN PRIVATE KEY-----\nSECRET-MATERIAL\n-----END PRIVATE KEY-----"
        self.card = {"limits": {"max_amount": CAP, "currency": "INR"},
                     "capabilities": ["payment.create"]}
        self._intent = intent or {"decision": "allow", "transaction_id": "TX",
                                  "authorization": {"authorization_id": "auth-1",
                                                    "expires_at": "2026-09-25T00:00:00+00:00"}}
        self._consume = consume or {"state": "PROVIDER_SUBMITTED",
                                    "razorpay_order_id": "order_fake_1",
                                    "remaining_uses": 0}
        self._proof = proof or {"transaction_id": "TX",
                                "artifacts": {"audit_record": {"chain_verified": True,
                                                               "events": [{}, {}]}}}
        self.intents: list[dict] = []
        self.consumes: list[str] = []
        self.proofs: list[str] = []

    def payment_intent(self, **kwargs):
        self.intents.append(kwargs)
        body = dict(self._intent)
        body.setdefault("transaction_id", kwargs["transaction_id"])
        if "authorization" in body and isinstance(body["authorization"], dict):
            body["authorization"] = dict(body["authorization"])
        return body

    def consume(self, authorization_id):
        self.consumes.append(authorization_id)
        return dict(self._consume)

    def proof_bundle(self, transaction_id):
        self.proofs.append(transaction_id)
        body = dict(self._proof)
        body["transaction_id"] = transaction_id
        return body


def make_broker(client=None, **overrides):
    kwargs = {"max_amount_minor_units": CAP, "currency": "INR"}
    kwargs.update(overrides)
    return PaariBroker(client=client or SpyClient(), **kwargs)


def tool_reply(name, args, call_id="call_1"):
    return Reply(text=None, tool_calls=(ToolCall(call_id, name, args),),
                 finish_reason="tool_calls")


def text_reply(text):
    return Reply(text=text, finish_reason="stop")


class FakeModel:
    """Scripted stand-in for the router: no network, fully deterministic."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.requests: list[dict] = []

    def complete(self, messages, *, tools=None, max_tokens=1200, temperature=None):
        self.requests.append({"messages": list(messages), "tools": tools})
        if not self.replies:
            raise AssertionError("FakeModel ran out of scripted replies")
        return self.replies.pop(0)


def proposal(amount=100, merchant="ProofStore", currency="INR"):
    return {"merchant": merchant, "amount_minor_units": amount, "currency": currency,
            "purpose": "test"}


# --- the broker refuses before anything reaches the network -------------------

def test_over_cap_proposal_never_reaches_the_server():
    client = SpyClient()
    result = make_broker(client).execute("propose_payment", proposal(amount=CAP + 1))
    assert result["ok"] is False
    assert result["code"] == "AMOUNT_OVER_LIMIT"
    assert client.intents == [], "broker sent an intent the delegation does not allow"


def test_zero_and_negative_amounts_are_refused():
    client = SpyClient()
    broker = make_broker(client)
    for amount in (0, -100):
        assert broker.execute("propose_payment", proposal(amount=amount))["ok"] is False
    assert client.intents == []


def test_wrong_currency_is_refused_locally():
    client = SpyClient()
    result = make_broker(client).execute("propose_payment", proposal(currency="USD"))
    assert result["ok"] is False
    assert result["code"] == "UNSUPPORTED_CURRENCY"
    assert client.intents == []


def test_model_cannot_supply_its_own_transaction_or_idempotency_ids():
    client = SpyClient()
    broker = make_broker(client)
    injected = proposal() | {"transaction_id": "TXN-of-the-other-agent"}
    result = broker.execute("propose_payment", injected)
    assert result["ok"] is False
    assert result["code"] == "UNKNOWN_ARGUMENT"
    assert client.intents == []
    # A well-formed proposal gets a broker-generated id instead.
    ok = broker.execute("propose_payment", proposal())
    assert client.intents[0]["transaction_id"] == ok["transaction_id"]
    assert "TXN-of-the-other-agent" not in json.dumps(client.intents)


def test_invented_authorization_id_is_refused_without_a_consume():
    client = SpyClient()
    result = make_broker(client).execute("confirm_payment", {"authorization_id": "auth-made-up"})
    assert result["ok"] is False
    assert result["code"] == "UNKNOWN_AUTHORIZATION"
    assert client.consumes == []


def test_denied_intent_stores_nothing_and_surfaces_reasons():
    client = SpyClient(intent={"decision": "deny", "reasons": ["amount exceeds policy"],
                              "authorization": None})
    broker = make_broker(client)
    # Under the broker's own cap on purpose: the refusal must come from governance.
    denied = broker.execute("propose_payment", proposal(amount=100))
    assert denied["ok"] is False
    assert denied["status"] == "denied"
    assert "amount exceeds policy" in denied["reasons"]
    assert "authorization_id" not in denied
    # Nothing confirmable was stashed, so a follow-up confirm cannot fire.
    assert broker.execute("confirm_payment", {"authorization_id": "anything"})["ok"] is False
    assert client.consumes == []


def test_second_consume_is_refused_by_the_broker():
    client = SpyClient()
    broker = make_broker(client)
    auth_id = broker.execute("propose_payment", proposal())["authorization_id"]
    assert broker.execute("confirm_payment", {"authorization_id": auth_id})["ok"] is True
    assert broker.execute("confirm_payment", {"authorization_id": auth_id})["ok"] is False
    assert client.consumes == [auth_id], "authorization was spent twice"


def test_read_proof_refuses_a_transaction_the_broker_never_created():
    client = SpyClient()
    result = make_broker(client).execute("read_proof", {"transaction_id": "TXN-foreign"})
    assert result["ok"] is False
    assert client.proofs == []


def test_unknown_tool_is_reported_not_raised():
    result = make_broker(SpyClient()).execute("revoke_everyone", {})
    assert result["ok"] is False
    assert result["code"] == "UNKNOWN_TOOL"


def test_model_sees_only_the_brokered_tools():
    assert tool_names() == ["get_delegation", "get_payment_authority", "propose_payment", "confirm_payment", "read_proof"]
    for schema in TOOL_SCHEMAS:
        assert schema["type"] == "function"
        fn = schema["function"]
        assert fn["description"], f"{fn['name']} has no description for the model"
        params = fn["parameters"]
        assert params["type"] == "object"
        # A required key missing from properties would fail every call silently.
        for key in params["required"]:
            assert key in params["properties"], f"{fn['name']} requires undocumented '{key}'"


# --- the loop ----------------------------------------------------------------

def test_loop_returns_when_the_model_answers_in_prose():
    model = FakeModel([tool_reply("get_delegation", {}), text_reply("Nothing affordable today.")])
    outcome = run_goal(model, make_broker(), "Buy something", max_turns=5)
    assert outcome.ok is True
    assert outcome.final_text == "Nothing affordable today."
    assert outcome.turns == 2


def test_loop_caps_turns_when_the_model_never_stops():
    looping = [tool_reply("get_delegation", {}, f"call_{i}") for i in range(20)]
    model = FakeModel(looping)
    outcome = run_goal(model, make_broker(), "Buy something", max_turns=4)
    assert outcome.turns == 4
    assert outcome.error == "MAX_TURNS"


def test_governance_deny_is_fed_back_to_the_model_as_a_tool_result():
    client = SpyClient(intent={"decision": "deny", "reasons": ["over policy"], "authorization": None})
    model = FakeModel([tool_reply("propose_payment", proposal(amount=100)),
                       text_reply("Understood, I will not pay that.")])
    outcome = run_goal(model, make_broker(client), "Buy something", max_turns=3)
    followup = model.requests[-1]["messages"]
    tool_messages = [m for m in followup if m["role"] == "tool"]
    assert tool_messages, "model never received the tool result"
    assert "denied" in tool_messages[-1]["content"]
    assert "over policy" in tool_messages[-1]["content"]
    assert outcome.payment_executed is False


def test_loop_records_a_successful_payment():
    client = SpyClient()
    model = FakeModel([tool_reply("propose_payment", proposal()),
                       tool_reply("confirm_payment", {"authorization_id": "auth-1"}),
                       text_reply("Paid.")])
    outcome = run_goal(model, make_broker(client), "Buy something", max_turns=5)
    assert outcome.payment_executed is True
    assert outcome.settled_state == "PROVIDER_SUBMITTED"


def test_loop_totals_token_usage_across_turns():
    replies = [
        Reply(text=None, tool_calls=(ToolCall("c1", "get_delegation", {}),),
              finish_reason="tool_calls",
              usage={"prompt_tokens": 400, "completion_tokens": 20, "cost": "free"}),
        Reply(text="Done.", finish_reason="stop",
              usage={"prompt_tokens": 430, "completion_tokens": 8}),
    ]
    outcome = run_goal(FakeModel(replies), make_broker(), "Buy something", max_turns=4)
    assert outcome.billed("prompt_tokens") == 830
    assert outcome.billed("completion_tokens") == 28
    assert "cost" not in outcome.usage, "non-integer usage must not be summed"


def test_signing_key_never_appears_in_anything_sent_to_the_model():
    client = SpyClient()
    model = FakeModel([tool_reply("get_delegation", {}),
                       tool_reply("propose_payment", proposal()),
                       tool_reply("confirm_payment", {"authorization_id": "auth-1"}),
                       text_reply("Paid 1.00 to ProofStore.")])
    outcome = run_goal(model, make_broker(client), "Pay Rs 1.00 to ProofStore", max_turns=6)
    assert outcome.payment_executed is True
    wire = json.dumps([req["messages"] for req in model.requests]
                      + [req["tools"] for req in model.requests], default=str)
    assert "SECRET-MATERIAL" not in wire
    assert "private_key" not in wire
    assert "Bearer" not in wire, "session token must not be echoed to the model"


# --- against the real /v1 surface (no network, provider faked at the seam) ----


@pytest.fixture()
def live_broker(paari_client, monkeypatch):
    """A broker on a real SDK client bound to the real app, with Ed25519 proofs."""
    from paari_agent import PaariAgentClient, fingerprint, generate_keypair, sign_delegation
    from datetime import datetime, timedelta, timezone
    import app.routers.payments as payments_router

    class FakeProvider:
        def create_payment(self, authorization_id, amount_minor_units, currency, notes):
            return {"id": "order_llm_1", "receipt": authorization_id,
                    "amount": amount_minor_units, "currency": currency, "status": "created"}

    monkeypatch.setattr(payments_router, "get_provider", lambda: FakeProvider())
    ctx = paari_client
    private, public = generate_keypair()
    now = datetime.now(timezone.utc)
    delegation = {
        "delegation_id": str(uuid.uuid4()), "parent_id": ctx.parent_id,
        "agent_public_key_fingerprint": fingerprint(public),
        "granted_capabilities": ["make_payment"], "payment_limit_minor_units": CAP,
        "currency": "INR", "issued_at": int(now.timestamp()),
        "expires_at": int((now + timedelta(days=7)).timestamp()),
    }
    client = PaariAgentClient("http://test", private, public, http=ctx.client)
    client.register(name="LLM Broker Agent", agent_type="assistant", purpose="llm tests",
                    delegation=delegation,
                    delegation_signature_b64=sign_delegation(ctx.parent_private, delegation))
    client.authenticate()
    return PaariBroker(client=client, max_amount_minor_units=CAP, currency="INR")


def test_broker_drives_real_governance_to_submitted_and_verifiable(live_broker):
    proposed = live_broker.execute("propose_payment", proposal(amount=1200))
    assert proposed["ok"] is True, proposed
    assert proposed["status"] == "authorized"

    confirmed = live_broker.execute("confirm_payment",
                                    {"authorization_id": proposed["authorization_id"]})
    assert confirmed["ok"] is True, confirmed
    assert confirmed["state"] == "PROVIDER_SUBMITTED"
    assert confirmed["provider_order_id"] == "order_llm_1"

    proof = live_broker.execute("read_proof", {"transaction_id": proposed["transaction_id"]})
    assert proof["ok"] is True, proof
    assert proof["chain_verified"] is True
    assert proof["stage_count"] >= 4
    # Pinned against the real bundle shape: the model can only report a settlement if the
    # broker surfaces the nodes the server actually writes.
    assert proof["state"] == "PROVIDER_SUBMITTED"
    assert proof["final_state"] == "PROVIDER_SUBMITTED"
    assert proof["terminal"] is False
    assert proof["webhook_verified"] is False
    assert proof["provider_order_id"] == "order_llm_1"


def test_broker_blocks_an_over_limit_payment_before_the_server_sees_it(live_broker):
    result = live_broker.execute("propose_payment", proposal(amount=10_000_000))
    assert result["ok"] is False
    assert result["code"] == "AMOUNT_OVER_LIMIT"


def test_real_governance_denies_a_payment_within_broker_cap(paari_client, live_broker):
    """The broker's cap mirrors the delegation, so tighten the ledger underneath it
    and confirm a sub-cap payment is still refused by the server, not by us."""
    import app.models as models

    proposed = live_broker.execute("propose_payment", proposal(amount=1200))
    assert proposed["ok"] is True, proposed
    db = paari_client.Session()
    agent = db.query(models.Agent).filter_by(agent_id=live_broker.client.agent_id).first()
    agent.payment_limit_minor_units = 100
    db.commit()
    db.close()

    second = live_broker.execute("propose_payment", proposal(amount=1200))
    assert second["ok"] is False, second
    assert second["status"] == "denied", second
    assert second["reasons"], "governance denial arrived without a reason"
