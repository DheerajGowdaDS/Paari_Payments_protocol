"""Offline contract tests for the OpenAI-compatible client — no network, no key.

These matter because the live path is optional in CI: the parsing rules below are what
turn a router response into a broker call, and a wrong assumption here would surface as
a mysterious payment failure later.
"""
from __future__ import annotations

import json

import httpx
import pytest

from llm_agent.model import ChatModel, ModelError, parse_completion

API_KEY = "sk-nry-not-a-real-key-0000000000"


def make_model(handler) -> tuple[ChatModel, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    client = httpx.Client(transport=httpx.MockTransport(record))
    return ChatModel(base_url="https://router.test/v1/", api_key=API_KEY,
                     model="step-5-preview", http=client), seen


def completion(message: dict, finish: str = "stop", usage=None) -> httpx.Response:
    return httpx.Response(200, json={
        "model": "step-5-preview",
        "choices": [{"message": message, "finish_reason": finish}],
        "usage": usage or {"total_tokens": 7},
    })


def test_plain_text_reply():
    model, _ = make_model(lambda r: completion({"role": "assistant", "content": "READY"}))
    reply = model.complete([{"role": "user", "content": "hi"}])
    assert reply.text == "READY"
    assert reply.wants_tools is False
    assert reply.usage["total_tokens"] == 7


def test_tool_calls_with_stringified_arguments_are_parsed():
    payload = {"role": "assistant", "content": None, "tool_calls": [
        {"id": "call_9", "type": "function",
         "function": {"name": "propose_payment",
                      "arguments": json.dumps({"merchant": "ProofStore",
                                               "amount_minor_units": 1200})}}]}
    model, _ = make_model(lambda r: completion(payload, finish="tool_calls"))
    reply = model.complete([{"role": "user", "content": "pay"}], tools=[{"type": "function"}])
    assert reply.finish_reason == "tool_calls"
    call = reply.tool_calls[0]
    assert (call.id, call.name) == ("call_9", "propose_payment")
    assert call.arguments["amount_minor_units"] == 1200


def test_arguments_already_an_object_are_accepted():
    payload = {"role": "assistant", "tool_calls": [
        {"id": "c", "function": {"name": "get_delegation", "arguments": {}}}]}
    model, _ = make_model(lambda r: completion(payload, finish="tool_calls"))
    assert model.complete([]).tool_calls[0].arguments == {}


def test_malformed_tool_arguments_are_refused_not_guessed():
    payload = {"role": "assistant", "tool_calls": [
        {"id": "c", "function": {"name": "confirm_payment",
                                 "arguments": '{"authorization_id": '}}]}
    model, _ = make_model(lambda r: completion(payload, finish="tool_calls"))
    with pytest.raises(ModelError, match="not valid JSON"):
        model.complete([])


def test_request_carries_auth_tools_and_model():
    model, seen = make_model(lambda r: completion({"content": "ok"}))
    model.complete([{"role": "user", "content": "hi"}], tools=[{"type": "function"}],
                   max_tokens=42)
    request = seen[0]
    assert request.url.path == "/v1/chat/completions"
    assert request.headers["Authorization"] == f"Bearer {API_KEY}"
    body = json.loads(request.content)
    assert body["model"] == "step-5-preview"
    assert body["max_tokens"] == 42
    assert body["tool_choice"] == "auto"
    assert body["tools"][0]["type"] == "function"


def test_no_tools_means_no_tools_key_on_the_wire():
    model, seen = make_model(lambda r: completion({"content": "ok"}))
    model.complete([{"role": "user", "content": "hi"}])
    assert "tools" not in json.loads(seen[0].content)


def test_list_models_reads_the_data_array():
    model, seen = make_model(lambda r: httpx.Response(200, json={
        "data": [{"id": "step-5-preview"}, {"id": "other"}, "not-an-object"]}))
    assert model.list_models() == ["step-5-preview", "other"]
    assert seen[0].url.path == "/v1/models"


def test_payment_error_is_reported_without_leaking_the_key():
    model, _ = make_model(lambda r: httpx.Response(
        402, json={"error": {"type": "payment_required", "message": "Insufficient credits"}}))
    with pytest.raises(ModelError) as excinfo:
        model.complete([{"role": "user", "content": "hi"}])
    assert "402" in str(excinfo.value)
    assert "Insufficient credits" in str(excinfo.value)
    assert API_KEY not in str(excinfo.value)


def test_error_body_arriving_on_a_200_is_still_an_error():
    """Found in the wild: the router returns HTTP 200 with an error object when
    upstream is unavailable, which must not be mistaken for a malformed reply."""
    model, _ = make_model(lambda r: httpx.Response(200, json={
        "error": {"type": "service_unavailable", "message": "The model service is busy"}}))
    with pytest.raises(ModelError, match="model error"):
        model.complete([])


def test_a_valid_completion_wins_over_a_stray_error_key():
    reply = parse_completion({"error": {"type": "rate_limit_warning"},
                              "choices": [{"message": {"content": "OK"},
                                           "finish_reason": "stop"}]})
    assert reply.text == "OK"


def test_transport_failure_becomes_a_model_error():
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    model, _ = make_model(boom)
    with pytest.raises(ModelError, match="failed"):
        model.complete([])


@pytest.mark.parametrize("body", [
    {"choices": []},
    {"unexpected": "shape"},
])
def test_unusable_payloads_are_refused(body):
    with pytest.raises(ModelError, match="no choices"):
        parse_completion(body)


def test_whitespace_only_content_counts_as_no_text():
    reply = parse_completion({"choices": [{"message": {"content": "   "},
                                           "finish_reason": "length"}]})
    assert reply.text is None
    assert reply.wants_tools is False
    assert reply.finish_reason == "length"


def test_missing_credentials_fail_before_any_request():
    with pytest.raises(ModelError, match="api_key"):
        ChatModel(base_url="https://router.test/v1", api_key="", model="step-5-preview")
    with pytest.raises(ModelError, match="model"):
        ChatModel(base_url="https://router.test/v1", api_key=API_KEY, model="")
