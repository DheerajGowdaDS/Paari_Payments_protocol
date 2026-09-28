"""Thin OpenAI-compatible chat client for the BYNARA router (httpx only)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx

_ERROR_CLIP = 400


class ModelError(RuntimeError):
    """Any failure talking to, or parsing a reply from, the model."""


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class Reply:
    text: str | None
    tool_calls: tuple[ToolCall, ...] = ()
    finish_reason: str = ""
    model: str = ""
    usage: dict[str, Any] = field(default_factory=dict)

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)


def _clip(text: str) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= _ERROR_CLIP else text[:_ERROR_CLIP] + "…"


def _parse_tool_calls(message: dict[str, Any]) -> tuple[ToolCall, ...]:
    calls: list[ToolCall] = []
    for raw in message.get("tool_calls") or []:
        fn = raw.get("function") or {}
        args = fn.get("arguments")
        if isinstance(args, str):
            try:
                args = json.loads(args) if args.strip() else {}
            except json.JSONDecodeError as exc:
                raise ModelError(f"tool call arguments are not valid JSON: {_clip(args)}") from exc
        if not isinstance(args, dict):
            raise ModelError(f"tool call arguments must be an object, got {type(args).__name__}")
        calls.append(ToolCall(id=str(raw.get("id", "")), name=str(fn.get("name", "")), arguments=args))
    return tuple(calls)


def parse_completion(body: dict[str, Any]) -> Reply:
    error = body.get("error")
    if isinstance(error, (dict, str)) and "choices" not in body:
        # The router answers 200 with this shape when upstream is unavailable.
        raise ModelError(f"model error: {_clip(json.dumps(error) if isinstance(error, dict) else error)}")
    choices = body.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ModelError(f"response has no choices: {_clip(json.dumps(body)[:_ERROR_CLIP])}")
    message = choices[0].get("message") or {}
    text = message.get("content")
    if isinstance(text, str) and not text.strip():
        text = None
    return Reply(
        text=text,
        tool_calls=_parse_tool_calls(message),
        finish_reason=str(choices[0].get("finish_reason") or ""),
        model=str(body.get("model") or ""),
        usage=dict(body.get("usage") or {}),
    )


@dataclass
class ChatModel:
    base_url: str
    api_key: str
    model: str
    timeout: float = 90.0
    http: httpx.Client | None = None

    def __post_init__(self):
        self.base_url = self.base_url.rstrip("/")
        if not self.api_key:
            raise ModelError("api_key is required")
        if not self.model:
            raise ModelError("model is required")
        self.http = self.http or httpx.Client(timeout=self.timeout)

    @property
    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}"}

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict[str, Any]:
        try:
            response = self.http.request(method, f"{self.base_url}{path}", json=payload,
                                         headers=self._headers)
        except httpx.HTTPError as exc:
            raise ModelError(f"{method} {path} failed: {exc}") from exc
        if response.status_code >= 400:
            raise ModelError(f"{method} {path} -> HTTP {response.status_code}: {_clip(response.text)}")
        try:
            return response.json()
        except ValueError as exc:
            raise ModelError(f"{method} {path} -> non-JSON body: {_clip(response.text)}") from exc

    def list_models(self) -> list[str]:
        body = self._request("GET", "/models")
        data = body.get("data") if isinstance(body.get("data"), list) else []
        return [str(item.get("id")) for item in data if isinstance(item, dict)]

    def complete(self, messages: list[dict[str, Any]], *, tools: list[dict] | None = None,
                 max_tokens: int = 1200, temperature: float | None = None) -> Reply:
        payload: dict[str, Any] = {"model": self.model, "messages": messages,
                                   "max_tokens": max_tokens}
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        if temperature is not None:
            payload["temperature"] = temperature
        return parse_completion(self._request("POST", "/chat/completions", payload))
