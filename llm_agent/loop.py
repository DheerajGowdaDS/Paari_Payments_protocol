"""The agent loop: model proposes, broker decides what may be signed."""
from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import Any

from .tools import TOOL_SCHEMAS

SYSTEM_PROMPT = """You are a shopping agent that can pay through Paari, a governance layer.

You do not hold a signing key and you cannot pay by asking directly. You propose; Paari
authorizes a single-use ticket; a broker you cannot touch executes it.

Rules:
- Call get_delegation before proposing a payment and stay inside the cap it reports.
- Use only ids that a tool returned to you. Invented ids never reach the server.
- A denial is a decision about these values, not an obstacle. Do not retry the same
  proposal, do not split it into smaller repeated payments, and do not ask again for a
  higher limit. Report the denial instead.
- Confirm at most the payment the user asked for, then verify it with read_proof.
- When you are done, or blocked, answer in plain prose and stop calling tools.
"""


@dataclass
class Outcome:
    ok: bool
    turns: int = 0
    tool_calls: int = 0
    usage: dict[str, int] = field(default_factory=dict)
    messages: list[dict[str, Any]] = field(default_factory=list)
    transcript: list[dict[str, Any]] = field(default_factory=list)
    final_text: str | None = None
    payment_executed: bool = False
    settled_state: str | None = None
    transaction_id: str | None = None
    error: str | None = None

    @property
    def tool_log(self) -> list[str]:
        return [entry["tool"] for entry in self.transcript]

    def billed(self, key: str) -> int:
        return self.usage.get(key, 0)


def _assistant_message(reply, call_ids: list[str]) -> dict[str, Any]:
    return {
        "role": "assistant",
        "content": reply.text,
        "tool_calls": [
            {"id": call_ids[i], "type": "function",
             "function": {"name": call.name, "arguments": json.dumps(call.arguments)}}
            for i, call in enumerate(reply.tool_calls)
        ],
    }


def run_goal(model, broker, goal: str, *, max_turns: int = 6, max_tool_calls: int = 12,
             max_tokens: int = 1200) -> Outcome:
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": goal},
    ]
    outcome = Outcome(ok=False, messages=messages)

    for turn in range(1, max_turns + 1):
        outcome.turns = turn
        reply = model.complete(messages, tools=TOOL_SCHEMAS, max_tokens=max_tokens)
        for key, value in (reply.usage or {}).items():
            if isinstance(value, int) and not isinstance(value, bool):
                outcome.usage[key] = outcome.usage.get(key, 0) + value

        if not reply.wants_tools:
            outcome.final_text = reply.text
            if reply.text is None:
                outcome.error = f"EMPTY_REPLY:{reply.finish_reason or 'unknown'}"
            else:
                outcome.ok = True
            return outcome

        if outcome.tool_calls + len(reply.tool_calls) > max_tool_calls:
            outcome.error = "MAX_TOOL_CALLS"
            return outcome

        call_ids = [call.id or f"call_{turn}_{i}" for i, call in enumerate(reply.tool_calls, 1)]
        messages.append(_assistant_message(reply, call_ids))

        for call_id, call in zip(call_ids, reply.tool_calls):
            outcome.tool_calls += 1
            # Sprint 7: stamp the model's own tool-call id onto the broker so
            # the payment intent carries the causal link back to this exact
            # model invocation (identifier only - never conversation content).
            if getattr(broker, "causal", None) is not None:
                broker.causal = replace(broker.causal, tool_call_id=call_id, tool_name=call.name)
            result = broker.execute(call.name, call.arguments)
            outcome.transcript.append({"turn": turn, "tool": call.name,
                                       "arguments": call.arguments, "result": result})
            if result.get("ok") and call.name == "confirm_payment":
                outcome.payment_executed = True
                outcome.settled_state = result.get("state")
                outcome.transaction_id = result.get("transaction_id")
            messages.append({"role": "tool", "tool_call_id": call_id,
                             "content": json.dumps(result, default=str)})

    outcome.error = "MAX_TURNS"
    return outcome
