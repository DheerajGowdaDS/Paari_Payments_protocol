"""Phase 1 smoke probe: is the key valid, is the model id right, does tool-calling work?

Touches no Paari code on purpose — this validates the model client alone before any
agent loop is built on top of it.

    python scripts/llm_smoke.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from llm_agent.env import load_env, require_env  # noqa: E402
from llm_agent.model import ChatModel, ModelError  # noqa: E402

PROBE_TOOL = [{
    "type": "function",
    "function": {
        "name": "smoke_probe",
        "description": "Echo back a literal token. Use this tool instead of replying in prose.",
        "parameters": {
            "type": "object",
            "properties": {
                "value": {"type": "string", "description": "The literal token to echo back."}
            },
            "required": ["value"],
        },
    },
}]

failures: list[str] = []

# This router reports the same "insufficient credits" condition as 402 and as 429.
HINTS = {
    "402": "account balance is zero — top up at router.bynara.id",
    "403": "the plan attached to this key does not include that model",
    "429": "rate limited; on this router it usually still means no credit",
    "502": "the upstream model service is unavailable, nothing to fix locally",
    "model error": "the router answered 200 with an error object",
}


def hint(text: str) -> str:
    for needle, advice in HINTS.items():
        if needle in text:
            return f"  -> {advice}"
    return ""


def report(name: str, ok: bool, evidence) -> None:
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {evidence}", flush=True)
    if not ok:
        failures.append(name)
        print(hint(str(evidence)), flush=True)


def main() -> int:
    keys = load_env(ROOT / ".env")
    report("0. .env loaded (names only)", bool(keys), f"keys={keys}")
    base = require_env("BYNARA_API_BASE")
    model_id = require_env("BYNARA_MODEL")
    model = ChatModel(base_url=base, api_key=require_env("BYNARA_API_KEY"), model=model_id)

    try:
        ids = model.list_models()
        report("1. key accepted by /models", True, f"{len(ids)} models listed")
        # /models is the whole catalog, not this key's entitlement — passing this
        # proves the id is spelled correctly, nothing more.
        report("2. model id exists in the catalog", model_id in ids,
               f"{model_id} found={model_id in ids} (catalog listing is not an entitlement)")
    except ModelError as exc:
        report("1. key accepted by /models", False, str(exc))
        return 1

    try:
        plain = model.complete(
            [{"role": "user", "content": "Reply with exactly the word READY and nothing else."}],
            max_tokens=600,
        )
        report("3. plain completion", bool(plain.text),
               f"finish={plain.finish_reason!r} text={plain.text!r} usage={plain.usage}")
    except ModelError as exc:
        report("3. plain completion", False, str(exc))
        plain = None

    try:
        tool = model.complete(
            [{"role": "user",
              "content": "Call smoke_probe with value set to exactly paari-smoke-7. "
                         "Do not answer in prose."}],
            tools=PROBE_TOOL,
            max_tokens=1500,
        )
        args = tool.tool_calls[0].arguments if tool.tool_calls else {}
        report("4. tool calling works", tool.wants_tools and tool.tool_calls[0].name == "smoke_probe",
               f"finish={tool.finish_reason!r} calls={[(c.name, c.arguments) for c in tool.tool_calls]}")
        report("5. arguments round-trip", args.get("value") == "paari-smoke-7",
               f"value={args.get('value')!r}")
        if not tool.wants_tools:
            print(f"       raw text was: {json.dumps(tool.text)[:300]}", flush=True)
    except ModelError as exc:
        report("4. tool calling works", False, str(exc))

    print("\n" + ("SMOKE GREEN: model client is usable" if not failures
                  else f"SMOKE RED: {failures}"), flush=True)
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
