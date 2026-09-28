"""Tool contracts for the model. Everything arriving here is untrusted input.

This mirrors the server's own rule (`docs/SECURITY.md`): values an agent asks for are
never authoritative. The broker enforces the caps; this module only checks shape.
"""
from __future__ import annotations

from typing import Any

MAX_STR_LEN = {"merchant": 80, "purpose": 300, "authorization_id": 128, "transaction_id": 128,
               "currency": 8, "merchant_category": 80}

_SPECS: dict[str, dict[str, type]] = {
    "get_delegation": {},
    "get_payment_authority": {},
    "propose_payment": {"merchant": str, "amount_minor_units": int, "currency": str,
                        "purpose": str, "merchant_category": str},
    "confirm_payment": {"authorization_id": str},
    "read_proof": {"transaction_id": str},
}

_REQUIRED: dict[str, tuple[str, ...]] = {
    "get_delegation": (),
    "get_payment_authority": (),
    "propose_payment": ("merchant", "amount_minor_units", "currency"),
    "confirm_payment": ("authorization_id",),
    "read_proof": ("transaction_id",),
}


class ToolArgsError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "get_delegation",
            "description": ("Report the spending authority the parent actually granted this agent: "
                            "currency, per-payment cap and remaining actions. Call this before "
                            "proposing a payment."),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_payment_authority",
            "description": ("Read the active user-granted payment mandate for this agent: per-transaction limit, "
                            "daily budget, allowed merchants/categories, review threshold and expiry. "
                            "This is user authority, separate from the parent's agent delegation."),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "propose_payment",
            "description": ("Ask Paari to authorize one payment. This does not move money: on approval "
                            "it returns a single-use authorization_id that must be spent with "
                            "confirm_payment. A denial is final for these values - do not retry the "
                            "same proposal, and never try to raise the limit."),
            "parameters": {
                "type": "object",
                "properties": {
                    "merchant": {"type": "string", "description": "Payee name."},
                    "amount_minor_units": {
                        "type": "integer",
                        "description": ("Amount in the smallest currency unit (paise for INR), so "
                                        "Rs 12.00 is 1200. Must be positive and within the cap."),
                    },
                    "currency": {"type": "string", "description": "ISO code, e.g. INR."},
                    "purpose": {"type": "string", "description": "Why this payment is needed."},
                    "merchant_category": {"type": "string", "description": "Optional category, e.g. grocery."},
                },
                "required": ["merchant", "amount_minor_units", "currency"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "confirm_payment",
            "description": ("Execute a proposal that propose_payment already approved, using the "
                            "authorization_id it returned. Spends it permanently. Ids you invent are "
                            "rejected without reaching the server."),
            "parameters": {
                "type": "object",
                "properties": {
                    "authorization_id": {"type": "string",
                                         "description": "The authorization_id returned by "
                                                        "propose_payment."},
                },
                "required": ["authorization_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_proof",
            "description": ("Read the tamper-evident stage-output record for your own transaction and "
                            "whether its audit chain verifies."),
            "parameters": {
                "type": "object",
                "properties": {
                    "transaction_id": {"type": "string",
                                       "description": "A transaction_id returned by propose_payment."},
                },
                "required": ["transaction_id"],
            },
        },
    },
]


def tool_names() -> list[str]:
    return [schema["function"]["name"] for schema in TOOL_SCHEMAS]


def validate(name: str, args: Any) -> dict[str, Any]:
    """Check a model-issued call against its contract; reject anything unexpected."""
    if name not in _SPECS:
        raise ToolArgsError("UNKNOWN_TOOL", f"'{name}' is not a tool you may call")
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise ToolArgsError("BAD_ARGUMENTS", "arguments must be an object")
    spec, required = _SPECS[name], _REQUIRED[name]
    unknown = sorted(set(args) - set(spec))
    if unknown:
        raise ToolArgsError("UNKNOWN_ARGUMENT",
                            f"{name} does not accept {', '.join(unknown)}; accepted: "
                            f"{', '.join(sorted(spec)) or 'none'}")
    missing = [key for key in required if args.get(key) is None]
    if missing:
        raise ToolArgsError("MISSING_ARGUMENT", f"{name} is missing {', '.join(missing)}")
    clean: dict[str, Any] = {}
    for key, expected in spec.items():
        if key not in args:
            continue
        value = args[key]
        if expected is int:
            # bool is an int subclass; a model passing true is not an amount.
            if isinstance(value, bool) or not isinstance(value, int):
                raise ToolArgsError("BAD_ARGUMENT_TYPE", f"{name}.{key} must be an integer")
        elif isinstance(value, str):
            limit = MAX_STR_LEN.get(key, 200)
            value = value.strip()
            if not value:
                raise ToolArgsError("BAD_ARGUMENT_TYPE", f"{name}.{key} must not be empty")
            if len(value) > limit:
                raise ToolArgsError("ARGUMENT_TOO_LONG", f"{name}.{key} exceeds {limit} characters")
        elif value is not None:
            raise ToolArgsError("BAD_ARGUMENT_TYPE", f"{name}.{key} must be a string")
        clean[key] = value
    return clean
