"""Canonical typed constructors for the Paari Protocol v1.0 message set."""
from __future__ import annotations

from typing import Any

MESSAGE_TYPES = (
    "agent.register",
    "agent.registered",
    "agent.card",
    "parent.delegation",
    "credential.issued",
    "auth.challenge",
    "auth.verify",
    "payment.intent",
    "payment.decision",
    "payment.authorization",
    "payment.consume",
    "payment.receipt",
    "mfa.challenge",
    "mfa.verify",
    "webhook.event",
    "agent.revoke",
)


def make_message(type: str, **fields: Any) -> dict:
    if type not in MESSAGE_TYPES:
        raise ValueError(f"unknown protocol message type: {type!r}")
    return {"type": type, **fields}


def agent_register(**fields: Any) -> dict: return make_message("agent.register", **fields)
def agent_registered(**fields: Any) -> dict: return make_message("agent.registered", **fields)
def agent_card(**fields: Any) -> dict: return make_message("agent.card", **fields)
def parent_delegation(**fields: Any) -> dict: return make_message("parent.delegation", **fields)
def credential_issued(**fields: Any) -> dict: return make_message("credential.issued", **fields)
def auth_challenge(**fields: Any) -> dict: return make_message("auth.challenge", **fields)
def auth_verify(**fields: Any) -> dict: return make_message("auth.verify", **fields)
def payment_intent(**fields: Any) -> dict: return make_message("payment.intent", **fields)
def payment_decision(**fields: Any) -> dict: return make_message("payment.decision", **fields)
def payment_authorization(**fields: Any) -> dict: return make_message("payment.authorization", **fields)
def payment_consume(**fields: Any) -> dict: return make_message("payment.consume", **fields)
def payment_receipt(**fields: Any) -> dict: return make_message("payment.receipt", **fields)
def mfa_challenge(**fields: Any) -> dict: return make_message("mfa.challenge", **fields)
def mfa_verify(**fields: Any) -> dict: return make_message("mfa.verify", **fields)
def webhook_event(**fields: Any) -> dict: return make_message("webhook.event", **fields)
def agent_revoke(**fields: Any) -> dict: return make_message("agent.revoke", **fields)
