"""LLM-driven Paari agent (client side only).

Imports nothing from `app/` — the trust layer stays deterministic and this
remains a black-box protocol test rather than an internal call.
"""
from .env import load_env
from .model import ChatModel, ModelError, Reply, ToolCall

__all__ = ["ChatModel", "ModelError", "Reply", "ToolCall", "load_env"]
