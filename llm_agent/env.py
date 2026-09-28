"""Minimal .env reader, so no python-dotenv dependency is added."""
from __future__ import annotations

import os
from pathlib import Path


def load_env(path: str | os.PathLike[str] = ".env") -> list[str]:
    """Populate os.environ from a local env file; returns key NAMES only."""
    file = Path(path)
    if not file.is_file():
        return []
    names: list[str] = []
    for line in file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key or key in os.environ:
            continue
        os.environ[key] = value.strip().strip('"').strip("'")
        names.append(key)
    return names


def require_env(key: str) -> str:
    value = os.environ.get(key, "").strip()
    if not value:
        raise RuntimeError(f"{key} is not set — add it to .env or your shell")
    return value
