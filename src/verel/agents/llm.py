"""Minimal, dependency-free LLM client (provider-agnostic seam).

Phase 0 implements the OpenAI Chat Completions backend because that is the key available in
this environment. **Claude (Anthropic) is the documented production default** per the design
— add an `anthropic` branch in `chat()` and it drops straight in. Uses stdlib `urllib` so
the core package gains no third-party dependency.

Key resolution (first hit wins): env `OPENAI_API_KEY` -> `~/.config/OpenAI/key`.
Model: arg -> env `VEREL_CODER_MODEL` -> `gpt-4o-mini`.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

DEFAULT_MODEL = "gpt-4o-mini"


@dataclass
class ChatResult:
    content: str
    prompt_tokens: int = 0
    completion_tokens: int = 0


class LLMError(RuntimeError):
    pass


def _openai_key() -> str:
    if key := os.environ.get("OPENAI_API_KEY"):
        return key.strip()
    p = Path.home() / ".config" / "OpenAI" / "key"
    if p.exists():
        return p.read_text().strip()
    raise LLMError("no OpenAI key (set OPENAI_API_KEY or ~/.config/OpenAI/key)")


def chat(messages: list[dict], *, model: str | None = None, temperature: float = 0.0,
         timeout: int = 90, provider: str | None = None) -> ChatResult:
    """One chat completion. `messages` = [{"role": "...", "content": "..."}]."""
    provider = provider or os.environ.get("VEREL_LLM_PROVIDER", "openai")
    model = model or os.environ.get("VEREL_CODER_MODEL", DEFAULT_MODEL)
    if provider != "openai":
        raise LLMError(f"provider {provider!r} not implemented in Phase 0 (Claude is the "
                       "production default — add the branch here)")

    payload = json.dumps(
        {"model": model, "temperature": temperature, "messages": messages}
    ).encode()
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=payload,
        headers={"Authorization": f"Bearer {_openai_key()}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as e:
        raise LLMError(f"OpenAI HTTP {e.code}: {e.read().decode()[:300]}") from e
    except urllib.error.URLError as e:
        raise LLMError(f"OpenAI request failed: {e}") from e

    usage = data.get("usage", {})
    return ChatResult(
        content=data["choices"][0]["message"]["content"],
        prompt_tokens=usage.get("prompt_tokens", 0),
        completion_tokens=usage.get("completion_tokens", 0),
    )


def have_key() -> bool:
    try:
        _openai_key()
        return True
    except LLMError:
        return False
