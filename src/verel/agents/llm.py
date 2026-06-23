"""Minimal, dependency-free, provider-agnostic LLM client (stdlib `urllib` only).

All supported providers expose an OpenAI-compatible `/chat/completions` endpoint, so one
request/response path serves them. Default is **Ollama Cloud** (the owner's Max subscription)
with a purpose-built coder model; OpenAI and (once a key is present) Anthropic are drop-ins.

Selection:
  provider: arg -> env `VEREL_LLM_PROVIDER` -> "ollama"
  model:    arg -> env `VEREL_CODER_MODEL`  -> the provider's default
Key resolution per provider: env var first, then `~/.config/<dir>/key`.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

DEFAULT_PROVIDER = "ollama"

PROVIDERS = {
    # provider: (base_url, env_key, ~/.config relative key file, default model)
    "ollama": ("https://ollama.com/v1", "OLLAMA_API_KEY", "ollama/key", "qwen3-coder:480b"),
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY", "OpenAI/key", "gpt-4o-mini"),
}


@dataclass
class ChatResult:
    content: str
    model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0


class LLMError(RuntimeError):
    pass


def _provider(name: str | None = None) -> str:
    return name or os.environ.get("VEREL_LLM_PROVIDER", DEFAULT_PROVIDER)


def _resolve_key(provider: str) -> str:
    if provider not in PROVIDERS:
        raise LLMError(f"unknown provider {provider!r}; known: {sorted(PROVIDERS)}")
    _, env_key, key_file, _ = PROVIDERS[provider]
    if val := os.environ.get(env_key):
        return val.strip()
    p = Path.home() / ".config" / key_file
    if p.exists():
        return p.read_text().strip()
    raise LLMError(f"no key for {provider!r} (set {env_key} or ~/.config/{key_file})")


def default_model(provider: str | None = None) -> str:
    provider = _provider(provider)
    return os.environ.get("VEREL_CODER_MODEL") or PROVIDERS[provider][3]


def chat(messages: list[dict], *, model: str | None = None, temperature: float = 0.0,
         timeout: int = 180, provider: str | None = None) -> ChatResult:
    """One chat completion. `messages` = [{"role": "...", "content": "..."}]."""
    provider = _provider(provider)
    base = PROVIDERS[provider][0]
    model = model or default_model(provider)

    payload = json.dumps(
        {"model": model, "temperature": temperature, "messages": messages}
    ).encode()
    if not str(base).lower().startswith(("http://", "https://")):
        # never let a misconfigured base_url ship the bearer key to a file:/ or custom-scheme target
        raise LLMError(f"{provider} base_url must be http(s), got {base!r}")
    req = urllib.request.Request(
        f"{base}/chat/completions",
        data=payload,
        headers={"Authorization": f"Bearer {_resolve_key(provider)}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 — scheme guarded http(s) above
            data = json.load(resp)
    except urllib.error.HTTPError as e:
        raise LLMError(f"{provider} HTTP {e.code}: {e.read().decode()[:300]}") from e
    except urllib.error.URLError as e:
        raise LLMError(f"{provider} request failed: {e}") from e

    usage = data.get("usage") or {}
    return ChatResult(
        content=data["choices"][0]["message"]["content"],
        model=data.get("model", model),
        prompt_tokens=usage.get("prompt_tokens", 0),
        completion_tokens=usage.get("completion_tokens", 0),
    )


def have_key(provider: str | None = None) -> bool:
    try:
        _resolve_key(_provider(provider))
        return True
    except LLMError:
        return False
