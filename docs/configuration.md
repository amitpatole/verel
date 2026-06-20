# Configuration

Verel is configured by a few environment variables — there is no config file.

| Env var | Default | Purpose |
|---|---|---|
| `VEREL_LLM_PROVIDER` | `ollama` | LLM provider for agents — `ollama` or `openai`. |
| `VEREL_CODER_MODEL` | provider default | Override the code-fixer model. |
| `OPENAI_API_KEY` | — | Required when `VEREL_LLM_PROVIDER=openai`. |
| `VEREL_REGISTRY_SECRET` | *dev value* | Signing secret for the skill registry — **set a real one in production**. |
| `VEREL_RUNNER_SECRET` | *dev value* | Grader-runner signing identity — **set a real one in production**. |

## LLM keys

- **Ollama Cloud** (default): key at `~/.config/ollama/key`, model `qwen3-coder:480b`.
- **OpenAI**: set `VEREL_LLM_PROVIDER=openai` and `OPENAI_API_KEY`.

The **eyes** (AgentVision) read their own provider keys — see the
[AgentVision configuration](https://amitpatole.github.io/agent-vision/configuration/).

!!! warning "Production secrets"
    `VEREL_REGISTRY_SECRET` and `VEREL_RUNNER_SECRET` ship with **development defaults** so the
    examples run out of the box. Set real, secret values in any shared or production
    environment — they sign skill-registry artifacts and grader run-receipts.
