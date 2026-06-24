# Configuration

Verel is configured by a few environment variables — there is no config file.

| Env var | Default | Purpose |
|---|---|---|
| `VEREL_LLM_PROVIDER` | `ollama` | LLM provider for agents — `ollama` or `openai`. |
| `VEREL_CODER_MODEL` | provider default | Override the code-fixer model. |
| `OPENAI_API_KEY` | — | Required when `VEREL_LLM_PROVIDER=openai`. |
| `VEREL_REGISTRY_SECRET` | *dev value* | Signing secret for the skill registry — **set a real one in production**. |
| `VEREL_RUNNER_SECRET` | *dev value* | Grader-runner signing identity — **set a real one in production**. |
| `VEREL_GITHUB_TOKEN` | — | Token the REST webhook / spec grader use to read a PR's diff + linked-issue criteria and post commit status. |
| `VEREL_GATE_TOKEN` / `VEREL_GATE_WEBHOOK_SECRET` | — | Bearer token + GitHub webhook HMAC secret for `verel serve` (the REST gate). |

## Memory backend

The shared **brain** (verified memory) is pluggable. Pick a backend by name; each reads its own
connection env. Built-in names are `local` (default) and `remote`; external-DB backends ship behind
extras in later releases (`pip install verel[<db>]`) and register under the same selector.

| Env var | Default | Purpose |
|---|---|---|
| `VEREL_MEMORY_BACKEND` | `local` | Backend to use — `local`, `remote`, or any registered name. If unset but `VEREL_BRAIN_URL` is set, defaults to `remote` (back-compat). |
| `VEREL_MEMORY_STORE` | `~/.config/verel/brain.db` | SQLite path for the `local` backend (`:memory:` for ephemeral). |
| `VEREL_EMBEDDER` | `lexical` | Recall relevance signal — `none`/`lexical` (token overlap, zero-config), `hash` (offline vectors), or `openai` (semantic; needs an OpenAI key). |
| `VEREL_BRAIN_URL` | — | `remote` backend: URL of a `MemoryServer` to share one brain across machines. |
| `VEREL_BRAIN_TOKEN` | — | Bearer token for the remote brain. |
| `VEREL_CLUSTER_TOKEN` | — | Replication-channel credential for the remote brain. |
| `VEREL_BRAIN_CACERT` | — | CA bundle that signed the remote brain's TLS cert. |
| `VEREL_BRAIN_CLIENT_CERT` / `VEREL_BRAIN_CLIENT_KEY` | — | Client cert/key for mTLS to the remote brain. |
| `VEREL_BRAIN_PIN` | — | Pin the remote brain's cert SHA-256 (comma-separated for a set). |
| `VEREL_BRAIN_INSECURE` | `0` | Explicit opt-out letting a token ride a cleartext hop (only behind a TLS-terminating proxy). |
| `VEREL_PRINCIPAL_SEED` | — | 64 hex chars: the identity that authors *signed* beliefs on a remote brain. |

`verel doctor` prints the selected backend and the available ones.

## LLM keys

- **Ollama Cloud** (default): key at `~/.config/ollama/key`, model `qwen3-coder:480b`.
- **OpenAI**: set `VEREL_LLM_PROVIDER=openai` and `OPENAI_API_KEY`.

The **eyes** (AgentVision) read their own provider keys — see the
[AgentVision configuration](https://amitpatole.github.io/agent-vision/configuration/).

!!! warning "Production secrets"
    `VEREL_REGISTRY_SECRET` and `VEREL_RUNNER_SECRET` ship with **development defaults** so the
    examples run out of the box. Set real, secret values in any shared or production
    environment — they sign skill-registry artifacts and grader run-receipts.
