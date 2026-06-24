# Get started

## Install

```bash
pip install verel              # core
pip install "verel[sight]"     # + AgentVision eyes (visual gating + temporal watch)
pip install "verel[dev]"       # + pytest/ruff/mypy graders for the CI gate
verel doctor                   # check your environment
```

Default LLM is **Ollama Cloud** (`~/.config/ollama/key`, model `qwen3-coder:480b`); set
`VEREL_LLM_PROVIDER=openai` to switch.

## The gate (no LLM key)

Unify tests + lint + types into one verdict over any repo:

```bash
verel-ci check --repo .        # verdict bus gate; non-zero exit on FAIL
```

```python
from verel.ci import inner_loop_stage, run_stage
result = run_stage(inner_loop_stage(".", with_lint=True))
print(result.verdict)          # pass / warn / fail
```

## Self-healing CI (with an LLM)

```bash
verel heal --repo .            # failing tests → an agent patches → green
```

## Drop it into your workflow

**GitHub Action** — fail the build on a FAIL verdict:

```yaml
# .github/workflows/verify.yml
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: amitpatole/verel@v0.50.0
        with:
          repo: .
          install: "-e .[dev]"     # your project deps so its tests import
```

**Gate over HTTP / from a PR webhook** — `verel serve --repo .` exposes `POST /gate` and an
HMAC-verified `POST /github` so any CI, script, or GitHub PR webhook can gate without an MCP host
(loopback is zero-config; a routable bind requires a token **and** TLS). See [CLI](cli.md#gate-over-http-verel-serve--for-ci-webhooks-any-language).

**pre-commit** (this repo ships `.pre-commit-hooks.yaml`):

```yaml
- repo: https://github.com/amitpatole/verel
  rev: v0.50.0
  hooks: [{ id: verel-precommit }]
```

**Native git hook:** `verel-ci install --repo .`

## In your agents — plug in, don't rip and replace

Verel grades *artifacts*, so it inserts into whatever agent stack you already run. One line:

```bash
verel mcp install                    # add the verel-mcp server to your host (Cursor/Claude/Cline/…)
verel rules --target cursor --write  # tell the agent: call verel_gate before "done" (also agents|claude|copilot)
```

- **`verel-mcp`** exposes the verdict bus + memory to any MCP host; the agent calls `verel_gate`
  before declaring done and self-corrects on a grounded FAIL.
- **`verel rules`** drops the gate instruction into `.cursorrules` / `CLAUDE.md` / `AGENTS.md` /
  copilot-instructions so *any* agent gates its own work — zero-code adoption.
- Add **`verel[sight]`** so the agent's work is also gated by the **eyes**
  ([AgentVision](https://amitpatole.github.io/agent-vision/)) — visual defects, intent match,
  and (via `verel.senses.watch`) verified playback over time.

### In an agent framework (one tool)

Not on MCP? `verel.integrations.sdk` gives a framework-agnostic `gate()` callable + function-calling
schemas, so the agent calls it before declaring done — works with OpenAI / Anthropic / Claude Agent
SDK / LangGraph / CrewAI / AutoGen:

```python
from verel.integrations.sdk import gate, openai_tools, anthropic_tools, run_tool_call

gate(".", criteria=ticket_text)          # universal callable → {"verdict": "pass"|"warn"|"fail", ...}

tools = openai_tools()                    # or anthropic_tools() — function-calling schema
result = run_tool_call("verel_gate", model_tool_call.arguments)   # run the call your loop receives
```

LangChain/LangGraph/CrewAI/AutoGen accept the plain `gate` callable as a tool
(`StructuredTool.from_function(gate)` / `@tool` / `register_function`); `langchain_tools()` adapts it
for you when LangChain is installed.

See the [Architecture](ARCHITECTURE.md) for how the organs fit together.
