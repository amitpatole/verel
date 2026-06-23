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
      - uses: amitpatole/verel@v0.35.0
        with:
          repo: .
          install: "-e .[dev]"     # your project deps so its tests import
```

**pre-commit** (this repo ships `.pre-commit-hooks.yaml`):

```yaml
- repo: https://github.com/amitpatole/verel
  rev: v0.35.0
  hooks: [{ id: verel-precommit }]
```

**Native git hook:** `verel-ci install --repo .`

## In your agents

- **`verel-mcp`** exposes the verdict bus + memory to any MCP host (Cursor, Claude, …).
- Add **`verel[sight]`** so the agent's work is gated by the **eyes**
  ([AgentVision](https://amitpatole.github.io/agent-vision/)) — visual defects, intent match,
  and (via `verel.senses.watch`) verified playback over time.

See the [Architecture](ARCHITECTURE.md) for how the organs fit together.
