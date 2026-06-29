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

### GitHub Action — fail the build on a FAIL verdict

```yaml
# .github/workflows/verify.yml
name: verify
on: [push, pull_request]
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: amitpatole/verel@v1.2.0
        with:
          repo: .                 # path to gate (default ".")
          install: "-e .[dev]"    # YOUR project's deps so its tests import
          extras: "dev"           # Verel extras (dev = pytest/ruff/mypy graders) — default
          # no-lint: "true"       # skip the lint grader
          # python-version: "3.12"
```

The action installs `verel[dev]`, then `pip install`s your `install:` spec, then runs
`verel-ci check --repo <repo>` (adding `--no-lint` when `no-lint: "true"`), which exits non-zero on a
FAIL verdict and fails the build.

### Gate every PR with the webhook (no MCP host)

`verel serve` exposes an HMAC-verified `POST /github` endpoint. Point a GitHub webhook at it and every
`pull_request` event runs the gate on the configured repo and returns the verdict.

```bash
# 1. Run the gate server next to a checkout of the repo you want to gate.
#    Loopback is zero-config; a routable bind REQUIRES a token AND TLS (it refuses to start otherwise).
export VEREL_GATE_WEBHOOK_SECRET="$(openssl rand -hex 32)"   # the shared secret GitHub signs with
export VEREL_GATE_TOKEN="$(openssl rand -hex 32)"           # bearer for POST /gate (routable bind)
verel serve --repo /path/to/checkout --host 0.0.0.0 --port 8750 \
  --certfile cert.pem --keyfile key.pem
# -> verel gate server on https://0.0.0.0:8750  (repo=/path/to/checkout)
#      POST /gate  ·  POST /github  ·  GET /health
```

Then add the webhook in GitHub (`Settings -> Webhooks -> Add webhook`):

- **Payload URL:** `https://your-host:8750/github`
- **Content type:** `application/json`  (required — the HMAC is verified over the raw JSON body)
- **Secret:** the value of `VEREL_GATE_WEBHOOK_SECRET` above
- **Events:** *Let me select individual events* -> **Pull requests** only

What the endpoint does:

- Verifies GitHub's `X-Hub-Signature-256` (constant-time HMAC) over the raw body **before** anything
  runs — an unsigned or forged event is rejected `401`, no gate runs.
- On a `pull_request` event it gates the **locally configured repo** (it never fetches a URL from the
  payload — no SSRF) and responds `200` with
  `{"event": {...}, "gate": {"verdict": "pass|warn|fail", "issues": [...]}}`.
- A non-PR event responds `200 {"skipped": "not a pull_request event"}`.

> **Known limitation:** `verel serve` returns the verdict in the HTTP **response** — it does **not**
> post a commit status / check back onto the PR by default. To make a red/green check appear on the
> PR, drive the library directly and wire `post_commit_status` (next section), or use the **GitHub
> Action** above, which fails the build on a FAIL verdict.

Verify it locally first (no GitHub needed):

```bash
curl -s http://127.0.0.1:8750/health        # {"status": "ok"}
curl -s -X POST -H "Authorization: Bearer $VEREL_GATE_TOKEN" \
     http://127.0.0.1:8750/gate              # {"verdict": "pass|warn|fail", "issues": [...]}
```

(`/gate` ignores its request body and gates the repo fixed at startup, so an authenticated caller can
never redirect CI at another directory.)

### Post a red/green check back to the PR (library)

`verel serve` only returns the verdict; to set a commit status on the PR, run the `GateServer` from
Python and pass an `on_event` callback that calls `post_commit_status` (both live in
`verel.integrations`). This is the seam the CLI leaves open on purpose (it needs a GitHub token).

```python
import os
from verel.integrations import GateServer, post_commit_status

GH_TOKEN = os.environ["VEREL_GITHUB_TOKEN"]   # a token with `repo:status` scope

def on_event(event, gate):
    # event = {"action", "repo" (owner/name), "number", "sha"} — repo/sha are shape-validated
    state = {"pass": "success", "warn": "success", "fail": "failure"}.get(gate["verdict"], "error")
    post_commit_status(
        event["repo"], event["sha"], state=state, token=GH_TOKEN,
        description=gate.get("reason", "")[:140], context="verel/gate",
    )

srv = GateServer(
    ".", host="0.0.0.0", port=8750,
    auth_token=os.environ["VEREL_GATE_TOKEN"],
    webhook_secret=os.environ["VEREL_GATE_WEBHOOK_SECRET"],
    certfile="cert.pem", keyfile="key.pem",
    on_event=on_event,
).start()
print("gating PRs on", srv.url)
```

`post_commit_status` posts to `POST /repos/{owner}/{repo}/statuses/{sha}` with `state` in
`pending|success|failure|error`, over the hardened transport opener (ignores ambient proxy env,
secure redirects). For GitHub Enterprise pass `api="https://ghe.example.com/api/v3"`.

### pre-commit

This repo ships `.pre-commit-hooks.yaml`:

```yaml
- repo: https://github.com/amitpatole/verel
  rev: v1.2.0
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

### MCP setup — the config block and where each host reads it

```bash
pipx install verel        # (or pip install verel) — provides the verel-mcp binary
verel mcp install         # prints the config + the per-host destination
verel mcp install --json  # just the JSON block
```

The config block is the standard `mcpServers` shape every host understands:

```json
{
  "mcpServers": {
    "verel": {
      "command": "verel-mcp"
    }
  }
}
```

Drop it where your host reads MCP config:

| Host | Config file |
|---|---|
| Claude Desktop | `~/.config/Claude/claude_desktop_config.json` (Linux) · `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| Cursor | `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global) |
| Cline | VS Code settings -> Cline MCP servers (`cline_mcp_settings.json`) |
| Continue | `~/.continue/config.json` (under `mcpServers`) |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

Once connected the agent gets the hero tools — chiefly **`verel_gate`** (run graders -> attested
verdict + verifiable receipt; the agent can no longer self-declare done). Other tools: `verel_sight`,
`verel_verify`, `verel_ci_check`, `verel_spec`, `verel_invariants`, `verel_smell`, `verel_recall`,
`verel_remember`, `verel_build_tool`. See the full [MCP tool reference](usage.md#mcp-tools-the-verified-review-graders).

### In an agent framework (one tool)

Not on MCP? `verel.integrations.sdk` gives a framework-agnostic gate. The agent calls it before it
declares "done"; treat the work complete only on `verdict == "pass"`.

> Note: the SDK `gate()` runs the CI gate (`verel_ci_check`) plus, when you pass `criteria`, the
> spec/intent grader (`verel_spec`). It returns a verdict + grounded issues but **no attested
> receipt** — for a publicly verifiable receipt use the `verel_gate` MCP tool instead.

**Plain callable** (works as a tool in LangChain/LangGraph/CrewAI/AutoGen — anything that takes a
Python function):

```python
from verel.integrations.sdk import gate

result = gate(".", criteria=ticket_text)   # criteria optional; also: files=[...], lint=True
# -> {"verdict": "pass|warn|fail", "issues": [...], "ci": {...}, "spec": {...}}
assert result["verdict"] == "pass"          # only now is the task done
```

**OpenAI function calling:**

```python
from openai import OpenAI
from verel.integrations.sdk import openai_tools, run_tool_call

client = OpenAI()
msgs = [{"role": "user", "content": "Implement X in this repo, then verify it's done."}]
resp = client.chat.completions.create(model="gpt-4o", messages=msgs, tools=openai_tools())
for call in resp.choices[0].message.tool_calls or []:
    out = run_tool_call(call.function.name, call.function.arguments)   # runs the gate
    # feed `out` back as a tool message and loop until out["verdict"] == "pass"
```

**Anthropic / Claude tool use:**

```python
from anthropic import Anthropic
from verel.integrations.sdk import anthropic_tools, run_tool_call

client = Anthropic()
msg = client.messages.create(
    model="claude-3-7-sonnet-latest", max_tokens=1024,
    tools=anthropic_tools(), messages=[{"role": "user", "content": "Build X, then verify done."}])
for block in msg.content:
    if block.type == "tool_use":
        out = run_tool_call(block.name, block.input)   # run_tool_call accepts a dict or JSON str
```

**LangChain / LangGraph:**

```python
from verel.integrations.sdk import langchain_tools   # needs `pip install langchain-core`
tools = langchain_tools()   # [StructuredTool(name="verel_gate", ...)] — bind to your agent/graph
```

`run_tool_call(name, arguments)` only knows `"verel_gate"`; an unknown name returns
`{"error": "..."}` (it never raises), so a stray model tool call can't crash your loop.

See the [Architecture](ARCHITECTURE.md) for how the organs fit together.
