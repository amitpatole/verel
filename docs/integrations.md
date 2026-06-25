# Integrations

Verel grades *artifacts*, so it plugs into whatever stack you already run — it never asks you to
rip-and-replace. Pick the channel that matches where your team works: an MCP host, your CI, a GitHub
webhook, an agent framework, or Kubernetes. Every channel returns the same thing — a verdict
(`pass` / `warn` / `fail`) plus grounded `file:line` issues — so "done" means the same everywhere.

## Channels at a glance

| Channel | What it does | Entry point | Where |
|---|---|---|---|
| **MCP server** | Exposes the gate + graders + brain to any MCP host; the agent calls `verel_gate` before "done" | `verel-mcp` | [↓](#mcp-server-any-host) · [tools](usage.md#mcp-tools-the-verified-review-graders) |
| **Per-host install** | One-line setup for Cursor / Claude Code / Cline / Continue / Windsurf | `verel mcp install` | [↓](#per-host-mcp-setup) |
| **Rules nudge** | Drops the gate instruction into a host's rules file (zero-code adoption) | `verel rules --target …` | [↓](#per-host-mcp-setup) |
| **REST gate** | Language-agnostic HTTP gate over one repo — any CI / script `POST`s, gets a verdict | `verel serve` | [↓](#rest-gate-any-language-any-ci) |
| **GitHub PR webhook** | HMAC-verified `pull_request` events run the gate on the configured repo | `POST /github` | [↓](#github-pr-webhook) |
| **Commit-status callback** | Posts a red/green check back onto the PR | `post_commit_status` / `on_event` | [↓](#post-a-check-back-to-the-pr) |
| **GitHub Action** | Fails the build on a FAIL verdict | `amitpatole/verel@v1.0.1` | [↓](#ci-matrix) |
| **pre-commit hook** | Gates the commit on the verdict bus | `.pre-commit-hooks.yaml` (`verel-precommit`) | [↓](#pre-commit) |
| **Agent SDK shims** | The gate as a tool for OpenAI / Anthropic / LangChain / LangGraph / CrewAI / AutoGen / Claude Agent SDK | `verel.integrations.sdk` | [↓](#agent-sdk-shims) |
| **Gate a PR vs. its ticket** | Pull a PR's acceptance criteria + diff from GitHub, grade intent | `grade_pr()` / `verel_spec` | [↓](#gate-a-pr-against-its-ticket) |
| **Kubernetes** | Helm chart + Kopf operator (`GateRun` / `Brain` / `GatewayService` / `VerelFleet`) | chart + operator | [k8s](kubernetes.md) |

---

## MCP server (any host)

`verel-mcp` exposes the verdict bus, the Verified-Review graders, and the shared brain to any MCP
host. Install the binary, register it, and the agent gets `verel_gate` (run graders → attested
verdict + a verifiable receipt) — it can no longer self-declare "done".

```bash
pipx install verel        # (or pip install verel) — provides the verel-mcp binary
verel mcp install         # prints the config block + the per-host destination
verel mcp install --json  # just the JSON block
```

The config is the standard `mcpServers` shape every host understands:

```json
{
  "mcpServers": {
    "verel": {
      "command": "verel-mcp"
    }
  }
}
```

Tools the agent gets: `verel_gate`, `verel_sight`, `verel_verify`, `verel_ci_check`, `verel_spec`,
`verel_invariants`, `verel_smell`, `verel_recall`, `verel_remember`, `verel_build_tool`. See the full
[MCP tool reference](usage.md#mcp-tools-the-verified-review-graders) and the
[Graders reference](graders.md).

---

## Per-host MCP setup

`verel mcp install` prints the config and where to drop it. The block is identical per host; only the
destination file differs:

| Host | Config file |
|---|---|
| Claude Desktop | `~/.config/Claude/claude_desktop_config.json` (Linux) · `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| Cursor | `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global) |
| Cline | VS Code settings → Cline MCP servers (`cline_mcp_settings.json`) |
| Continue | `~/.continue/config.json` (under `mcpServers`) |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

Claude Code reads the same `mcpServers` block — add it to your host config and the gate is live.

### Rules nudge (zero-code, any agent)

Not every host speaks MCP. `verel rules` writes the gate instruction into a host's rules file so the
agent gates its own work with no MCP server at all:

```bash
verel rules --target cursor  --write   # → .cursorrules
verel rules --target claude  --write   # → CLAUDE.md
verel rules --target agents  --write   # → AGENTS.md
verel rules --target windsurf --write  # → .windsurfrules
verel rules --target copilot --write   # → .github/copilot-instructions.md
verel rules                            # print the snippet instead of writing it
```

`--write` appends idempotently (a second run is a no-op) and preserves existing content.

> **GitHub Copilot is rules-only.** `verel rules --target copilot` writes
> `.github/copilot-instructions.md` — a **text nudge** that tells Copilot to gate before "done".
> There is **no live MCP gate**: Copilot has no MCP-tool path here, so it can't actually *run*
> `verel_gate`. For an enforced gate on Copilot-authored code, wire the [CI](#ci-matrix) or
> [PR webhook](#github-pr-webhook) channel — those execute the verdict bus, not just instruct it.

---

## REST gate (any language, any CI)

`verel serve` runs a small HTTP gate over **one** repo. Any CI step, script, or webhook `POST`s and
gets the verdict — no MCP host, no Python in your build. Loopback is zero-config; a routable bind
**requires** a token AND TLS or it refuses to start.

```bash
verel serve --repo .                       # loopback: POST /gate · POST /github · GET /health · GET /ready

VEREL_GATE_TOKEN=…  verel serve --repo . --host 0.0.0.0 \
  --certfile cert.pem --keyfile key.pem    # routable bind: token + TLS mandatory
```

```bash
curl -s http://127.0.0.1:8750/health        # {"status": "ok"}
curl -s -X POST -H "Authorization: Bearer $VEREL_GATE_TOKEN" \
     http://127.0.0.1:8750/gate             # {"verdict": "pass|warn|fail", "issues": [...]}
```

`POST /gate` ignores its request body and gates the repo fixed at startup, so an authenticated caller
can never redirect CI at another directory. See [`verel serve`](cli.md#gate-over-http-verel-serve-for-ci-webhooks-any-language).

### GitHub PR webhook

`POST /github` verifies GitHub's `X-Hub-Signature-256` HMAC over the **raw** body
(`VEREL_GATE_WEBHOOK_SECRET`) **before** anything runs — an unsigned or forged event is rejected
`401`, no gate runs. On a `pull_request` event it gates the **locally configured** repo (it never
fetches a URL from the payload — no SSRF) and responds `200` with
`{"event": {...}, "gate": {"verdict": …, "issues": […]}}`. A non-PR event responds
`200 {"skipped": "not a pull_request event"}`.

In GitHub (`Settings → Webhooks → Add webhook`): Payload URL `https://your-host:8750/github`,
Content type **`application/json`** (required — the HMAC is over the raw JSON), Secret =
`VEREL_GATE_WEBHOOK_SECRET`, Events = **Pull requests** only.

### Post a check back to the PR

`verel serve` returns the verdict in the HTTP **response** — it does **not** set a commit status by
default. To make a red/green check appear on the PR, run `GateServer` from Python with an `on_event`
callback that calls `post_commit_status` (both in `verel.integrations`):

```python
import os
from verel.integrations import GateServer, post_commit_status

GH_TOKEN = os.environ["VEREL_GITHUB_TOKEN"]   # needs the `repo:status` scope

def on_event(event, gate):
    # event = {"action", "repo" (owner/name), "number", "sha"} — repo/sha are shape-validated
    state = {"pass": "success", "warn": "success", "fail": "failure"}.get(gate["verdict"], "error")
    post_commit_status(event["repo"], event["sha"], state=state, token=GH_TOKEN,
                       description=gate.get("reason", "")[:140], context="verel/gate")

GateServer(".", host="0.0.0.0", port=8750,
           auth_token=os.environ["VEREL_GATE_TOKEN"],
           webhook_secret=os.environ["VEREL_GATE_WEBHOOK_SECRET"],
           certfile="cert.pem", keyfile="key.pem", on_event=on_event).start()
```

`post_commit_status(repo, sha, *, state, token, …)` posts to
`POST /repos/{owner}/{repo}/statuses/{sha}` with `state ∈ pending|success|failure|error`. For GitHub
Enterprise pass `api="https://ghe.example.com/api/v3"`.

---

## CI matrix

Same verdict bus, three drop-ins. The **GitHub Action** is canonical; everything else shells out to
`verel-ci check`.

### GitHub Action

```yaml
# .github/workflows/verify.yml
name: verify
on: [push, pull_request]
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: amitpatole/verel@v1.0.1
        with:
          repo: .                 # path to gate (default ".")
          install: "-e .[dev]"    # YOUR project's deps so its tests import
          extras: "dev"           # Verel extras (dev = pytest/ruff/mypy graders) — default
          # no-lint: "true"       # skip the lint grader
          # python-version: "3.12"
```

The action installs `verel[dev]`, `pip install`s your `install:` spec, then runs
`verel-ci check --repo <repo>` (adding `--no-lint` when `no-lint: "true"`) — non-zero exit on a FAIL
verdict fails the build.

### GitLab CI

```yaml
# .gitlab-ci.yml
verel-gate:
  image: python:3.12
  script:
    - pip install "verel[dev]"
    - pip install -e ".[dev]"          # your project's deps so its tests import
    - verel-ci check --repo .          # exits non-zero on a FAIL verdict → the job fails
```

### Any CI (the one-liner)

```bash
pip install "verel[dev]" && verel-ci check --repo .   # exit 0 unless verdict == fail
```

For a build that has no Python — or where you'd rather not install Verel per-job — stand up
[`verel serve`](#rest-gate-any-language-any-ci) once and `POST /gate` from the pipeline instead.

### pre-commit

```yaml
# .pre-commit-config.yaml
- repo: https://github.com/amitpatole/verel
  rev: v1.0.1
  hooks: [{ id: verel-precommit }]
```

`verel-precommit` runs the pre-commit stage and aborts the commit on a FAIL verdict. The hook runs in
pre-commit's isolated venv, so a heavy project (whose tests need its own deps importable) is better
served by the GitHub Action above or a native git hook via `verel-ci install --repo .`.

---

## Gate a PR against its ticket

The highest-value channel for a team already living in GitHub: does the change actually implement
what the PR/issue **asked for**? `grade_pr` pulls the PR's acceptance criteria (its title/body +
linked issues) **and** its diff straight from GitHub, then runs the [spec/intent
grader](graders.md) — the LLM only
*proposes* checks from the ticket; *execution* decides, so a hallucinated judge can neither block a
good merge nor pass a broken one.

```python
import os
from verel.ci.spec import grade_pr

rep = grade_pr(
    ".",                 # local checkout to grade against
    "octo/api",          # owner/name on GitHub
    42,                  # PR number
    token=os.environ["VEREL_GITHUB_TOKEN"],
)
print(rep.verdict)                         # Verdict.PASS / WARN / FAIL
for issue in rep.issues:                   # grounded INTENT_MISMATCH per violated criterion
    print(issue.locator, "-", issue.message)
```

- **`VEREL_GITHUB_TOKEN`** needs **PR read** to fetch the ticket + diff. (If you *also* post the
  result back with [`post_commit_status`](#post-a-check-back-to-the-pr), the token additionally needs
  the **`repo:status`** scope.)
- **GitHub Enterprise:** `grade_pr(".", "octo/api", 42, token=…, api="https://ghe.example.com/api/v3")`.
- **Needs an LLM** — `grade_pr` defaults `chat=default_chat()` to compile the criteria into checks
  (configure via `VEREL_LLM_PROVIDER`); the executed checks run under OS-isolation and **fail closed**
  (the criterion stays advisory) when bwrap is absent.
- Full signature: `grade_pr(repo, repo_full_name, number, *, token=None, api="https://api.github.com",
  chat=None, n=2) -> Report`.

From an MCP host, the same grader is the **`verel_spec`** tool — pass the ticket text as `criteria`
and the changed paths as `files`.

---

## Agent SDK shims

`verel.integrations.sdk` gives a framework-agnostic gate: hand the agent a *tool* that runs the gate
and reads the verdict before it declares "done". No heavy SDK is imported — the snippets below show
the per-framework wiring.

> The SDK `gate()` runs the CI gate (and, with `criteria`, the spec grader). It returns a verdict +
> grounded issues but **no attested receipt** — for a publicly verifiable receipt use the
> `verel_gate` MCP tool instead.

**Plain callable** (CrewAI / AutoGen / Claude Agent SDK — anything that takes a Python function):

```python
from verel.integrations.sdk import gate

result = gate(".", criteria=ticket_text)   # criteria optional; also: files=[...], lint=True
assert result["verdict"] == "pass"          # only now is the task done
```

**OpenAI** function calling:

```python
from openai import OpenAI
from verel.integrations.sdk import openai_tools, run_tool_call

client = OpenAI()
resp = client.chat.completions.create(model="gpt-4o", tools=openai_tools(),
    messages=[{"role": "user", "content": "Implement X in this repo, then verify it's done."}])
for call in resp.choices[0].message.tool_calls or []:
    out = run_tool_call(call.function.name, call.function.arguments)   # runs the gate
    # feed `out` back as a tool message and loop until out["verdict"] == "pass"
```

**Anthropic / Claude** tool use:

```python
from anthropic import Anthropic
from verel.integrations.sdk import anthropic_tools, run_tool_call

client = Anthropic()
msg = client.messages.create(model="claude-sonnet-4-5", max_tokens=1024,
    tools=anthropic_tools(), messages=[{"role": "user", "content": "Build X, then verify done."}])
for block in msg.content:
    if block.type == "tool_use":
        out = run_tool_call(block.name, block.input)   # accepts a dict or a JSON string
```

**LangChain / LangGraph** — bind the gate as a node/tool:

```python
from verel.integrations.sdk import langchain_tools   # needs `pip install langchain-core`

tools = langchain_tools()   # [StructuredTool(name="verel_gate", ...)] — bind to your agent or graph
```

`run_tool_call(name, arguments)` only knows `"verel_gate"`; an unknown name returns
`{"error": "..."}` (it never raises), so a stray model tool call can't crash your loop.

---

## Kubernetes

Run the brain, the gate, and the gateway in-cluster with the Helm chart and the Kopf operator (the
`GateRun`, `Brain`, `GatewayService`, and `VerelFleet` CRDs). See
[Deploy on Kubernetes / k3s](kubernetes.md).

See also the [Developer guide](usage.md) for the full surface and the
[Architecture](ARCHITECTURE.md) for how the organs fit together.
