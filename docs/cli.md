# CLI reference

Verel ships two console scripts: **`verel`** (interactive / agent commands) and **`verel-ci`**
(the gated CI entry point). Both support `-h`.

## `verel`

| Command | Purpose |
|---|---|
| `doctor` | Check the environment (keys, dependencies). |
| `version` | Print the Verel version. |
| `loop` | Run the visual loop over an artifact (the eyes). |
| `fleet` | LLM-manager fan-out over artifacts toward a goal. |
| `heal` | Self-healing CI — failing tests → an agent fixes → green. |
| `ci` | Delegate to `verel-ci` (agent-run CI). |
| `mcp install` | Print the `verel-mcp` server config + where each agent host expects it. |
| `rules` | Emit a rules-file snippet that makes any agent gate via Verel before "done". |

```bash
verel loop <artifact> [--backend BACKEND] [--max-iter N]
verel fleet <goal> --artifacts A [A ...] [--backend BACKEND] [--max-iter N]
verel heal --repo PATH [--max-rounds N]
verel doctor
```

### Plug Verel into your agent (one line)

Make any MCP-host agent (Claude Code/Desktop, Cursor, Cline, Continue, Windsurf…) gate its own
work — no workflow change:

```bash
verel mcp install                       # prints the verel-mcp config + per-host install path
verel mcp install --json                # just the JSON config block
verel rules --target cursor --write     # writes .cursorrules telling the agent to call verel_gate
verel rules --target agents --write     # → AGENTS.md   (also: claude|copilot|windsurf)
verel rules                             # print the snippet instead of writing it
```

The rules snippet instructs the agent: before declaring any task done, call `verel_gate`; treat it
done only on `verdict: pass`; never edit tests to go green. `--write` appends idempotently (a second
run is a no-op) and preserves existing file content.

### Gate over HTTP (`verel serve`) — for CI, webhooks, any language

A language-agnostic gate: run a small HTTP server over one repo; any CI step, script, or webhook
`POST`s and gets the verdict — no MCP host needed.

```bash
verel serve --repo .                       # loopback, zero-config: POST /gate · POST /github · GET /health
VEREL_GATE_TOKEN=… verel serve --repo . --host 0.0.0.0 \
  --certfile cert.pem --keyfile key.pem    # a routable bind REQUIRES a token AND TLS, or it refuses to start
```

- `POST /gate` → runs the gate on the configured repo, returns `{verdict, issues}` (bearer-auth when
  `VEREL_GATE_TOKEN` is set). The repo is fixed at startup — a caller can't redirect CI at another path.
- `POST /github` → verifies GitHub's `X-Hub-Signature-256` HMAC over the raw body
  (`VEREL_GATE_WEBHOOK_SECRET`) before doing anything, then gates the PR and returns the verdict.
- Secrets come from the environment, never the command line. Bind policy, TLS, body-size cap,
  slowloris timeout, and connection caps are inherited from the hardened `verel.transport`.

## `verel-ci` — the CI gate

Runs the verdict bus (tests + lint + types) and exits non-zero on a `fail` verdict, so it
wires straight into CI or a git hook.

| Command | Purpose |
|---|---|
| `check --repo PATH [--no-lint]` | Run the inner-loop stage, print the verdict, exit non-zero on FAIL. |
| `precommit --repo PATH [--no-lint]` | Pre-commit stage — aborts a commit on FAIL. |
| `install --repo PATH` | Install a native git pre-commit hook. |

```bash
verel-ci check --repo .        # gate; exit 0 unless verdict == fail
verel-ci install --repo .      # wire a native pre-commit hook
```

For drop-in CI/pre-commit usage (GitHub Action, `.pre-commit-config.yaml`) see
[Get started](getting-started.md).
