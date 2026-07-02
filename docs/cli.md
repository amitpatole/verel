# CLI reference

Verel ships **four** console scripts:

| Script | Purpose |
|---|---|
| `verel` | The interactive / agent command line (`doctor`, `loop`, `fleet`, `heal`, `verify`, `verify-access`, `serve`, `mcp`, `rules`, `ci`). |
| `verel-ci` | The gated CI entry point — runs the verdict bus and exits non-zero on a `fail` (CI / git-hook). |
| `verel-mcp` | The stdio MCP server a host launches to expose the graders as MCP tools (see [below](#verel-mcp-the-stdio-mcp-server)). |
| `verel-operator` | The Kubernetes (Kopf) operator that reconciles the Verel CRDs (see [below](#verel-operator-the-kubernetes-operator)). |

`verel` and `verel-ci` both support `-h`. `verel-mcp` is normally launched by an agent host, and
`verel-operator` runs inside a cluster — both are documented in their own sections at the end.

## `verel`

| Command | Purpose |
|---|---|
| `doctor` | Check the environment (keys, dependencies). |
| `version` | Print the Verel version. |
| `loop` | Run the visual loop over an artifact (the eyes). |
| `fleet` | LLM-manager fan-out over artifacts toward a goal. |
| `heal` | Self-healing CI — failing tests → an agent fixes → green. |
| `ci` | Delegate to `verel-ci` (agent-run CI). |
| `verify` | Verify a run-receipt — `ed25519` receipts are publicly verifiable (see below). |
| `verify-access` | **Opt-in, online.** Query what the cloud *actually* grants (AWS IAM Access Analyzer / GCP Policy Analyzer / Azure role assignments). Needs cloud read creds from `~/.config`; **not** part of the offline gate. |
| `serve` | Run the REST gate server over a repo (`POST /gate`, `POST /github`). |
| `mcp install` | Print the `verel-mcp` server config + where each agent host expects it. |
| `rules` | Emit a rules-file snippet that makes any agent gate via Verel before "done". |

```bash
verel loop <artifact> [--backend BACKEND] [--max-iter N]
verel fleet <goal> --artifacts A [A ...] [--backend BACKEND] [--max-iter N]
verel heal --repo PATH [--max-rounds N]
verel verify <receipt.json> [--require-public]
verel serve --repo PATH [--host H] [--port P] [--certfile C --keyfile K] [--no-lint]
verel doctor
```

### Runnable examples (copy-paste)

```bash
# Check the environment — keys, tools, and which memory backend will be used.
verel doctor
```

`doctor` prints a checklist (`OK` = present, `--` = missing) and the resolved memory backend.
A representative run:

```text
verel 1.6.0
  OK python 3.11.9
  OK git
  -- ollama cloud key (~/.config/ollama/key)
  -- openai key (fallback)
  OK agentvision (eyes) — `pip install verel[sight]`
  OK ruff (lint grader)
  OK mypy (typecheck grader)
  -- mem0 (rented memory backend) — `pip install verel[mem0]`
  -> memory backend: local  (available: local, remote, postgres, lancedb, redis)
```

> Representative output — the exact `OK`/`--` marks and version reflect your machine.

```bash
# Visual loop (the eyes): an agent fixes an artifact until AgentVision passes.
verel loop ./mockups/login.png --backend local --max-iter 5

# Manager fan-out: one goal → workers fix each artifact in parallel.
verel fleet "ship the checkout flow" --artifacts cart.png checkout.png receipt.png

# Self-healing CI: failing tests → an agent fixes → green (exit 0 iff healed).
verel heal --repo . --max-rounds 3

# Delegate to verel-ci: everything after `ci` is passed straight through (argparse REMAINDER).
verel ci check --repo .          # identical to:  verel-ci check --repo .
verel ci check --repo . --no-lint
```

`verel ci …` forwards its remainder verbatim to `verel-ci`, so any `verel-ci` subcommand/flag
(`check`, `precommit`, `iac`, `install`) works behind `verel ci`. See [`verel-ci`](#verel-ci-the-ci-gate).

```bash
# Grade an IaC artifact OFFLINE — catch a dangerous cloud-IAM change before apply (exit 1 on FAIL):
terraform plan -out tfplan.bin && terraform show -json tfplan.bin > tfplan.json
verel ci iac --repo . --plan tfplan.json        # drift (INFO) + IAM risks (gate)
verel ci iac --repo . --manifests rendered.json # K8s RBAC sensor (kubectl -o json)
```

```bash
# OPT-IN effective-access check — what does the cloud ACTUALLY grant? (online; reads creds from ~/.config)
verel verify-access --cloud aws --policy-file policy.json                 # static: IAM Access Analyzer validate-policy
verel verify-access --cloud aws --principal-arn arn:aws:iam::123456789012:role/app \
                    --action iam:PassRole sts:AssumeRole                  # EFFECTIVE: simulate-principal-policy
verel verify-access --cloud gcp   --scope projects/my-proj               # analyze-iam-policy
verel verify-access --cloud azure                                        # role assignment list
# Fails closed (exit 2) when the cloud's creds are absent; never runs in the offline gate.
```

For AWS, `--policy-file` is **static validation** (does this policy *document* have findings?) while
`--principal-arn` is **effective access** — it asks the account, via `simulate-principal-policy`, what a
role/user is *actually* allowed across all attached/inline/SCP policies. `--action` defaults to the
privilege-escalation primitives when omitted. GCP needs `--scope` (e.g. `projects/<id>`); Azure lists
role assignments. The verifier never claims a cloud identity it didn't check, and reuses the offline
sensor's privesc sets so the live check is never *blinder* than the plan grader.

### Verify a receipt (`verel verify`) — publicly verifiable "done"

A gate can emit a **run-receipt**: a signed attestation that a required grader actually ran the frozen
suite over the changed files and produced the graded verdict. `verel verify` checks one with **no
trust in its producer** — for an `ed25519` receipt it needs only the runner's *public* key, so a
stranger (a reviewer, an auditor, a downstream consumer) can confirm an agent's `pass` was real.

```bash
verel verify receipt.json                  # exit 0 iff valid
verel verify receipt.json --require-public  # reject HMAC; demand ed25519 public verifiability
```
```text
OK  ed25519  runner=ed25519:Ab3kQ1z9_xYwTuVe  [public-verifiable]
   ed25519 verified against a trusted public key
```
- **Exit code** — `0` valid · `1` invalid/forged/untrusted-key · `2` couldn't read the receipt.
- **`[public-verifiable]`** = signed `ed25519`, checked against a trusted public key (no shared secret);
  **`[shared-secret]`** = an `hmac-sha256` receipt verified inside one trust domain. `--require-public`
  fails closed on anything that isn't `ed25519`.
- Publish a verifier's trust by dropping `<key_id>.pub` into `~/.config/verel/trusted_keys/`
  (`VEREL_TRUSTED_KEYS` overrides the dir). An untrusted `key_id` can't verify itself into trust. The
  same check is the **`verel_verify`** MCP tool. See [Configuration](configuration.md#receipts-signing-trusted-keys).

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
  (`VEREL_GATE_WEBHOOK_SECRET`) before doing anything, then gates the PR and returns the verdict **in
  the HTTP response**. It does **not** post a commit status back to GitHub by default (no PR check
  appears) — wire that yourself via the library `post_commit_status(repo, sha, state=…, token=…)`
  helper from a custom `on_event` handler.
- Secrets come from the environment, never the command line. Bind policy, TLS, body-size cap,
  slowloris timeout, and connection caps are inherited from the hardened `verel.transport`.
- **`VEREL_GATE_INSECURE`** (`1`/`true`/`yes`/`on`) waives the in-process TLS requirement for a
  non-loopback bind — use it **only** when a TLS-terminating ingress or proxy sits in front (the
  Helm chart's behind-ingress path). Auth is **still** required: `VEREL_GATE_TOKEN` must be set, or
  the server still fails closed. Without this flag a routable bind needs `--certfile`/`--keyfile`.
  See [Configuration](configuration.md#receipts-signing-trusted-keys) and
  [Deploy on Kubernetes](kubernetes.md#quickstart-a-the-gate-server-helm).

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

## Run a Verified-Review grader from the shell

Most Verified-Review graders are exposed as a **Python API** and as **MCP tools** (`verel_spec`,
`verel_invariants`, `verel_smell` — see the [Developer guide](usage.md)). The **mutation**
(test-effectiveness) grader additionally ships a standalone module CLI:

```bash
# Mutate the changed source files and re-run YOUR suite; a surviving mutant prints in the JSON.
python -m verel.ci.mutation --repo . --targets billing.py,orders.py

# Tune the budget (defaults shown): up to 25 mutants/file, 120s per suite-run.
python -m verel.ci.mutation --repo . --targets billing.py --cap 25 --timeout 120

# Pass extra args through to pytest (e.g. restrict to the affected tests).
python -m verel.ci.mutation --repo . --targets billing.py --test-args "tests/test_billing.py"
```

It prints one JSON line — `{"baseline_pass": true, "total": 3, "survivors": [...]}` — which the
`mutation_spec` grader parses on the verdict bus. A **surviving mutant** (a fault no test catches) is
a deterministic FAIL; a non-green baseline reports `baseline_pass: false` and assesses nothing
(test-effectiveness is meaningless on a red suite).

> There is **no** `verel`/`verel-ci` subcommand and **no** MCP tool for mutation, and `verel_gate`
> does not run it — wire it into a gate with `premerge_stage(repo, mutation=["billing.py"])` or
> `mutation_spec(...)` in Python (see the [Developer guide](usage.md#agent-run-cicd-verelci)).

The spec, invariant, and smell graders have **no CLI**; invoke them via the Python API or their MCP
tools (`verel_spec` / `verel_invariants` / `verel_smell`).

## MCP tools — what the agent can call

`verel mcp install` wires the `verel-mcp` server into your agent host. Once installed, the agent can
call any of these (each returns a structured verdict; an unknown tool or a tool error comes back as
`{"error": …}` rather than dropping the connection):

| MCP tool | What it does |
|---|---|
| `verel_gate` | Run the verdict bus (tests + lint + types) over a repo; work is "done" only on `pass`. |
| `verel_ci_check` | Run the inner-loop CI stage over a repo and return the verdict. |
| `verel_sight` | Grade a render / UI / image artifact (the eyes) and return grounded issues. |
| `verel_verify` | Verify a run-receipt — confirm a prior verdict was real (`ed25519` = publicly verifiable). |
| `verel_spec` | Spec/intent grader: extract the ticket's acceptance criteria, compile + run checks, gate on an intent mismatch. |
| `verel_invariants` | Business-rule grader: compile declared invariants into property checks, run them, gate a falsified rule. |
| `verel_smell` | Over-engineering / scope-creep grader (AST only, no execution): a complexity budget + a speculative-generality flag. |
| `verel_recall` | Recall verified facts/skills from the shared brain (operator-selected backend; not agent-redirectable). |
| `verel_remember` | Record a fact/skill into the brain (enters as a candidate; re-verifies before it's trusted). |
| `verel_build_tool` | Tool-smith: detect → scaffold → test → register a new tool under a capability jail (needs an LLM key). |

The spec, invariants, and build-tool tools execute generated code under real OS isolation (bwrap
`--unshare-all` + seccomp + rlimits) and **fail closed** when no isolation is available.

## `verel-mcp` — the stdio MCP server

`verel-mcp` is the stdio MCP server that exposes the tools above (`verel_gate`, `verel_sight`,
`verel_verify`, …) to any MCP host. It needs the MCP extra:

```bash
pip install "verel[mcp]"
```

You normally **don't run it by hand** — `verel mcp install` prints the config that wires it into a
host (Claude Code/Desktop, Cursor, Cline, Continue, Windsurf…), which then launches it over stdio as
needed. The equivalent invocation a host runs is:

```bash
python -m verel.mcp_server     # == the verel-mcp console script; speaks MCP over stdio
```

It takes no flags and communicates only on stdin/stdout, so running it in a terminal just blocks
waiting for an MCP client. See [Integrations & MCP install](usage.md#mcp-tools-the-verified-review-graders)
and the [MCP tools](#mcp-tools-what-the-agent-can-call) table above.

## `verel-operator` — the Kubernetes operator

`verel-operator` is the [Kopf](https://kopf.readthedocs.io/) operator that reconciles the Verel CRDs
(`GateRun`, `Brain`, `GatewayService`, `VerelFleet`) inside a cluster. It needs the operator extra:

```bash
pip install "verel[operator]"     # kopf + the kubernetes client
```

It **takes no flags** and runs as the entrypoint of the operator Deployment. The equivalent form:

```bash
python -m verel.operator     # == the verel-operator console script
```

On start it configures Kopf and serves Kopf's liveness probe at
**`http://0.0.0.0:8080/healthz`**, so the operator Deployment has a real health signal for its
Kubernetes liveness probe. You deploy it via the chart/manifests rather than invoking it directly —
see [Deploy on Kubernetes](kubernetes.md#quickstart-b-the-operator-crds).
