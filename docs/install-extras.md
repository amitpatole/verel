# Install & extras

Verel keeps the **base wheel light** and puts every heavy dependency behind an *extra* that's lazy-imported
only when you use that feature. Install just what you need.

```bash
pip install verel               # core: the verdict bus + graders that need no extra deps
```

- **Requires Python ≥ 3.10.** The only base dependency is `pydantic>=2`.
- Everything below is `pip install "verel[<extra>]"` (combine them: `pip install "verel[dev,telecom]"`).

## The extras

| Extra | Pulls in | Use it for |
|---|---|---|
| `dev` | pytest · pytest-asyncio · ruff · mypy · **bandit** | The pre-merge CI gate — the test / type / lint / **security** graders. |
| `sight` | `agentvision[render]` | The **eyes** — visual gating of rendered UIs/video, temporal watch. |
| `hearing` | `audel[asr]` | The **ears** — audio/voice grading (DSP grounding + local ASR). |
| `attest` | `pynacl` | **ed25519** publicly-verifiable receipts. HMAC receipts work without it. |
| `container` | `pyseccomp` | The **seccomp-bpf** syscall filter for the bwrap container runner. |
| `mcp` | `mcp` · `anyio` | Expose Verel over the **Model Context Protocol** (`verel-mcp`). |
| `operator` | `kopf` · `kubernetes` | The **Kubernetes operator** reconciling the Verel CRDs (`verel-operator`). |
| `iac` | `pyyaml` | **IaC / cloud-IAM** graders (Terraform plan + RBAC). *Shells out to external binaries* — terraform/tofu, trivy, tflint, checkov, conftest, kube-score, … (not pip deps; `verel doctor` probes them). |
| `telecom` | `pyyaml` · `defusedxml` | The **5G RAN/Core** KPI + config-invariant graders (defusedxml hardens PM-XML / NETCONF against XXE). |
| `telecom-actuator` | `ncclient` | Only the **live** NETCONF apply path of `verel-ci telecom-apply`. The offline planner/dry-run needs none of it. |
| `mem0` | `mem0ai` · `chromadb` | The Mem0 conversational-memory adapter. |
| `postgres` | `psycopg` · `pgvector` | An external multi-machine **brain** (Postgres + pgvector ANN recall). |
| `lancedb` | `lancedb` | An embedded vector store — zero-infra ANN recall. |
| `redis` | `redis` | A networked shared **brain** (atomic optimistic-concurrency over Redis). |

## Things worth knowing

- **`bandit` is load-bearing, not optional-in-spirit.** The pre-merge `security` grader **fails closed**
  if bandit isn't installed — it won't silently skip. That's why it lives in `dev`, which the gate assumes.
- **`attest` unlocks cross-domain verification.** Receipts are HMAC-SHA256 by default (a shared secret
  within one trust domain). Install `attest` to sign/verify **ed25519** receipts a *second party* can
  check with only your public key. Without PyNaCl, an ed25519 verification **fails closed** (never a silent
  green) — see the [trust model](trust-model.md).
- **`iac` doesn't bundle the tools it drives.** It ships one Python dep (`pyyaml`); the actual scanners
  (terraform, trivy, checkov, …) are external binaries you install separately. `verel doctor` reports
  which are present; a required grader whose tool is absent fails the gate closed.
- **Telecom is split on purpose.** `telecom` (plan / grade / dry-run) is fully offline and needs no
  network. `telecom-actuator` adds *only* the live NETCONF session (`ncclient`) — so a CI job that just
  grades or dry-runs a change never takes that dependency.
- **Memory backends are pluggable.** `local` (SQLite, built in) needs nothing; `postgres` / `lancedb` /
  `redis` register via entry points and activate when their extra is installed.

## Command-line entry points

| Command | What it is |
|---|---|
| `verel` | The agent CLI — `verel doctor`, `verel heal`, `verel verify`, … |
| `verel-ci` | The CI gate — `verel-ci check`, `telecom`, `telecom-cfg`, `iac`, … |
| `verel-mcp` | The MCP server (needs `[mcp]`). |
| `verel-operator` | The Kubernetes operator (needs `[operator]`). |

Run `verel doctor` after any install to see exactly what's wired and what's missing.
