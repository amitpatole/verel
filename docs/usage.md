# Developer guide

How to use Verel as a library, a CLI, a CI gate, and an MCP server. Every example here runs
against the real API; the ones that need a model say so.

The one idea underneath all of it: **an agent's output is a hypothesis until a grader returns a
verdict.** You compose graders (any sense — tests, lint, types, vision, perf, security) into a
`Report`, reduce them with `gate()`, and only verified work is allowed to compound.

---

## Install

```bash
pip install verel                 # core (only dependency: pydantic)
pip install "verel[dev]"          # + pytest / ruff / mypy graders (the CI gate)
pip install "verel[sight]"        # + AgentVision eyes (visual gating + temporal watch)
pip install "verel[container]"    # + seccomp-bpf for the bwrap tool sandbox
pip install "verel[mem0]"         # + the rented mem0 memory backend
pip install "verel[mcp]"          # + the MCP server
```

| Extra | Pulls in | Enables |
|---|---|---|
| `dev` | pytest, ruff, mypy | the Python test/lint/type graders |
| `sight` | `agentvision[render]` | `verel.senses` — DOM/contrast/OCR vision + `watch` |
| `container` | `pyseccomp` | the seccomp syscall filter on the `bwrap` tool runner |
| `mem0` | `mem0ai`, `chromadb` | `Mem0Memory` as the `MemoryView` backend |
| `mcp` | `mcp`, `anyio` | `verel-mcp` (Cursor / Claude / any MCP host) |

Verify your environment:

```bash
verel doctor
```

### Configure the LLM

Anything that authors or judges with a model uses the provider seam in `verel.agents.llm`. Default
is **Ollama Cloud**; **OpenAI** is the bundled fallback.

```bash
export VEREL_LLM_PROVIDER=ollama        # default; or: openai
export VEREL_CODER_MODEL=qwen3-coder:480b
```

Keys resolve from an env var first, then `~/.config/<provider>/key`:

| Provider | Env var | Key file | Default model |
|---|---|---|---|
| `ollama` | `OLLAMA_API_KEY` | `~/.config/ollama/key` | `qwen3-coder:480b` |
| `openai` | `OPENAI_API_KEY` | `~/.config/OpenAI/key` | `gpt-4o-mini` |

Everything that calls a model takes an injectable `chat` function, so unit tests (and the
offline examples in `examples/`) run with no key at all.

---

## The surfaces

| Surface | Entry point | Use it for |
|---|---|---|
| **Library** | `import verel` | building your own harness on the verdict bus |
| **CLI** | `verel …` | `doctor` · `loop` · `fleet` · `heal` · `ci` |
| **CI CLI / git hook** | `verel-ci …` | a verdict-bus gate in CI or a pre-commit hook |
| **MCP server** | `verel-mcp` | exposing gate / recall / build-tool / ci-check to an MCP host |
| **GitHub Action** | `amitpatole/verel@v1.2.0` | failing a build on a FAIL verdict |
| **pre-commit** | `.pre-commit-hooks.yaml` | gating commits |

### CLI reference

```bash
verel doctor                              # environment + key check
verel version
verel loop <artifact> [--backend local] [--max-iter 5]    # ultracode visual loop (needs sight + LLM)
verel fleet "<goal>" --artifacts a.html b.html            # LLM manager fan-out
verel heal --repo . [--max-rounds 3]                      # self-healing CI (needs LLM)
verel ci <args…>                                          # delegates to verel-ci
```

```bash
verel-ci check    --repo .   [--no-lint]   # run the inner-loop stage; print the verdict
verel-ci precommit --repo .                # pre-commit stage; non-zero exit aborts the commit
verel-ci install  --repo .                 # install the native git pre-commit hook
```

### GitHub Action & pre-commit

```yaml
# .github/workflows/verify.yml
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: amitpatole/verel@v1.2.0
        with:
          repo: .
          install: "-e .[dev]"      # your project deps so its tests import
```

```yaml
# .pre-commit-config.yaml
- repo: https://github.com/amitpatole/verel
  rev: v1.2.0
  hooks: [{ id: verel-precommit }]
```

---

## The verdict bus (`verel.verdict`)

The contract every sense speaks. A grader emits a `Report` of `Issue`s; `gate()` reduces a set of
reports to one `pass` / `warn` / `fail`.

```python
from verel.verdict import Issue, IssueKind, Report, Severity, GraderKind, Verdict, gate, assign

report = assign(Report(                       # assign() stamps stable fingerprints
    verdict=Verdict.FAIL,
    summary="2 type errors",
    grader=GraderKind.TYPECHECK,
    issues=[Issue(kind=IssueKind.OTHER, severity=Severity.ERROR,
                  source=GraderKind.TYPECHECK, message="Incompatible return type",
                  locator="app.py:42")],
))

result = gate([report], required={GraderKind.TYPECHECK})
print(result.verdict)            # Verdict.FAIL
```

Load-bearing rules `gate()` enforces:

- **Advisory ceiling** — an issue is clamped to at most `warn` (it cannot gate) **iff** its report's
  grader is in `ADVISORY_GRADERS = {VISION, LLM_JUDGE, ACOUSTIC, AUDIO_LLM}` **or** the issue's own
  `confidence == LOW` (`verel/verdict/gate.py`, `constants.py`). Every other grader gates at full
  severity — including `PERF` and `CONTRACT`, which gate even though they aren't in `PRECISE_GRADERS`
  (membership in `PRECISE_GRADERS` is a *receipt-verification* concern, not the gating switch — see
  below). The clamp keys off the **report's grader**, not a per-issue source list; the only place
  per-issue `Issue.source` decides trust is the canary/rollback engine (next section). The full
  grader-by-grader table lives in **[Graders](graders.md)**.
- **Attestation** — a *required* grader must carry a signed `run_receipt` proving it ran the
  frozen suite over the changed files. A hollow `PASS, issues=[]` with no receipt **fails**.
- **Stuck vs. progress** — `progressed(curr, prev)` is strict shrinkage of the gating-failure set;
  pure churn or growth is not progress.

### Receipts & attestation — a verdict a stranger can re-check

When a *required* grader passes, it doesn't just say `pass` — it attaches a signed **run-receipt** that
binds the verdict to the exact inputs it graded. `gate()` rejects a required grader whose receipt is
missing, forged, stale, or doesn't match the code in front of it. Four bindings are enforced (see
`verel.verdict.gate`):

- **suite_sha** — the receipt must name the *frozen* suite that ran (a swapped suite fails).
- **inputs_digest** — the receipt must match the bytes graded *now*, so a green receipt can't be
  replayed onto different code with the same filenames.
- **result_digest** — the receipt commits to the graded outcome (verdict + issues), so an attacker
  can't pair a valid receipt with a tampered `Report` (issues stripped → fake PASS).
- **coverage** — the grader must prove it scanned at least one changed file.

Two signing tiers (`alg`):

| `alg` | Trust model | Who can verify |
|---|---|---|
| `hmac-sha256` (default) | shared secret within one trust domain (`VEREL_RUNNER_SECRET`) | anyone holding the secret |
| `ed25519` | public-key, cross-domain | **anyone with the public key** — no secret |

Verify a receipt with no trust in its producer:

```python
import json
from verel.verdict import RunReceipt, verify_receipt

receipt = RunReceipt.model_validate(json.load(open("receipt.json")))
res = verify_receipt(receipt, allowed_algs={"ed25519"})   # require public verifiability
print(res.valid, res.public_verifiable, res.runner_identity, res.reason)
```

or from the shell / an MCP host:

```bash
verel verify receipt.json --require-public   # exit 0 iff a trusted ed25519 key validates it
```

To make `gate()` itself **demand** public verifiability for required graders, pass
`gate(reports, required={...}, allowed_algs={"ed25519"})` — an HMAC (shared-secret) receipt then fails
closed.

**Keys (ed25519):** the runner signs with `VEREL_RUNNER_ED25519_SEED` (64 hex chars), else a persisted
per-install key. A verifier trusts a runner by placing `<key_id>.pub` in `~/.config/verel/trusted_keys/`
(override the dir with `VEREL_TRUSTED_KEYS`). An untrusted `key_id` never verifies — there is no
self-certification path.

#### Two receipt levels — the per-grader `RunReceipt` vs. the gate-level `GateReceipt`

Everything above is the **per-grader `RunReceipt`** — one signed receipt per grader, binding *that
grader's* outcome to *its* inputs. A whole stage produces several of them. The headline wedge a
**second party** verifies isn't a `RunReceipt` but the envelope that wraps them all: the gate-level
**`GateReceipt`** (`verel.verdict.attest`). `build_gate_receipt(verdict, reports)` assembles one
`GraderAttestation` per report (`kind` / `verdict` / `precise` / its `RunReceipt`), records whether the
clamp held an opinion back (`ceiling_clamped`), optionally binds extra attested context in `subject`
(e.g. a sight percept's `image_ref` + `matches_intent`), and **signs the aggregate** — so neither a
flipped headline verdict nor a swapped grader line survives. This is exactly what `verel_gate` /
`verel_sight` hand an MCP host back.

```python
import json
from verel.verdict import GateReceipt, verify_gate_receipt

gr = GateReceipt.model_validate(json.load(open("gate_receipt.json")))
res = verify_gate_receipt(gr, allowed_algs={"ed25519"})   # require public verifiability
print(res.valid, res.verdict, res.graders_checked, res.public_verifiable, res.subject)
```

`verify_gate_receipt` fails closed in layers: (1) the **envelope** signature must verify (binds the
aggregate verdict + fingerprint + identity), (2) the fingerprint must recompute from the grader lines,
(3) every **precise** grader — precision decided by `kind ∈ PRECISE_GRADERS`, never the receipt's
self-declared `precise` flag (an attacker could relabel a grader advisory to skip its check) — must
carry a `RunReceipt` whose signature verifies. `public_verifiable` is `True` only when the envelope
*and* all precise receipts verified as ed25519.

The same envelope underpins **portable fact attestation** for the brain: `attest_fact(...)` mints a
`GateReceipt` whose `subject` commits to a specific claim, and `verify_fact_attestation(receipt,
subject, predicate, text)` accepts it only if it verifies, is a `PASS`, and is bound to *that* exact
fact — so trust travels via a trusted grader's signature over the claim, never the caller's say-so.
See **[Memory backends](memory-backends.md)** for how the brain uses it.

> **Where `Report` and `Handoff` live.** Verel's `Report` extends AgentVision's `Report` through the
> sight adapter (`verel.senses.sight`) — that's why a percept and a test verdict share one schema.
> The organism-wide `Handoff` is defined in **`agentsensory`**, not `verel`; don't hunt for a `Handoff`
> symbol in this package.

---

## Agent-run CI/CD (`verel.ci`)

Tests, lint, and types as first-class graders, across **Python · JS/TS · Go**, plus **perf**,
**security**, and **IaC / cloud-IAM** (Terraform plan + Kubernetes RBAC — see
[Integrations](integrations.md) and [Graders](graders.md)). Stages compose graders and gate them with
attestation + failure-memory.

```python
from verel.ci import inner_loop_stage, premerge_stage, run_stage

res = run_stage(inner_loop_stage(".", language="python", with_lint=True, with_types=True))
print(res.verdict, [r.grader.value for r in res.reports])
```

### The four stages — a ladder, each rung adds a stronger guard

The stages aren't variants; they compose, tightening as a change moves toward `main`. Each is a
`Stage` you hand to `run_stage`:

| Stage | Builder | Composes | Adds over the rung below |
|---|---|---|---|
| **inner_loop** | `inner_loop_stage` | tests (required) + lint; `with_types=True` adds types | the fast author-loop gate |
| **pre_commit** | `precommit_stage` | tests (required) + lint | **regression memory** — `run_stage(ledger=…)` fails a change that reintroduces a previously-fixed failure, *from memory alone* |
| **pre_merge** | `premerge_stage` | tests + lint (+types) | **types, security, perf, mutation** — the full sandbox-CI gate before merge |
| **post_merge** | `postmerge_stage` | a smoke/E2E canary on the merged code | **canary → rollback** — a failing canary on *precise* evidence drives `git revert` |

```python
from verel.ci import precommit_stage, postmerge_stage, run_stage
from verel.memory.failure_ledger import FailureLedger

# pre_commit: pass a ledger and a reintroduced past failure gates from memory (§7.5),
# while transient/flaky failures are recorded VOLATILE so they self-clean unless they recur.
res = run_stage(precommit_stage("."), ledger=FailureLedger("."))
print(res.verdict, res.regressions)
```

The regression-memory check (`pre_commit`) and the canary→rollback engine (`post_merge`) are what make
the ladder more than "run the tools four times": failure-memory stops the fleet repeating a fix, and
the rollback policy below authorizes the one destructive action in the whole pipeline.

Pick a language; add precise senses:

```python
from verel.ci import premerge_stage, perf_spec, run_stage

stage = premerge_stage(
    ".", language="go",            # python | js | go
    security=True,                 # SAST (bandit) / dependency audit (npm)
    perf=perf_spec(".", ["./bench"], budgets={"p95_ms": 150}),  # regression past budget gates
    mutation=["billing.py"],       # test-effectiveness: surviving mutants in changed files gate
)
res = run_stage(stage)
```

Each `GraderSpec` carries its own parser, so `pytest`, `go test -json`, and a TAP runner — all
`GraderKind.TEST` — coexist on one bus. Language toolchains live in `verel.ci.LANGS`; the graders
are `pytest_spec`/`ruff_spec`/`mypy_spec`, `jstest_spec`/`eslint_spec`/`tsc_spec`,
`gotest_spec`/`govet_spec`, plus `bandit_spec`/`npm_audit_spec`/`perf_spec`/`mutation_spec`.

### Test-effectiveness (mutation) — "tests exist" is not "tests test"

A green suite proves nothing if it asserts nothing. `mutation_spec` injects faults into the changed
source and re-runs the suite; a **surviving mutant** (one no test catches) is a deterministic FAIL
(`GraderKind.MUTATION` is precise/gating, not advisory). Diff-scoped + capped to stay under the CI
budget; the suite is your own tests, so there's no new sandbox surface.

```python
from verel.ci.mutation import run_mutation

res = run_mutation(".", ["billing.py"], cap_per_file=25)
print(res.baseline_pass, res.survivors)   # survivors → the tests don't constrain that code
```

### Security grader — what actually gates (`bandit_spec` / `npm_audit_spec`)

`security=True` on `premerge_stage` adds a `GraderKind.SECURITY` grader (`PRECISE`, so it gates). For
**Python** it runs `bandit -r -q -f json` with a deliberate floor: `--severity-level medium
--confidence-level medium` — only findings at **MEDIUM+ severity AND MEDIUM+ confidence** (real SQLi,
weak crypto, command injection) cause the non-zero exit that gates; `LOW` stays advisory. The scan
**excludes** `tests/ test/ tools/ scripts/ examples/ .venv venv env build dist .git node_modules .tox`
— otherwise every test-only `assert` (B101) and all vendored code would drown the gate. Verified false
positives are pinned in-code with `# nosec Bxxx`. For **JS/TS** the grader is `npm audit --json`. Both
map tool severity onto the bus the same way: `critical→CRITICAL`, `high→ERROR` (gates),
`moderate/medium→WARNING`, `low/info→INFO` (advisory).

### Spec / intent conformance — "the ticket says A, the code does B"

Does the change actually implement the ticket? `verel.ci.spec` extracts checkable acceptance criteria
from the **ticket** (the PR/issue text — never the agent's diff), has the LLM compile each into pytest
checks, **executes** them, and gates on a grounded violation (`INTENT_MISMATCH`). The LLM only
*proposes* checks; *execution* decides — a hallucinated judge can neither block a good merge nor pass
a broken one.

```python
from verel.ci.spec import grade_spec, default_chat

rep = grade_spec(".", ticket_text, ["billing.py"], chat=default_chat())  # gates on a violated criterion
```

- **Majority vote** over N independent generated checks per criterion, so one wrong generated test
  can't false-fail a merge; a criterion that can't be grounded is **advisory**, never a gate. A
  non-empty ticket that yields *no* criteria is reported as unverified (WARN), never a confident PASS.
- **`verel_spec` MCP tool** and **`grade_pr`** (pull criteria + diff straight from a GitHub PR via
  `verel.integrations.github`, `VEREL_GITHUB_TOKEN`).
- **Security:** generated checks are LLM-authored from a possibly-hostile ticket, so they execute under
  real OS isolation by default (`isolation="container"`: bwrap `--unshare-all` no-network, read-only
  fs, seccomp denylist, rlimits) and **fail closed** (the criterion stays advisory, code is never run)
  when bwrap is absent. `isolation="subprocess"` is a documented opt-out for a **trusted-local** repo
  only — never for external-contributor PRs.

### Business rules / invariants — "business rules get ignored"

Declare cross-cutting invariants — *"an order total always includes tax", "a refund never exceeds the
charge"* — in a `verel_invariants.yaml` (one per line) or pass them in. `verel.ci.invariants` compiles
each into property checks, runs them under the same OS-isolation as the spec grader, and gates on a
falsified rule. Rules are **human-declared** (not from a ticket), so the injection surface is smaller.

```python
from verel.ci.invariants import grade_invariants, load_invariants
from verel.ci.spec import default_chat

rules = load_invariants(".")                       # from verel_invariants.yaml, or pass a list of strings
rep = grade_invariants(".", rules, ["billing.py"], chat=default_chat())  # a violated rule gates
```

Also the **`verel_invariants` MCP tool**. Like the spec grader, execution defaults to container
isolation and fails closed without it.

### Gate the boundary — the action gateway (`verel.gateway`)

Instead of trusting the agent to call the gate, put the gate *in front of its actions*. The gateway
classifies each tool call and enforces a verdict on the consequential ones — the agent needn't know
it's there:

```python
from verel.gateway import Gateway, Policy, repo_gate

gw = Gateway(invoke=my_tool_runner, policy=Policy(dry_run=True),
             gate=repo_gate("."), approve=ask_human)
gw.handle("read_file", {...})     # SAFE        → forwarded
gw.handle("create_pr", {...})     # CONSEQUENTIAL → forwarded only if the gate PASSes, else BLOCKED
gw.handle("deploy_prod", {...})   # IRREVERSIBLE  → DRY-RUN by default; applied only on human approval
```

- **Fail closed:** an unclassifiable or un-gateable consequential action is **blocked**, never
  forwarded unverified; an irreversible action is **never auto-applied** (dry-run + explicit approval).
- Built behind a clean **verdict / enforce / adapters** seam, so it lifts into the boundary organ
  (`immel`) and act-then-verify organ (`actel`) later unchanged.

#### How the gateway classifies a tool call

`Policy.classify(tool)` tokenizes the tool name (snake/kebab/camelCase → word tokens) and matches the
tokens against verb sets — **irreversible wins over consequential wins over safe**:

| Class | Sample verbs (token match) | Enforcement |
|---|---|---|
| **IRREVERSIBLE** | `delete` `destroy` `drop` `deploy` `release` `publish` `push` `rm` `remove` `revoke` `terminate` `merge` `purge` `wipe` `truncate` `reset` `kill` `rollback` … | dry-run by default; applied only on explicit human `approve` |
| **CONSEQUENTIAL** | `write` `create` `update` `edit` `commit` `set` `put` `patch` `apply` `insert` `rename` `move` `save` `add` `modify` | forwarded **only on a gate PASS**, else blocked |
| **SAFE** | `read` `list` `get` `search` `fetch` `view` `show` `query` `status` `describe` `inspect` `diff` `find` `count` `head` | forwarded immediately (read-only heuristic) |

A tool whose name matches **no** verb set is treated as **CONSEQUENTIAL**, not SAFE — the gateway
fails closed and refuses to assume an unknown action is read-only. Force a class with
`Policy(overrides={"my_tool": ActionClass.IRREVERSIBLE})`, and constrain the tool set with
`Policy(allow={...})` (an allowlist) / `Policy(deny={...})` (`deny` always wins).

```python
from verel.gateway import Gateway, Policy, ActionClass, repo_gate

policy = Policy(
    dry_run=True,
    deny={"force_push"},                          # never run, regardless of class
    overrides={"sync_index": ActionClass.CONSEQUENTIAL},  # name looks SAFE; force a gate
)
gw = Gateway(invoke=my_tool_runner, policy=policy, gate=repo_gate("."), approve=ask_human)
```

> **`repo_gate(repo)` is a pre-condition gate**, not an artifact check: it runs the Verel CI gate and
> forwards a consequential action only if the repo is **currently green** *before* the action. It does
> **not** verify what the action produces — confirming the post-action world changed is `actel`'s
> act-then-verify job (this seam lifts into `immel`/`actel` later).

### Over-engineering smell — "abstractions nobody needed"

`verel.smell` turns over-engineering into a measurable signal — **deterministic AST analysis, no code
execution**. A function over a cyclomatic-complexity budget **gates**; a public class/function added in
the diff but referenced nowhere is flagged as **speculative generality** (advisory). The future home
is the `olfel` organ; today it's a self-contained module + the `verel_smell` MCP tool.

```python
from verel.smell import grade_smell

rep = grade_smell(".", ["billing.py"], complexity_budget=12)   # over-complex functions gate
```

### MCP tools — the Verified-Review graders

Three of the five Verified-Review graders are exposed as MCP tools by `verel-mcp` (alongside
`verel_gate` / `verel_ci_check` / `verel_iac_check` / `verel_verify` / `verel_recall` /
`verel_remember` / `verel_build_tool`). The **mutation** grader and the **action gateway** have no MCP
tool — invoke them from Python (see above).

| MCP tool | Required args | Optional args | Gates on |
|---|---|---|---|
| `verel_spec` | `repo`, `criteria` | `files[]`, `checks_per_criterion` | a violated acceptance criterion (`intent_mismatch`) |
| `verel_invariants` | `repo` | `invariants[]`, `files[]` | a falsified declared business rule |
| `verel_smell` | `repo`, `files[]` | `complexity_budget` | a function over the cyclomatic-complexity budget |
| `verel_iac_check` | `repo` | `plan`, `manifests` | a dangerous cloud-IAM change (wildcard/privesc/public/admin) in a terraform plan or K8s manifests — offline, before apply |

Example tool-call payloads (the shape an MCP host sends):

```json
{
  "name": "verel_spec",
  "arguments": {
    "repo": "/abs/path/to/repo",
    "criteria": "total_with_tax([60,40], 0.10) must equal 110.0",
    "files": ["billing.py"],
    "checks_per_criterion": 2
  }
}
```

```json
{
  "name": "verel_invariants",
  "arguments": {
    "repo": "/abs/path/to/repo",
    "invariants": ["a refund never exceeds the original charge"],
    "files": ["refunds.py"]
  }
}
```

When `invariants` is omitted, `verel_invariants` loads the declared rules from
`verel_invariants.{yaml,yml,txt}` in the repo; with neither present it returns an error.

```json
{
  "name": "verel_smell",
  "arguments": {
    "repo": "/abs/path/to/repo",
    "files": ["billing.py"],
    "complexity_budget": 12
  }
}
```

Every tool returns the same shape:

```json
{
  "verdict": "pass" | "warn" | "fail",
  "issues": [
    {"grader": "smell", "severity": "error", "locator": "billing.py:total",
     "message": "total() has cyclomatic complexity 14 > budget 12 — likely over-complex; split it"}
  ]
}
```

#### `verel_sight` — give the agent eyes (needs `verel[sight]`)

`verel_sight` renders a URL and returns an **attested percept**: grounded observations with pixel
bboxes, an `image_ref`, intent conformance, and a verifiable `GateReceipt` whose `subject` binds the
`image_ref` + `matches_intent` (so a relayed percept can't swap the image or flip the verdict).

| Arg | Req? | Meaning |
|---|---|---|
| `url` | **yes** | the `http(s)` URL to render and grade (other schemes are refused — SSRF/LFI guard) |
| `intent` | no | what the UI *should* be; drives intent-conformance grading |
| `viewport` | no | `WxH`, e.g. `"1280x800"` |
| `backend` | no | vision backend; `"local"` (default) = no-LLM structural checks |
| `allow_local` | no | only literal JSON `true` opts in to rendering localhost/LAN (the SSRF guard is off); any truthy non-bool fails closed |
| `attest` | no | `auto` (ed25519 if available, else hmac) · `ed25519` (fails closed if PyNaCl absent) · `hmac` |

```json
{
  "name": "verel_sight",
  "arguments": {
    "url": "https://app.local/checkout",
    "intent": "a checkout form with a visible Pay button above the fold",
    "viewport": "1280x800",
    "attest": "ed25519"
  }
}
```

The precise visual failures gate; the advisory vision-LLM opinion is clamped to `warn` (the same
advisory ceiling as everywhere else). The response carries `verdict`, `observations[]` (each with a
`bbox`, `confidence`, `precise`), `matches_intent`, `ceiling_clamped`, and the full `receipt`.

#### `verel_build_tool` — let the agent build its own tool (needs an LLM key)

`detect → scaffold → test → register`. The MCP path **requires the container isolation tier** (bwrap
netns + read-only fs + seccomp) and fails closed without it — it runs LLM-authored code, so it never
falls back to the weaker subprocess tier.

| Arg | Req? | Meaning |
|---|---|---|
| `name` | **yes** | tool name |
| `capability` | **yes** | one-line description of what it does |
| `signature_hint` | no | a hint for the generated signature |
| `side_effect` | no | `read_only` (default) · `idempotent` · `destructive` |
| `cases` | no | list of `{args, expected}` eval cases — the attested eval the tool must pass to be admitted |

```json
{
  "name": "verel_build_tool",
  "arguments": {
    "name": "slugify",
    "capability": "convert a title to a url slug",
    "side_effect": "read_only",
    "cases": [{"args": ["Hello World"], "expected": "hello-world"}]
  }
}
```

### Self-healing

```python
from verel.ci import inner_loop_stage, self_heal

result = self_heal(".", inner_loop_stage(".", with_lint=False))   # needs an LLM key
print(result.healed, result.terminated_on)
```

On a failure the **ci-medic** classifies each issue (retry / regen-lockfile / quarantine-flaky /
fix-branch) and, for genuine regressions, invokes the code-fixer — re-gating each round until the
graders pass or it escalates.

#### ci-medic — the decision engine that makes self-heal safe (`verel.ci.medic`)

Self-heal is only safe because it never *guesses* what to do with a red grader. `triage(report)`
runs a **deterministic** keyword/signature classifier (so an LLM can't game it) that maps each failing
issue to one `Action`:

| `Action` | When | What it does |
|---|---|---|
| `RETRY` | infra/transient signal (`connection reset`, `timed out`, `429/502/503`, `ECONNRESET`…) | re-run; never "fix" a network blip |
| `REGEN_LOCKFILE` | dependency drift (`ModuleNotFoundError`, `ResolutionImpossible`, `incompatible`…) | regenerate the lockfile |
| `QUARANTINE_FLAKY` | a fingerprint already seen flipping pass/fail | downgrade `ERROR→WARNING` — **visible, ticketed, never silently dropped** |
| `FIX_BRANCH` | anything else — a genuine regression | spin a code-fixer loop (an LLM may *enrich* the diagnosis with a one-line root cause; it never changes the `Action`) |

The decision drives **how a failure is remembered**. In `run_stage(ledger=…)`, transient (`RETRY`) and
flaky (`QUARANTINE_FLAKY`) fingerprints are written **volatile** — they self-clean from failure-memory
unless they recur — while a genuine regression is recorded **persistent**, so the next change that
reintroduces it is gated from memory alone. Volatile-vs-persistent is exactly what keeps the
regression guard from petrifying every one-off CI hiccup into a permanent gate.

### Verdict-driven rollback

The agent *proposes*; a deterministic engine *authorizes* — and only on **precise** gating evidence
(never an advisory opinion), performing a safe `git revert` (never a history rewrite). This is the
**one subsystem where per-issue `Issue.source` decides trust**: the policy walks each cited gating
issue and keys off `i.source ∈ ADVISORY_GRADERS` *per issue* (not the report's grader, not
`Report.backend`). A rollback backed only by advisory sources is **denied**; at least one precise
gating source must justify the destructive revert.

```python
from verel.ci import RollbackExecutor, RollbackProposal
outcome = RollbackExecutor().maybe_rollback(repo, proposal, reports)
```

---

## The brain — memory that compounds (`verel.memory`)

A trust layer over a **pluggable backend**. Each record carries **two orthogonal quantities** —
`epistemic_confidence` (belief; moved only by corroborate/contradict) and `retrieval_strength`
(reachability; decays, resets on recall).

```python
from verel.memory import LocalMemory, MemoryRecord, MemoryKind
from verel.memory.view import make_key

mem = LocalMemory()                                   # or LocalMemory(embedder=OpenAIEmbedder())
mem.write(MemoryRecord(kind=MemoryKind.FACT, subject="auth", predicate="uses",
                       text="sessions are JWT, 15-min expiry", scope="repo:app",
                       subj_pred_key=make_key("auth", "uses", "repo:app")))
hits = mem.recall("how does login work", scope="repo:app", k=3)
```

### Pick a backend (no code change)

Every backend implements one `MemoryView` contract, so the whole trust layer — consolidation, the
promotion gate, the regression guard — works unchanged whichever you select. Choose one by name with
`VEREL_MEMORY_BACKEND`; the registry resolves it (`verel doctor` prints the selection):

```python
from verel.memory import load_backend, known_backends
print(known_backends())                # ['lancedb', 'local', 'postgres', 'redis', 'remote']
brain = load_backend("local")          # honours VEREL_MEMORY_BACKEND; falls back to the named arg
```

The names are **always listed** (built in); `pip install verel[<name>]` only adds the heavy driver —
selecting one whose driver is absent fails closed with a clear hint. See the **[Memory backends
reference](memory-backends.md)** for a per-backend env table, a runnable example each, the decision
matrix, and the trust-layer features (lattice, librarian, lifecycle flags, replication) that work the
same on every backend.

- **`local`** — zero-dependency SQLite (`VEREL_MEMORY_STORE`, default `~/.config/verel/brain.db`).
- **`remote`** — a whole fleet shares one authenticated brain over HTTP(S) (`VEREL_BRAIN_URL`).
- **`postgres` / `lancedb` / `redis`** — external DBs via `pip install verel[<db>]`, same selector.
- **`mem0`** is **not** `VEREL_MEMORY_BACKEND`-selectable — it's constructed in code
  (`make_ollama_mem0()`), see below.

See [`examples/demo_backend_registry.py`](https://github.com/amitpatole/verel/tree/main/examples/demo_backend_registry.py)
and the [Configuration → Memory backend](configuration.md#memory-backend) table.

Trust is **earned, never asserted** — a candidate reaches `verified` only by passing a held-out,
agent-inaccessible eval (with a leakage canary):

```python
from verel.memory import PromotionGate, HeldOutCorpus, EvalCase
corpus = HeldOutCorpus([
    EvalCase(text="a card overflows the viewport on a 320px screen",
             covers_kind="overflow", label="prevent"),   # "prevent" | "allow"
])
gate = PromotionGate(mem, corpus)        # ratifies candidates → verified via the bus
```

### Consolidation: episodes → rules → schemas

```python
from verel.memory import consolidate_failures, induce_hierarchy, consolidate_across_scopes

# recurring FAILUREs in a scope → candidate, structured DesignRules (condition → action)
rules = consolidate_failures(mem, scope="repo:app", min_cluster=2)

# rules → order-2 principles → order-3 meta-principles, until the corpus stops supporting more
levels = induce_hierarchy(mem, scope="repo:app", min_size=2)

# a pattern recurring across several repos → one `global` rule (records detail['spans'])
glob = consolidate_across_scopes(mem, ["repo:a", "repo:b"], min_scopes=2)
```

### Contradiction-driven revision

Consolidation can be **wrong**. A new failure in a rule's domain that the rule failed to prevent is
a counterexample: the rule is weakened, and once enough accumulate it's **split** into a narrowed
rule + an exception — and the split **propagates up** the schema hierarchy so principles above stop
over-claiming.

```python
from verel.memory import revise_with_counterexample, contradicts

if contradicts(rule, new_failure):
    rev = revise_with_counterexample(mem, rule, new_failure)   # needs an LLM for the split
    print(rev.action)            # "weakened" | "split" | "rejected"
    print(rev.propagated)        # schemas above the rule that were re-derived
```

Everything starts `candidate` / `inferred`; height, breadth, and survival never confer trust.

### mem0 backend

mem0 is **constructed in code**, not selected via `VEREL_MEMORY_BACKEND` (it isn't in the registry).
It wraps a mem0 client behind the same `MemoryView`, so the trust layer is unchanged.

```python
from verel.memory import make_ollama_mem0      # needs verel[mem0]
mem = make_ollama_mem0()                        # same MemoryView Protocol; recall is semantic
```

!!! note
    `make_ollama_mem0()` uses a local Chroma vector store and needs an **OpenAI key** for the embedder
    (`OPENAI_API_KEY` or `~/.config/OpenAI/key`) — Ollama Cloud serves no embeddings endpoint. Prefer
    **`lancedb`** for zero-infra vector recall or **`postgres`/`redis`** for a shared brain (those
    *are* `VEREL_MEMORY_BACKEND`-selectable). See **[Memory backends](memory-backends.md)**.

---

## Tool-smith — agents build their own tools (`verel.toolsmith`)

`detect → scaffold → test → register → reuse`. A tool is admitted only on a passing attested eval;
reuse **re-verifies** against the new spec's cases (a close match isn't trusted blindly).

```python
from verel.memory import LocalMemory
from verel.toolsmith import ToolRegistry, ToolSmith, ToolSpec, ToolCase, SideEffect

smith = ToolSmith(ToolRegistry(LocalMemory()), isolation="container")   # needs an LLM key
res = smith.build(ToolSpec(
    name="slugify", capability="convert a title to a url slug",
    side_effect=SideEffect.READ_ONLY,
    cases=[ToolCase(args=["Hello World"], expected="hello-world")],
))
print(res.trust, res.registered)
```

### Isolation tiers

Untrusted, agent-authored code runs in a separate trust domain. From weakest to strongest:

| `isolation=` | What it is |
|---|---|
| `"subprocess"` | fresh interpreter + rlimits + wall-clock timeout (dependency-free) |
| `"container"` | `bwrap` namespace sandbox — no network, read-only fs, ephemeral `/tmp`, cleared env |
| `"container"` + `verel[container]` | …plus a **seccomp-bpf** filter |

Three seccomp profiles (`run_container(..., seccomp_profile=…)`):

- `denylist` (default) — EPERM on dangerous syscalls; safe for arbitrary tools.
- `allowlist` — default-deny; only pure-compute syscalls (no network/subprocess/threads).
- `capability` — the tightest: only the syscalls a tool exercised while passing its eval (learn
  with `learn_syscall_profile`, then enforce via `tool.syscall_policy`).

---

## The fleet — agents managing agents (`verel.fleet`)

A single-writer scheduler over a Task DAG, every node gated by the bus.

```python
import asyncio
from verel.fleet import Scheduler, Task, WorkerResult
from verel.verdict import Verdict

async def worker(task):                       # your agent; returns a graded result
    ...
    return WorkerResult(verdict=Verdict.PASS)

tasks = [Task(id="a"), Task(id="b", deps=["a"])]
state = asyncio.run(Scheduler(worker, concurrency=4).run(tasks))
```

Barriers (`all` / `k_of_n` / `optional`), retry → quarantine, a hard budget lease, and WAL-based
crash resume are all on `Task` / `Scheduler`.

### Concurrent managers (fencing)

More than one scheduler can share a task store safely via **fencing leases** — a stale leader's
writes are rejected:

```python
from verel.fleet import Scheduler, InMemoryLeaseStore   # or SqliteLeaseStore for cross-process
store = InMemoryLeaseStore()
s1 = Scheduler(worker, leases=store, owner="m1")
s2 = Scheduler(worker, leases=store, owner="m2")          # each task runs exactly once
```

Across **machines**, put the lease authority behind the HTTP control plane:

```python
from verel.fleet import ControlPlaneServer, RemoteLeaseStore
srv = ControlPlaneServer("/var/lib/verel/leases.db", auth_token="…").start()
sched = Scheduler(worker, leases=RemoteLeaseStore(srv.url, auth_token="…"), owner="host-1")
```

### Multi-repo + atomic sagas

```python
from verel.fleet import plan_multi_repo, CrossDep, run_saga, SagaStep, git_revert_head

dag = plan_multi_repo({"api": api_tasks, "client": client_tasks},
                      [CrossDep(to_repo="client", dependent="ship", from_repo="api", needs="build")])

# all-or-nothing across repos: a failure compensates the repos that already landed, in reverse
res = run_saga([SagaStep("api",    forward_api,    lambda _r: git_revert_head("/repos/api")),
                SagaStep("client", forward_client, lambda _r: git_revert_head("/repos/client"))])
```

A **git pre-receive fencing sink** (`write_pre_receive_hook`) extends the fence to pushes: a push
carrying a stale token is refused at the remote.

---

## Eyes / senses (`verel.senses`) — needs `verel[sight]`

AgentVision as a grounded perception sense on the same bus.

```python
from verel.senses import perceive, watch
percept = perceive("dist/index.html")           # DOM / contrast / OCR, + intent conformance
clip = watch("https://app.local/player")         # temporal: playback / loading / liveness
```

A precise visual failure (overflow, clipped, missing element) gates; the advisory vision-LLM
opinion is clamped to `warn`.

---

## Skill registry (`verel.registry`)

Content-addressed, signed skill artifacts — and the rule that keeps the flywheel honest: **trust
does not travel.** A fetched skill enters as a `candidate` and only becomes `verified` by passing
the importer's OWN held-out eval.

```python
from verel.registry import export_skill, import_skill, PublicRegistry

art = export_skill(verified_tool, origin="tenant:A")
PublicRegistry("/srv/skills").publish(art)        # verifies the signature; refuses a tamper
res = import_skill(art, into=my_registry, target_cases=my_cases)
print(res.reverified)                             # True only if it passed MY eval
```

Host it over HTTP for cross-machine sharing:

```python
from verel.registry import RegistryServer, RemoteRegistry
srv = RegistryServer("/srv/skills", auth_token="…").start()
remote = RemoteRegistry(srv.url, auth_token="…")
import_skill(remote.get(content_hash), into=my_registry, target_cases=my_cases)
```

Whether a public registry is even a moat is *measured*, not assumed — `measure_transfer` (the H2
experiment) re-verifies skills across tenants. See [H2 results](H2_RESULTS.md).

---

## Cookbook

Runnable, mostly offline — see the [`examples/`](https://github.com/amitpatole/verel/tree/main/examples) directory:

| Want to… | Run |
|---|---|
| gate a repo on tests+lint+types | `verel-ci check --repo .` |
| self-heal failing tests | `python examples/demo_selfheal.py` |
| grade Python/JS/Go + perf + security on one bus | `python examples/demo_polyglot_ci.py` |
| consolidate failures → rules → schema → revise | `python examples/demo_consolidation.py` |
| sandbox a tool to only the syscalls it earned | `python examples/demo_capability_jail.py` |
| run concurrent managers + a multi-repo saga | `python examples/demo_distributed_fleet.py` |
| publish a skill and have another tenant re-verify | `python examples/demo_hosted_registry.py` |
| measure cross-tenant skill transfer (live) | `python examples/run_h2.py` |

See also the [Architecture & roadmap](ARCHITECTURE.md) for how the organs fit together.
