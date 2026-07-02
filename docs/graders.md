# Graders reference

Nothing is done until a grader returns a verdict. Every sense in Verel — tests, lint, types, security,
perf, mutation, smell, contract, the eyes — speaks one contract: it emits a **`Report`** (a `Verdict` +
grounded `Issue`s + a signed `RunReceipt`), and `gate()` reduces a set of reports to one
`pass` / `warn` / `fail`. Graders split into two trust tiers. **Precise** graders gate at full
severity: an `ERROR`/`CRITICAL` issue forces `FAIL`. **Advisory** graders inform but are
ceiling-clamped — their worst issue can never exceed `WARNING`, so a model's open-ended opinion can
slow a merge but never block or bless one. The clamp is what keeps "couldn't verify" from ever reading
as a confident PASS.

## The precise / advisory rule (exactly)

The clamp is per **issue**, applied in `verel.verdict.gate`. An issue is clamped to `WARNING` — it
cannot gate, and its effective severity is capped at `WARNING` — **iff either** of these holds:

1. its report's `grader` is in `ADVISORY_GRADERS = {VISION, LLM_JUDGE, ACOUSTIC, AUDIO_LLM}`, **or**
2. the issue's `confidence == Confidence.LOW`.

Every other issue gates at its declared severity. The reducer then sets the verdict: any surviving
issue at `≥ ERROR` (`GATING_SEVERITY`) → `FAIL`; else any `WARNING` → `WARN`; else `PASS`.

```python
# verel/verdict/gate.py — the clamp, verbatim in spirit
for r in reports:
    for i in r.issues:
        sev = i.severity
        if r.grader in ADVISORY_GRADERS or i.confidence == Confidence.LOW:
            sev = clamp_ceiling(sev, ADVISORY_CEIL)   # ADVISORY_CEIL = Severity.WARNING
        gating.append((sev, i))
```

Two consequences worth internalising:

- **It keys off the report's `grader` and the issue's `confidence` — not off `Issue.source`.** A
  `TEST` issue carried on a report from an advisory grader is clamped; a `VISION`-sourced issue on a
  precise grader's report is not. Trust travels with the *grader that ran*, plus the per-issue
  confidence escape hatch.
- **`PERF` and `CONTRACT` gate.** They are not in `ADVISORY_GRADERS`, so their `ERROR` issues are
  never clamped — a perf-budget regression or a violated acceptance criterion forces `FAIL`. (They are
  also absent from `PRECISE_GRADERS`, which is the separate set used to mark a grader's receipt
  `precise` and to authorise verdict-driven rollback; gating itself only consults `ADVISORY_GRADERS`.)
  For reference, `PRECISE_GRADERS = {TEST, TYPECHECK, LINT, MUTATION, SMELL, DOM, OCR, CV, SECURITY,
  IAC, IAM, POLICY, COST, DSP, ASR}`.

## Every `GraderKind`

| `GraderKind` | Grades | Tier | Invoke | `IssueKind`s emitted | Demo |
|---|---|---|---|---|---|
| `TEST` | unit/integration suites (Python · JS/TS · Go) | gates | `pytest_spec` / `jstest_spec` / `gotest_spec`; `verel-ci check` | `OTHER` | `examples/demo_polyglot_ci.py` |
| `LINT` | lint / static checks | gates | `ruff_spec` / `eslint_spec` / `govet_spec` | `OTHER` | `examples/demo_polyglot_ci.py` |
| `TYPECHECK` | type errors | gates | `mypy_spec` / `tsc_spec` | `OTHER` | `examples/demo_polyglot_ci.py` |
| `SECURITY` | SAST (bandit) · dependency audit (npm) | gates | `bandit_spec` / `npm_audit_spec`; `premerge_stage(security=True)` | `OTHER` | `examples/demo_polyglot_ci.py` |
| `PERF` | benchmark metrics vs an explicit budget | gates | `perf_spec(repo, command, budgets)` | `OTHER` | `examples/demo_polyglot_ci.py` |
| `MUTATION` | test-effectiveness (surviving injected faults) | gates | `mutation_spec` / `run_mutation`; `premerge_stage(mutation=[...])` | `SURVIVED_MUTANT`, `OTHER` | `examples/demo_mutation.py` |
| `SMELL` | over-engineering (complexity, speculative generality) | gates (complexity) + advisory (speculative) | `grade_smell`; `verel_smell` (MCP) | `COMPLEXITY` | `examples/demo_smell_grader.py` |
| `CONTRACT` | spec/intent conformance · declared invariants | gates | `grade_spec` / `grade_invariants`; `verel_spec` / `verel_invariants` (MCP) | `INTENT_MISMATCH`, `OTHER` | `examples/demo_spec_grader.py` · `examples/demo_invariant_grader.py` |
| `LLM_JUDGE` | open-ended model judgement (advisory companion) | advisory (clamped) | emitted alongside `CONTRACT`/`SMELL` for unverifiable findings | `INTENT_MISMATCH`, `OTHER` | — |
| `DOM` · `OCR` · `CV` | structural/visual defects from the eyes | gates | `verel.senses.perceive` (needs `verel[sight]`) | `OVERFLOW`, `CLIPPED`, `MISSING_ELEMENT`, … | — |
| `VISION` | the vision-LLM's open-ended opinion | advisory (clamped) | `verel.senses.perceive` (needs `verel[sight]`) | layout/contrast/typo kinds | — |
| `IAC` | terraform/tofu validate · plan (drift) · helm/kubectl render | gates | `terraform_validate_spec` / `terraform_plan_spec` / `helm_template_spec` / `kubectl_dryrun_spec` | `IAC_DRIFT`, `OTHER` | `examples/demo_iac.py` |
| `IAM` | cloud-IAM change sensor + least-priv + effective-access | gates | `parse_terraform_plan` (sensor) · `parliament_spec` / `cloudsplaining_spec` · `EffectiveAccessVerifier` | `IAM_RISK` | `examples/demo_iac.py` |
| `POLICY` | policy-as-code (conftest / OPA) | gates | `conftest_spec` | `OTHER` | `examples/demo_iac.py` |
| `COST` | cloud spend vs an explicit budget (infracost) | gates | `infracost_spec(repo, budgets={...})` | `OTHER` | `examples/demo_iac.py` |
| `KPI` | 5G RAN/Core PM counters vs **declared** thresholds (3GPP TS 28.552/28.554); delta-vs-baseline. Inputs: Prometheus/OpenMetrics · CSV/JSON · **PM-XML (TS 32.435)**; vendor counter mapping via `--mapping` | gates | `grade_kpi(repo, metrics=, thresholds=, mapping=)`; `verel-ci telecom --kpi` (needs `verel[telecom]`) | `THRESHOLD_BREACH`, `BASELINE_REGRESSION` | `examples/demo_telecom_kpi.py` |
| `TELECOM_CFG` | declared 5G Core + RAN invariants over one normalized model, from **Helm values, NETCONF/28.541-NRM, OR 3GPP bulk-CM (32.615)** (S-NSSAI consistency, UE-pool, N3/N6 separation, redundancy, SUCI, SBI-TLS, MTU; PCI collision/confusion, neighbor symmetry, EIRP, PRACH-root non-overlap, SSB sync-raster; the flagship **TAC/PLMN RAN↔Core cross-check**) — deterministic, receipt-visible waivers | gates | `grade_cfg(repo, values=, rules=)`; `verel-ci telecom-cfg --values` (needs `verel[telecom]`) | `INVARIANT_VIOLATION`, `CROSS_NF_MISMATCH` | `examples/demo_telecom_cfg.py` · `examples/demo_telecom_ran.py` |
| `DSP` · `ASR` · `ACOUSTIC` · `AUDIO_LLM` | hearing (audel / ears) | reserved | not wired in verel | audio kinds | — |

`DSP`/`ASR`/`ACOUSTIC`/`AUDIO_LLM` are organism-level `GraderKind`s the contract reserves (the
`audel`/ears organ); they are defined in the model but **not produced by any grader inside `verel`**
today. `DSP`/`ASR` are precise and `ACOUSTIC`/`AUDIO_LLM` advisory by the same rule above, for when the
hearing organ lands.

### IaC / DevOps — grade Terraform, Kubernetes & cloud IAM before apply

The IaC graders bring Terraform/OpenTofu, the wider DevOps toolchain, and **cloud-IAM blast radius**
onto the bus. Tools shell out behind pure parsers (offline-tested; the runner is injected), and each
maps onto an existing trust tier — so `tflint`→`LINT`, `trivy`/`checkov`/`kube-score`→`SECURITY`,
`conftest`→`POLICY`, `infracost`→`COST` (against an **explicit** budget, like `PERF`).

The headline is the **IAM change sensor**: `parse_terraform_plan` reads a `terraform show -json` plan,
normalizes every IAM-affecting change, and runs deterministic rules — wildcard action/resource,
`iam:PassRole`-style privilege escalation, public principal (`*`/`allUsers`/`system:anonymous`),
admin grants (`AdministratorAccess`/`roles/owner`/`cluster-admin`), open `0.0.0.0/0` ingress — across
AWS, GCP, Azure and Kubernetes RBAC. A risk is a grounded `IAM_RISK` `ERROR`/`CRITICAL` on the bus,
caught **before** apply (`examples/demo_iac.py`, no cloud creds).

```python
from verel.ci import parse_terraform_plan          # offline — over a `terraform show -json` plan
issues = parse_terraform_plan(open("tfplan.json").read())
for i in issues:
    print(i.severity.value, i.source.value, i.detail["rule_id"], i.locator)
# error iam WILDCARD_ACTION aws_iam_policy.admin
```

The same offline sensor is wired to two surfaces: the **`verel_iac_check`** MCP tool (`repo` + `plan`
and/or `manifests`) and the **`verel-ci iac --repo . --plan tfplan.json`** CLI (exit 1 on FAIL) — so an
agent or a CI step catches a dangerous grant before apply with no cloud credentials.

#### The IAM/IaC rule catalog

Every `rule_id` the sensor can emit (a grounded `IAM_RISK` on a `GraderKind.IAM` report unless noted),
grouped by what it catches:

| `rule_id` | Severity | Catches | Clouds |
|---|---|---|---|
| `WILDCARD_ACTION` | ERROR | `*`/`?` anywhere in an action (`iam:*`, `s3:Get*`, `iam:*Policy`) | AWS + generic policy docs |
| `WILDCARD_RESOURCE` | ERROR | wildcard action **on** a `*` resource | AWS + generic |
| `PRIVILEGE_ESCALATION` | ERROR (scoped) / CRITICAL | `iam:PassRole`/`sts:AssumeRole*`/`lambda:AddPermission` primitives; GCP `serviceAccountTokenCreator`/`roleAdmin`/…; Azure User-Access-Administrator; K8s `escalate`/`bind`/`impersonate`, webhook/CSR/node/proxy primitives, `serviceaccounts/token`, `pods/exec` | AWS · GCP · Azure · K8s |
| `PUBLIC_PRINCIPAL` | CRITICAL | `*`/`allUsers`/`allAuthenticatedUsers`/`system:anonymous`/`system:unauthenticated`/`system:authenticated`; Lambda public invoke; wildcard principal ARN | AWS · GCP · Azure · K8s |
| `ADMIN_GRANT` | ERROR | `AdministratorAccess`/`PowerUserAccess`/`IAMFullAccess`; GCP `roles/owner`/`editor`/…; Azure Owner/Contributor (name or GUID); K8s built-in `cluster-admin`/`admin`/`edit` ClusterRole, `system:masters` | AWS · GCP · Azure · K8s |
| `ALLOW_BY_EXCLUSION` | ERROR | `NotAction`/`NotResource` ("everything except" = presumptive admin) | AWS + generic |
| `CROSS_ACCOUNT_TRUST` | WARNING (advisory) | trust policy lets a concrete external AWS account assume the role (confused-deputy without an ExternalId) | AWS |
| `OPEN_INGRESS` | ERROR | `0.0.0.0/0`/`::/0` (incl. split-CIDR halves) ingress | AWS SG · GCP firewall · Azure NSG |
| `PUBLIC_ACCESS_BLOCK_DISABLED` | ERROR | S3 public-access-block deleted, or any of the 4 flags false/absent | AWS |
| `PUBLIC_ACL` | ERROR | S3 canned ACL (`public-read`…) or an AllUsers/AuthenticatedUsers grant | AWS |
| `PUBLIC_DB_ENDPOINT` | ERROR | `publicly_accessible=true` on any routable resource (RDS/Redshift/DMS/…) | AWS |
| `PUBLIC_BLOB_ACCESS` | ERROR | Azure storage account anonymous public-blob access | Azure |
| `CREDENTIAL_EXPOSURE` | ERROR | GCP long-lived service-account **key** creation (exportable credential) | GCP |
| `UNKNOWN_IAM_CONTENT` | ERROR | an IAM-relevant field is "(known after apply)" — blast radius invisible, **fails closed** | all |
| `UNAUDITABLE_PROVISIONER` | ERROR (`IAC`) | `local-exec`/`remote-exec` provisioner or `external` data source — runs an unauditable program at apply/refresh | all |
| `HTTP_DATA_SOURCE` | WARNING (advisory, `IAC`) | `data "http"` — fetches a URL every refresh (exfil/SSRF) | all |
| `DESTROY_OR_REPLACE` | INFO (`IAC_DRIFT`) | a planned destroy/replace (visibility + gateway escalation; does not gate) | all |
| `WILDCARD_RBAC` | ERROR | RBAC rule granting `*` verbs on `*` resources | K8s |
| `SECRETS_ACCESS` | ERROR (cluster / privileged ns) / WARNING (ns) | read of `secrets`, or read-all over `*` | K8s |
| `AGGREGATION_RULE` | WARNING (advisory) | a ClusterRole `aggregationRule` — grows silently to label-selected roles | K8s |

**The plan is not reality.** Three guarantees stop a "clean diff, dirty apply": (1) **provisioners and
side-effecting data sources are gated** — a `local-exec`/`remote-exec` provisioner, an `external` data
source, or a `data "http"` runs code the plan's diff can't see (`UNAUDITABLE_PROVISIONER` gates,
`HTTP_DATA_SOURCE` advises); (2) **computed IAM fails closed** — any IAM field marked "(known after
apply)" gates as `UNKNOWN_IAM_CONTENT` rather than passing on an unverifiable blast radius;
(3) **out-of-band drift is graded** — terraform's `resource_drift` is evaluated too, so a live,
un-reverted manual grant (no planned change to overwrite it) gates at full severity, while a drift the
apply *will* revert is advisory. The sensor was hardened against a hostile plan/manifest as untrusted
input over a 14-round adversarial security cadence (every fix pinned as a regression test).

Acting is gated, not just graded. The **terraform actuator** (`verel.actuators.TerraformActuator`)
plans → grades the **bound** plan file → applies *exactly* that file (a digest mismatch from a re-plan
between approval and apply is refused — the plan-binding / TOCTOU defense) → re-plans to confirm the
world converged. The gateway classifies an apply from what the bound plan does: any **destroy/replace
or IAM widening** ⇒ `IRREVERSIBLE` (dry-run + human approval), pure create/no-op ⇒ `CONSEQUENTIAL`
(verdict-gated). Direct IAM-mutating tool calls (code/agents) are intercepted the same way
(`iam_action_class`). Finally, `EffectiveAccessVerifier` confirms what the cloud *actually* grants
(AWS IAM Access Analyzer / GCP Policy Analyzer / Azure role assignments) with read creds resolved from
`~/.config` — accurate, but not a pure offline gate.

### Tests · lint · types — the polyglot CI graders

Each `GraderSpec` carries its own parser, so `pytest`, `node --test` (TAP), and `go test -json` — all
`GraderKind.TEST` — coexist on one bus. Pick a language with `LANGS` (`python` · `js` · `go`); the
stages wire them up:

```python
from verel.ci import inner_loop_stage, premerge_stage, run_stage

res = run_stage(inner_loop_stage(".", language="python", with_lint=True, with_types=True))
print(res.verdict, [r.grader.value for r in res.reports])
```

A grader whose tool is missing returns `errored=True` and `FAIL` — a did-not-run is never a silent
green.

### Security — a real gate, not a wall of noise

`bandit_spec` runs `bandit -r -q -f json --severity-level medium --confidence-level medium`, so a
finding gates only at **MEDIUM-or-higher severity AND MEDIUM-or-higher confidence** (real SQLi, weak
crypto, command injection); `LOW` stays advisory. `parse_bandit` maps bandit severities onto the bus —
`critical → CRITICAL`, `high → ERROR`, `medium → WARNING`, `low → INFO`. Test/vendored trees are
excluded (`_BANDIT_EXCLUDE` = `./tests,./test,./tools,./scripts,./examples,./.venv,./venv,./env,
./build,./dist,./.git,./node_modules,./.tox`) so every `assert` (`B101`) doesn't drown the gate.
`npm_audit_spec` (`npm audit --json`) maps `moderate → WARNING`, `high → ERROR`, `critical → CRITICAL`.

### Perf — precise, but only against an explicit budget

`perf_spec(repo, command, budgets={"p95_ms": 150})` runs a benchmark that prints
`{"metrics": {name: value}}`; each metric over its budget is an `ERROR` that gates. A regression is
precise evidence, so a perf failure can drive verdict-driven rollback — but only against a budget you
declared, never an inferred one.

### Mutation — "tests exist" is not "tests test"

`mutation_spec(repo, targets)` injects faults into the changed source and re-runs your own suite; a
**surviving mutant** (one no test catches) is a deterministic `SURVIVED_MUTANT` `ERROR`. A non-green
baseline also gates (you can't measure effectiveness on a red suite). Python only; diff-scoped and
capped (`cap_per_file`, default 25) to stay under the CI budget. Call it directly for the raw result:

```python
from verel.ci.mutation import run_mutation
res = run_mutation(".", ["billing.py"], cap_per_file=25)
print(res.baseline_pass, res.survivors)
```

### Smell — over-engineering as a countable signal

`grade_smell(repo, files, complexity_budget=12)` is deterministic `ast` analysis, no code execution. A
function over the cyclomatic-complexity budget is a gating `COMPLEXITY`/`SMELL` `ERROR`; a new public
def/class referenced nowhere in the repo is **speculative generality** — a `COMPLEXITY` issue at
`Confidence.LOW`, which the clamp keeps advisory. Also the `verel_smell` MCP tool.

### Contract — spec/intent & invariants

Both contract graders follow Verel's invariant: **the LLM only proposes checks; execution decides.**

- `grade_spec(repo, ticket_text, files, chat=...)` extracts checkable acceptance criteria from the
  **ticket** (never the agent's diff), compiles each to N independent pytest checks, executes them
  under OS isolation, and majority-votes. A violated criterion is a grounded `INTENT_MISMATCH` `ERROR`
  on a `CONTRACT` report (gates). Also `grade_pr` (pull criteria + diff from a GitHub PR) and the
  `verel_spec` MCP tool.
- `grade_invariants(repo, rules, files, chat=...)` does the same for **human-declared** business rules
  (a `verel_invariants.{yaml,yml,txt}`, one per line, or passed in). A falsified rule gates. Also the
  `verel_invariants` MCP tool.

Generated checks are LLM-authored from possibly-hostile input, so they execute under `bwrap`
OS-isolation by default (`isolation="container"`) and **fail closed** when bwrap is absent — the
criterion stays advisory, the code is never run. `isolation="subprocess"` is a documented opt-out for
trusted-local repos only.

## Spec/intent & invariant graders — why "couldn't verify" never passes

The contract graders emit **two issues from one report** for a criterion they can't ground:

- a gating `INTENT_MISMATCH` (`GraderKind.CONTRACT`, `ERROR`) only when a check *executed* and a
  strict majority **failed** — a confirmed violation; and
- an advisory issue (`source=GraderKind.LLM_JUDGE`, `Severity.WARNING`, `Confidence.LOW`) when a
  criterion couldn't be grounded into a runnable check, or a non-empty ticket yielded zero criteria.

Because the advisory issue is double-clamped (advisory grader *and* low confidence), it can never gate
— but it also can never vanish into a PASS. The report surfaces as `WARN`, not `PASS`: absence of
verification is reported honestly, while a hallucinated judge can neither block a good merge nor bless
a broken one.

## See also

- **[Developer guide → MCP tools](usage.md#mcp-tools-the-verified-review-graders)** — the
  `verel_spec` / `verel_invariants` / `verel_smell` tool payloads and the shared response shape.
- **[Developer guide → Agent-run CI/CD](usage.md#agent-run-cicd-verelci)** — stages, receipts, and
  attestation in depth.
- **[CLI reference](cli.md)** — `verel-ci check` / `precommit` / `install`.
- **[Examples](examples.md)** — runnable, mostly offline demos for each grader.
- **[Configuration](configuration.md)** — env vars, the LLM seam, and grader knobs.
