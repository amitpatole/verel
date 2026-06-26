# IAC-KICKOFF — Infrastructure-as-Code graders, IAM change sensor, and act-then-verify actuators

> Status track for the **DevOps / SRE / Platform-Engineering** capability in Verel: grade Terraform/
> OpenTofu (and the wider IaC + Kubernetes toolchain) on the verdict bus, **catch dangerous cloud IAM
> changes before they execute**, and gate `apply`/`destroy` through the action gateway with
> act-then-verify. Built **inbuilt** in Verel now, behind the gateway's three-layer seam
> (`verdict / enforce / adapters`) so it lifts out into `immel` (boundary/policy) + `actel`
> (act-then-verify) later as a package move, not a rewrite.

Follow this phase by phase. **Stop at each acceptance check for review.** The gate = lint + types +
tests green, run the way CI runs them. Security cadence (audit → triage → fix → verify → prove →
commit → ≥3 red-team rounds) applies to every phase with attack surface; the actuator phase gets the
full loop.

---

## Why this exists

Functional graders (tests/lint/types) are blind to infrastructure intent and to **cloud IAM blast
radius**. An IAM-affecting change rides inside a 200-resource `terraform plan`, a one-off `boto3`
call, or an agent tool action — passes every functional gate — and only surfaces as an incident or a
failed audit weeks later. Verel's verification-first contract is the right place to make those changes
**fail closed before they execute**.

Three capture surfaces, **one normalized model**, deterministic risk rules that gate, plus an
IAM-aware gateway escalation and a post-apply effective-access check.

---

## Design spine (maps onto what already exists)

- **Grader** = `GraderSpec(grader, command, cwd, covers, parser, lang)` + a **pure**
  `Parser: (stdout, stderr) -> list[Issue]` (`src/verel/ci/graders.py`). Adding a tool = a parser +
  a spec constructor. The `Runner` is injectable, so parsers are tested offline with no binaries.
- **Verdict bus** — issues carry per-issue `source: GraderKind` and grounding; the gate reducer
  (`src/verel/verdict/gate.py`) gates on `GATING_SEVERITY = ERROR` and clamps advisory graders. One
  plan Report can therefore carry IAC drift issues (`source=IAC`, informational) **and** IAM risk
  issues (`source=IAM`, gating) at once.
- **Gateway** — `Gateway.handle(tool, args)` already classifies `terraform destroy` → IRREVERSIBLE
  and `terraform apply` → CONSEQUENTIAL (`src/verel/gateway.py`). Built behind the
  `verdict / enforce / adapters` seam *specifically* so it extracts into `immel`+`actel` later.

### New verdict-bus vocabulary

| Addition | Where | Classification |
|---|---|---|
| `GraderKind.IAC` | `verdict/models.py` | **precise** (`PRECISE_GRADERS`) |
| `GraderKind.IAM` | `verdict/models.py` | **precise** (`PRECISE_GRADERS`) |
| `GraderKind.POLICY` | `verdict/models.py` | **precise** (`PRECISE_GRADERS`) |
| `GraderKind.COST` (promote) | `verdict/constants.py` | **precise**, gated vs an explicit budget only (mirrors PERF) |
| `IssueKind.IAC_DRIFT` | `verdict/models.py` | destroy/replace visibility |
| `IssueKind.IAM_RISK` | `verdict/models.py` | wildcard / privesc / public / admin |
| `IssueKind.MISCONFIG` | `verdict/models.py` | scanner misconfig findings |

---

## Tool → grader-bus mapping (the full DevOps suite)

| Tool | GraderKind | Precise? | Format | Phase |
|---|---|---|---|---|
| `terraform/tofu validate` | IAC | precise | text/JSON | 1 |
| `terraform/tofu plan` (`show -json`) | IAC (+ IAM extraction) | precise | plan JSON | 1 |
| `trivy config` | SECURITY | precise | `--format json` | 1 |
| `tflint` | LINT | precise | `--format json` | 2 |
| `checkov` | SECURITY | precise | `-o json` | 2 |
| `conftest` / OPA | POLICY | precise | JSON | 2 |
| `infracost` | COST | precise vs budget | `--format json` | 2 |
| `helm template` / `kubectl --dry-run` | IAC | precise | rendered YAML | 3 |
| `kube-score` / `kube-linter` / `polaris` | SECURITY | precise | JSON | 3 |
| Parliament / Cloudsplaining | IAM | precise | JSON | 2 |
| PMapper (privesc graph) | IAM | precise | JSON | 4 |
| AWS IAM Access Analyzer (validate + preview) | IAM | precise | JSON | 5 |
| GCP Policy Analyzer / IAM Recommender | IAM | precise | JSON | 5 |
| rbac-tool / `kubectl auth can-i` | IAM | precise | JSON | 3 |
| iamlive (capture → least-priv) | IAM | advisory | JSON | later |

---

## IAM change sensor — one model, three surfaces

```
IamChange{
  cloud, change_type: grant|widen|revoke|replace|create_principal,
  principal, actions[], resources[], effect, conditions[],
  source_locus,   # plan address / file:line / tool-call id
  blast_flags[],  # the deterministic risk hits
}
```

- **Capture A — IaC (pre-apply, Phase 1):** filter `terraform show -json` `resource_changes` for IAM
  resource types; richest, fully shift-left, zero new tooling.
- **Capture B — K8s RBAC (Phase 3):** extract Role/ClusterRole/(Cluster)RoleBinding from rendered
  manifests; rbac-tool / `can-i`.
- **Capture C — direct calls (Phase 4):** the **gateway** intercepts IAM-mutating tool actions
  (`attach_*_policy`, `add-iam-policy-binding`, `role assignment create`, `kubectl ... rolebinding`).

### Deterministic risk rules (precise → gating)

Wildcard action (`*`, `svc:*`) · wildcard resource (`Resource:*`) · public principal (`*`,
`allUsers`, `allAuthenticatedUsers`, SG `0.0.0.0/0`) · privilege-escalation primitives
(`iam:PassRole`, `iam:CreatePolicyVersion`, `AttachRolePolicy`, wildcard `sts:AssumeRole`) ·
admin/owner grants (`AdministratorAccess`, `roles/owner`, `cluster-admin`) · guardrail removal
(deleting a `Deny`) · cross-account/external principal expansion. Advisory layer (`LLM_JUDGE` /
`CONTRACT`, clamped): "does this grant match stated intent / least-privilege?"

---

## Gateway escalation (dynamic, from the bound plan)

On top of the destroy/replace escalation, the actuator's plan inspector flags IAM changes:

- IAM **widening** (grant / attach / new admin binding) → **IRREVERSIBLE** → dry-run + human approval,
  *regardless* of the rest of the plan (blast radius, not reversibility, drives this).
- IAM **revoke** → CONSEQUENTIAL but surfaced loudly (revokes break prod too).
- Pure create / no-op, no IAM widening → CONSEQUENTIAL → forwards on grader PASS.

### Plan-binding (TOCTOU defense — non-negotiable)

The thing approved **is** the thing applied: `plan -out=tfplan.bin` → `RunReceipt.inputs_digest`
binds the plan file's bytes → gateway `approve()` approves *that digest* → `apply tfplan.bin` consumes
exactly that file, **never a re-plan**. Reuses the existing receipt machinery 1:1.

---

## Phases

### Phase 0 — Foundations *(no user-facing surface; unblocks everything)*
- Add `GraderKind.IAC/IAM/POLICY` and `IssueKind.IAC_DRIFT/IAM_RISK/MISCONFIG`.
- Add all three to `PRECISE_GRADERS`; promote `COST` to precise.
- `verel[iac]` extra (binaries are external, not pip) + `verel doctor` probes `terraform`/`tofu`/
  `trivy`/`tflint`/`checkov`/`conftest`/`infracost` and reports presence; a **required** grader whose
  tool is absent fails closed (no silent green — mirrors `graders.py` tool-missing path).
- **Acceptance:** enums import; `PRECISE_GRADERS` updated; `verel doctor` lists the IaC tools;
  `ruff`+`mypy`+`pytest` green.

### Phase 1 — Read-only MVP slice *(ships "catch dangerous IaC + IAM before apply")*
- `src/verel/ci/iac.py`:
  - `parse_terraform_validate` (gates on validation errors),
  - `parse_terraform_plan` (drift/destroy/replace as `IAC_DRIFT` INFO + IAM risk issues),
  - `extract_iam_changes` + `iam_risk_issues` (the sensor core),
  - `parse_trivy_config` (SECURITY),
  - `plan_summary` / `destructive_changes` (for the Phase-4 actuator),
  - spec constructors `terraform_validate_spec`, `terraform_plan_spec`, `trivy_config_spec`.
- Export from `ci/__init__.py`; pure-parser tests over canned fixtures (offline, no binaries).
- **Acceptance:** a wildcard/privesc/public-principal IAM change in a sample plan produces a gating
  `IAM_RISK` issue; a destroy produces an `IAC_DRIFT` issue; trivy misconfig maps to SECURITY; all
  parsers tested offline; gate green.

### Phase 2 — Broaden graders
- `tflint` (LINT), `checkov` (SECURITY), `conftest`/OPA (POLICY) + policy-bundle distribution story,
  `infracost` (COST vs explicit budget), Parliament/Cloudsplaining (IAM least-priv report).
- **Acceptance:** each new tool has a pure parser + spec + tests; POLICY bundle documented; gate green.

### Phase 3 — Kubernetes graders + RBAC sensor
- `helm template` / `kubectl --dry-run` (IAC); reuse kube-score/kube-linter/polaris parsers from the
  k8s track (SECURITY); Capture B RBAC extraction + rbac-tool/`can-i` (IAM).
- **Acceptance:** rendered-manifest graders + RBAC risk rules tested offline; gate green.

### Phase 4 — Actuator + gateway *(the attack-surface phase — full security cadence)*
- `src/verel/actuators/terraform.py` (mirrors `gateway.py` seam): `plan → check → act → watch`.
- Plan-binding receipt; `apply tfplan.bin`; `destroy`; **dynamic escalation** incl. IAM widening;
  rollback hook. Dry-run default; human approval for irreversible. Capture C gateway interception of
  direct IAM calls.
- Security cadence specifics: plan-binding/TOCTOU, credential isolation (creds from `~/.config`,
  never logged, redact plan/state output), command/option injection (argv form; vars never
  string-built; watch `-`-prefixed values), state-file as secret, subprocess timeout + `RLIMIT_*`,
  fail closed on missing scanner / unparseable plan / crashing gate, never auto-apply destructive on
  advisory evidence.
- **Acceptance:** exploit run + blocked + regression-pinned for each finding; ≥3 clean red-team
  rounds; residual risk documented in `docs/SECURITY_RESIDUALS.md`; gate green.

### Phase 5 — Effective-access verify + integrations + docs (lockstep)
- `watch()` queries effective permissions (AWS IAM Access Analyzer preview / simulator,
  GCP Policy Analyzer) and confirms granted-vs-intended — needs cloud **read** creds from
  `~/.config`; accurate but not a pure offline gate.
- `verel-ci` wiring, MCP (`verel_iac_check`), REST gate; `docs/graders.md` (new kinds),
  `docs/integrations.md` (IaC + IAM section + CI examples), `examples/demo_iac.py` (broken HCL →
  grounded FAIL → fixed → PASS, no cloud creds, **real captured output**), `cli.md`, CHANGELOG,
  version bumps. `mkdocs build --strict` then curl live.
- **Acceptance:** docs build strict + serve live; demo runs key-free; gate green; `main` CI green.

---

## Open risks (carried, not hidden)
- Provider network calls during `plan` (SSRF-ish) cannot be fully sandboxed → residual, documented.
- Effective-access verification needs live cloud read access → accurate but not offline.
- Capture C requires the agent host to route cloud actions through the gateway (integration
  requirement, not just a parser).
- OPA/conftest + Cedar policy-bundle distribution & signing → designed in Phase 2.

— amitpatole
