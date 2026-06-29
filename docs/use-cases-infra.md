# Use cases — SRE, Platform & Cloud Engineering

> The throughline: **catch a dangerous infrastructure or cloud-IAM change *before* `apply`** — whether
> a human or an agent authored it — gate it on one verdict bus, escalate the irreversible to a human,
> and emit a **signed receipt** of what actually ran. Nothing is "done" until a grader says so.

Modern infra work is increasingly agent-driven: an LLM writes the Terraform, edits the RBAC, opens the
PR. The agent is author *and* reviewer, and the blast radius is your cloud account. Verel's
[IaC / cloud-IAM grader track](graders.md#iac-devops-grade-terraform-kubernetes-cloud-iam-before-apply)
gives you a deterministic, offline, attestable gate that a wildcard policy, a public bucket, a
`cluster-admin` binding, or a `local-exec` that grants admin **cannot** slip past.

## Who this is for

| Persona | Owns | The pain |
|---|---|---|
| **Cloud Engineering** | the cloud accounts, landing zones, IAM, networking | a dangerous grant rides inside a 200-resource plan; least-privilege erodes; public exposure and cross-account trust creep in; "what does this role *actually* have?" |
| **Platform Engineering** | the paved road / golden paths, the self-service developer platform | guardrails must scale to every team's repo **without** becoming a human bottleneck; agents and app teams provision infra you can't hand-review |
| **SRE** | reliability, the blast radius, incident response, the SLOs | a bad change reaches prod; out-of-band drift; cost blowouts; postmortems need *verifiable* evidence of what ran, not a screenshot of a green check |

All three share one substrate: the **verdict bus** (`pass`/`warn`/`fail` with grounded issues), the
**action gateway** (classifies every consequential action; irreversible ones require human approval),
and **signed receipts** (an attestation that a required grader actually ran the frozen checks over the
changed files and produced the graded verdict — publicly verifiable with `verel verify`).

---

## Part 1 — Cloud Engineering: the IAM blast radius

### 1. A dangerous IAM grant rides inside a 200-resource plan

A `terraform plan` is a wall of green. Buried at resource #147 is an inline policy with
`Action: "*", Resource: "*"`, or a role anyone can assume. Functional tests, `terraform validate`, and
lint all pass — the grant only surfaces in an incident or a failed audit months later.

The **cloud-IAM change sensor** reads a `terraform show -json` plan offline (no cloud creds) and runs
deterministic rules across AWS / GCP / Azure / Kubernetes:

```bash
terraform plan -out tfplan.bin
terraform show -json tfplan.bin > tfplan.json
verel-ci iac --repo . --plan tfplan.json     # exit 1 on FAIL — wire it into CI
```

```
[iac] verdict=fail
      iam:critical aws_iam_role_policy.admin  privilege-escalation action (iam:PassRole) granted
      iam:error    aws_iam_policy.broad       wildcard action granted
      iam:critical aws_s3_bucket_policy.data  policy grants access to a public principal
```

It catches **20 rule classes** — wildcard action/resource, `iam:PassRole`/`sts:AssumeRole`/
`lambda:AddPermission` privilege escalation, public principals, admin grants
(`AdministratorAccess`/`roles/owner`/`cluster-admin`), allow-by-exclusion (`NotAction`), and more (the
full catalog is in [Graders → the IAM/IaC rule catalog](graders.md#the-iamiac-rule-catalog)). Each is a
grounded `IAM_RISK` on the bus with a precise locator, so a reviewer (or an agent) jumps straight to the
offending resource.

### 2. "The plan is not reality" — what the diff *can't* show you

The hardest infra failures are the ones a clean plan hides. Verel closes three of them:

- **Provisioners and side-effecting data sources are gated.** A `null_resource` with
  `provisioner "local-exec" { command = "aws iam attach-role-policy …AdministratorAccess" }` shows as a
  benign no-op in `resource_changes` — the command runs admin-granting code at apply that the diff never
  reveals. Verel parses the plan's `configuration` block and **gates it** (`UNAUDITABLE_PROVISIONER`),
  and the actuator escalates the apply to require human approval. A `data "external"` program and a
  `data "http"` (exfil/SSRF at refresh) are caught the same way.
- **Computed IAM fails closed.** When a policy is `policy = data.aws_iam_policy_document.x.json`,
  Terraform renders `(known after apply)` and the value is *invisible* in the plan. Verel does **not**
  treat "can't tell" as "safe" — it gates `UNKNOWN_IAM_CONTENT` rather than passing on an unverifiable
  blast radius.
- **Out-of-band drift is graded.** Terraform reports live divergence separately in `resource_drift`. If
  someone grants admin out-of-band and then writes the config to match it, there's *no planned change* —
  yet Verel evaluates the drift too and **gates** a live, un-reverted admin grant.

These are the defaults; you don't configure them. They were hardened against a hostile plan as untrusted
input over a 14-round adversarial security cadence.

### 3. Multi-cloud public exposure — every leg of the triad

Public exposure isn't always a policy `Statement`. Verel models the flat-field forms too, across clouds:

| Change | Rule | Cloud |
|---|---|---|
| `aws_s3_bucket_acl` `public-read` / an `AllUsers` grant | `PUBLIC_ACL` | AWS |
| S3 public-access-block deleted or a flag false/absent | `PUBLIC_ACCESS_BLOCK_DISABLED` | AWS |
| `publicly_accessible = true` (RDS / Redshift / DMS / …) | `PUBLIC_DB_ENDPOINT` | AWS |
| `azurerm_storage_account` anonymous blob access | `PUBLIC_BLOB_ACCESS` | Azure |
| `google_compute_firewall` / `azurerm_network_security_rule` open to `0.0.0.0/0` (incl. split-CIDR halves) | `OPEN_INGRESS` | GCP · Azure · AWS SG |
| `aws_lambda_permission` `principal = "*"` (public invoke) | `PUBLIC_PRINCIPAL` | AWS |
| a trust policy granting a concrete external account `sts:AssumeRole` | `CROSS_ACCOUNT_TRUST` (advisory) | AWS |

The open-ingress check uses real CIDR math, so the `0.0.0.0/1 + 128.0.0.0/1` "two halves of the
internet" trick is caught, while a legitimate `10.0.0.0/8` stays clean.

### 4. "What does this role *actually* have?" — effective access

Pre-apply graders read what a change *intends*. The opt-in, online
[`verel verify-access`](cli.md) reads what the cloud **actually grants** — it shells out
to the cloud's own analyzers with read-only creds resolved from `~/.config` (never logged), and maps the
findings onto the same verdict bus.

```bash
# Static: does this policy DOCUMENT have findings? (IAM Access Analyzer validate-policy)
verel verify-access --cloud aws --policy-file policy.json

# Effective: what is this principal ACTUALLY allowed, across all attached/inline/SCP policies?
verel verify-access --cloud aws --principal-arn arn:aws:iam::123456789012:role/app \
                    --action iam:PassRole sts:AssumeRole

verel verify-access --cloud gcp   --scope projects/prod      # analyze-iam-policy
verel verify-access --cloud azure                            # role assignment list
```

It **fails closed** (exit 2) when the cloud's creds are absent — never a silent pass — and the live
checks are held to a *superset* of the offline sensor's privilege-escalation set, so the "what the cloud
really grants" answer is never blinder than the plan grader.

### 5. Act-then-verify: gate the `apply` itself, not just the plan

Grading a plan is good; trusting that the *approved* plan is the one that applies is better. The
**Terraform actuator** binds the plan to a digest and applies *exactly* those bytes:

```python
from verel.actuators import TerraformActuator

act = TerraformActuator(repo=".")
plan = act.plan()                       # grades the BOUND plan file (drift + the IAM sensor)
if plan.report.verdict is Verdict.PASS:
    res = act.act(plan.plan_digest)     # applies EXACTLY that file — a re-plan/swap is REFUSED
    convergence = act.watch()           # re-plans after apply; PASS only when the world converged
```

A re-plan or file substitution between approval and apply is rejected (the plan-binding / TOCTOU
defense). And the gateway escalates **dynamically**: any destroy/replace, IAM widening, or
provisioner ⇒ `IRREVERSIBLE` (dry-run + **human approval**); a pure create/no-op stays `CONSEQUENTIAL`
(verdict-gated). Direct IAM-mutating tool calls (`attach-role-policy`, `set-iam-policy`, …) are
intercepted the same way — so an *agent* driving `terraform apply` gets a human in the loop precisely
when the change is irreversible, and only then.

---

## Part 2 — Platform Engineering: guardrails at scale, without the bottleneck

### 6. Policy-as-code in every repo's CI — one verdict, zero human bottleneck

The paved road needs a guardrail that runs the same way in every team's pipeline and gates the build —
not a wiki page nobody reads. The offline sensor is exit-coded for exactly this:

```yaml
# .github/workflows/iac-gate.yml — fail the PR on a dangerous plan
- run: pip install verel
- run: terraform show -json tfplan.bin > tfplan.json
- run: verel-ci iac --repo . --plan tfplan.json   # exit 1 → red build
```

```yaml
# .pre-commit-config.yaml — catch it before it's even pushed (a local hook over a refreshed plan)
- repo: local
  hooks:
    - id: verel-iac
      name: verel IaC/IAM gate
      entry: bash -c 'terraform show -json tfplan.bin > tfplan.json && verel-ci iac --repo . --plan tfplan.json'
      language: system
      pass_filenames: false
```

The same sensor backs `verel serve` (a REST gate with a `POST /github` PR webhook) and the
`verel_iac_check` MCP tool — so every surface (CI, pre-commit, a bot, an agent host) reaches the **same**
deterministic verdict. App teams keep their velocity; the platform team sets the rules once.

### 7. Kubernetes RBAC guardrails — before the manifest lands

The same engine grades native Kubernetes RBAC (or the Terraform `kubernetes_*` provider), so an
over-broad role never reaches the cluster:

```bash
kubectl apply -f rbac/ --dry-run=client -o json > manifests.json
verel-ci iac --repo . --manifests manifests.json
```

It gates `WILDCARD_RBAC` (`*` verbs on `*` resources), write-all over `*` (create rolebindings/webhooks
→ takeover), `escalate`/`bind`/`impersonate`, admission-webhook / CSR-approval / node-proxy escalation
primitives, `serviceaccounts/token` minting, binding to the built-in `cluster-admin` / `admin` / `edit`
ClusterRoles, `system:masters` / anonymous subjects, and secret reads in privileged namespaces — with
`SECRETS_ACCESS` and `AGGREGATION_RULE` as advisories. Wire it into Argo/Flux pre-sync, a PR check, or
the agent's MCP host.

### 8. Self-service infra for app teams — the agent proposes, Verel disposes

The platform's promise is "ship your own infra." The risk is that the proposer is now an LLM. Point the
agent at the gate via `verel rules` / `verel mcp install`, and the loop becomes: the agent writes the
Terraform → Verel grades the bound plan → a clean plan with only creates applies on the verdict → a
destroy/replace or IAM widening **stops for human approval** at the gateway. The human is involved
exactly at the irreversible moments, not on every PR — which is what makes self-service safe *and* fast.

### 9. Grade a repo *in-cluster* — the operator + `GateRun` CRD

For a platform running its own control plane, the [Kubernetes operator](kubernetes.md) turns a grade
into a first-class cluster object. Apply a `GateRun` and the operator runs it as a hardened, network-
isolated `Job`, then writes the **verdict + a signed receipt** back to `.status`:

```yaml
apiVersion: verel.dev/v1alpha1
kind: GateRun
metadata: { name: grade-platform-iac }
spec:
  repo: https://github.com/acme/platform-infra
  # → operator schedules a deny-egress, nonroot, read-only-rootfs Job; verdict + receipt land in .status
```

A `Brain`, `GatewayService`, and `VerelFleet` CRD round out an in-cluster, GitOps-native verification
plane — the gate becomes part of the platform, not a script bolted onto CI.

### 10. The platform's lessons stop getting relearned

Every team rediscovering "don't make the bucket public" is pure toil. Verel's **failure memory** (the
failure-ledger) records a graded failure once; a later run recognizes the regression and the platform's
hard-won rules **compound** instead of evaporating between repos and incidents. Only verified work enters
memory — a green check that wasn't actually graded doesn't count.

---

## Part 3 — SRE: blast radius, drift, cost, and attestable evidence

### 11. Stop a bad change reaching prod — canary + deterministic rollback

The self-healing pipeline runs stages (inner-loop → pre-commit → pre-merge → **canary**). When the
canary grader fails, the **rollback engine** performs a deterministic `git revert` to the last good
HEAD — and it **refuses to act on advisory-only evidence** (a `WARN` never triggers a rollback, only a
gating `FAIL` does). The blast radius is bounded by a control you can reason about, not a flaky heuristic.

### 12. Catch out-of-band drift before it becomes an incident

Configuration drift — a manual console change, an emergency `kubectl edit`, a break-glass grant nobody
reverted — is the classic source of "but it worked in the plan." Because Verel grades Terraform's
`resource_drift`, a live, un-reverted dangerous grant **gates** even when the plan shows no change. Run
it on a schedule against a refreshed plan and drift becomes a verdict, not a surprise.

### 13. Cost guardrails — gate a plan that blows the budget

Cost is a reliability concern (a runaway `for_each` is an outage *and* a bill). The `infracost` grader
gates only against an **explicit** budget — never an inferred one — so it behaves like a perf budget:

```python
from verel.ci import infracost_spec
spec = infracost_spec(repo=".", budgets={"monthly": 5000, "diff": 500})   # FAIL if exceeded
```

### 14. Attestable evidence for postmortems, audits, and compliance

A green checkmark is a *claim*. SRE and AppSec need to prove **what actually ran**. A Verel gate emits a
**run-receipt**: a signed attestation that a required grader ran the frozen checks over the changed
files and produced the graded verdict — binding the *actual outcome*, not just "a run happened."

```bash
verel verify receipt.json --require-public   # ed25519 → verifiable with only the runner's PUBLIC key
```

A reviewer, an auditor, or a downstream consumer confirms an agent's `pass` was real **without trusting
its producer**. That turns "we have a CI gate" into "here is cryptographic evidence the gate ran and what
it found" — the difference between a control and an attestable control.

### 15. Self-healing infra CI — failing checks fix themselves, then re-gate

When an infra change breaks a test or a policy, `verel heal` lets an agent patch the **source** (never
the checks) and re-gates until the *graders themselves* go green (`terminated_on=passed`) — so an
on-call engineer isn't paged for a mechanical fix an agent can make under a verdict.

```bash
verel heal --repo .          # failing graders → agent patches source → stage re-gates to green
```

### 16. Close the loop with the rest of the organism

Verel is the brain; the verdict bus is shared. After an actuator (`actel`) changes the world, the other
senses **confirm** it: vitals (`vitel`) grade SLOs/health, the eyes (`agentvision`) grade a rendered
dashboard, knowledge (`citel`) gates what enters memory. "Done" means a sense returned a verdict that the
world is actually in the intended state — not that a script exited 0. (See the
[organism overview](index.md).)

---

## Wiring it into your platform

| Surface | Command | Use it for |
|---|---|---|
| **CI gate** | `verel-ci iac --repo . --plan tfplan.json` (exit 1 on FAIL) | every repo's pipeline / pre-merge |
| **Pre-commit** | a `repo: local` hook calling `verel-ci iac` (or the published `verel-precommit` hook, `rev: v1.2.0`, for the full gate) | catch it before the push |
| **Agent host (MCP)** | `verel mcp install` → `verel_iac_check` | an agent grades its own plan/manifests |
| **Rules file** | `verel rules` | make any agent gate via Verel |
| **REST + PR webhook** | `verel serve --repo .` (`POST /gate`, `POST /github`) | a shared gate service / bot |
| **In-cluster** | the operator + `GateRun` CRD | GitOps-native, in-cluster grading |
| **Effective access** | `verel verify-access --cloud {aws,gcp,azure}` | online "what does the cloud actually grant" |
| **Act-then-verify** | `verel.actuators.TerraformActuator` | gate the `apply`/`destroy`, not just the plan |

## Which one is you?

| If you… | Start with | Then |
|---|---|---|
| own the cloud accounts / IAM / landing zones (Cloud Eng) | **1, 4** | 2, 3, 5 |
| run the paved road for many teams (Platform Eng) | **6, 7** | 8, 9, 10 |
| own reliability and the blast radius (SRE) | **11, 14** | 12, 13, 15 |

See also: [Graders](graders.md) · [Integrations](integrations.md) · [Deploy on Kubernetes](kubernetes.md)
· [CLI](cli.md) · [the original product use cases](use-cases.md).
