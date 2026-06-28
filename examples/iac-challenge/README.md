# IaC challenge — "the clean plan that lies"

A small, **realistic** AWS Terraform stack (a VPC, a security group, an RDS instance, an S3
bucket, a couple of IAM roles, a `null_resource`). Run `terraform plan` and it looks clean —
there's no literal `0.0.0.0/0`, no `Action = "*"` sitting in plain sight, and most of the
stack is correctly locked down (private DB, all-four S3 public-access-block flags on, a scoped
least-privilege policy, normal service-trust roles).

But **four** changes grant more access than intended — each invisible or near-invisible in the
plan *diff*. The point of this challenge is the *layer*: how much does a tool catch when the
danger isn't in the text it's handed?

## The task

> **Find every change that grants more access than intended — before `apply`.**

Same input to any tool: the [`main.tf`](main.tf) source (what an editor would scan) and the
[`plan.json`](plan.json) (`terraform show -json`).

## The planted issues

| # | What | Why it's hard to see |
|---|---|---|
| 1 | A security-group rule open to the **whole internet** | written as two halves — `cidr_blocks = ["0.0.0.0/1", "128.0.0.0/1"]` — so a search for `0.0.0.0/0` finds nothing |
| 2 | A CI role with an **admin (`*:*`) policy** | the policy is `data.aws_iam_policy_document.ci_permissions.json` (defined far from where it's attached) → rendered **`(known after apply)`**, i.e. *null in the plan diff* |
| 3 | A provisioner that **attaches `AdministratorAccess` at apply** | a `null_resource` `local-exec`; it's a **no-op in `resource_changes`** — the command lives in the plan's `configuration` block, not the diff |
| 4 *(stretch)* | An out-of-band **admin grant the config now matches** | there is **no planned change** for it, so it never appears in `resource_changes` — only Terraform's `resource_drift` sees it |

Issues 1–3 are in the source: a reasoning tool *could* find them — the test is whether
reasoning-over-a-report reliably does. Issue 4 is the honest stretch: it is **not in the plan
or the source at all** (it's live drift), so anything reading the diff structurally cannot see it.

## How Verel scores it

```bash
pip install verel
verel-ci iac --repo examples/iac-challenge --plan plan.json   # exit 1 on FAIL
```

```
[iac] verdict=fail
  iac:error    null_resource.bootstrap            UNAUDITABLE_PROVISIONER  — runs an unauditable program at apply
  iam:error    aws_security_group_rule.ops_ssh    OPEN_INGRESS             — ingress open to the world
  iam:error    aws_iam_role_policy.ci             UNKNOWN_IAM_CONTENT      — IAM field computed (known after apply) → fail closed
  iam:critical aws_iam_role_policy.legacy_admin   PRIVILEGE_ESCALATION     — [live, un-reverted] action "*"
  iam:error    aws_iam_role_policy.legacy_admin   WILDCARD_ACTION / WILDCARD_RESOURCE
```

**4 dangers caught, 0 false positives** — the 8 benign resources (private DB, locked-down S3,
scoped policy, service-trust roles, VPC, log group) produce nothing.

How each is caught (deterministically, regardless of plan size):
- **#1** — real CIDR coverage math (via `ipaddress`), not a `0.0.0.0/0` string match: `0.0.0.0/1 + 128.0.0.0/1` collapses to the whole internet.
- **#2** — reads `change.after_unknown`; a computed IAM field **fails closed** (`UNKNOWN_IAM_CONTENT`) instead of passing on an unverifiable blast radius.
- **#3** — parses the plan's `configuration` block for `local-exec`/`remote-exec` provisioners and `external`/`http` data sources, gates them, and the gateway escalates the apply to `IRREVERSIBLE` (human approval).
- **#4** — grades Terraform's `resource_drift`; a live, un-reverted grant with no planned change gates at full severity.

## Reproduce it yourself

The answer key above is literally `verel-ci iac`'s output on `plan.json` — run the command and
you'll get it byte-for-byte. To regenerate the plan from source with your own Terraform (≥1.6):

```bash
cd examples/iac-challenge
terraform init
TF_VAR_db_password=x terraform plan -out tfplan.bin
terraform show -json tfplan.bin > plan.json   # (issue #4 appears only if the live drift exists)
```

## The honest takeaway

This isn't "tool A beats tool B." It's a **layer** distinction. A reasoning council that scans a
diagnostic report is strong at *proposing* fixes from what's visible. A deterministic gate that
parses `configuration` / `after_unknown` / `resource_drift` catches what *isn't* in the diff and
**proves** it the same way every time. They're complementary: reason about the change → then
verify it against the plan before it ships.
