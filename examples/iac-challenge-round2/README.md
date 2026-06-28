# IaC challenge — Round 2 (blind)

Round 1 disclosed the planted issues up front. **Round 2 doesn't.** No spoilers, no count, no
answer key in this folder — find them yourself.

This is a small, realistic AWS stack: a CI runner role, a security group, a bootstrap step from
the shared platform module. The policy and network values are supplied by the pipeline's secret
store (see [`ci-pipeline.yml`](ci-pipeline.yml)), so the committed `.tf` reads clean — the
resolved values land in [`plan.json`](plan.json) (`terraform show -json`).

## The task

> **Find every change that grants more access than intended — before `apply`.**

Use **any combination of tools you like** — a reasoning layer (Code Reasoner) over the source,
a deterministic gate (verel) over the plan, both together, whatever. The interesting question is
what each layer surfaces on its own and what only shows up when you combine them.

```bash
# the deterministic gate, over the resolved plan
pip install verel
verel-ci iac --repo examples/iac-challenge-round2 --plan plan.json   # exit 1 on FAIL

# and/or point your editor / Code Reasoner at main.tf + plan.json + ci-pipeline.yml
```

## How to play

1. Run whatever combination of tools you want over the repo.
2. **Post what each tool finds** — the issues, the file/locator, and which tool surfaced each.
3. The **ground truth is held back** until findings are in, so nobody reasons backward from the
   answer. Once results are posted, we reveal the full key and score both layers against it —
   honestly, including anything either tool missed or false-flagged.

No tricks: every issue is a real, exploitable access-widening change that a careful reviewer
would want caught before this plan applies. Some are easier from the source; some only exist in
the resolved plan. That's the whole point of running the layers together.

*(Reproduce the plan yourself: set the pipeline's `TF_VAR_*` values, `terraform init && plan`,
then `terraform show -json`.)*
