"""Catch a dangerous cloud-IAM change BEFORE `terraform apply` (no cloud creds needed).

The IAM change sensor reads a `terraform show -json` plan, normalizes every IAM-affecting change, and
runs deterministic risk rules (wildcard / privilege-escalation / public-principal / admin / open
ingress) that gate. A broken plan → grounded FAIL; the fixed plan → PASS. Fully offline.

Run:  python examples/demo_iac.py
"""

from __future__ import annotations

import json

from verel.actuators import escalate
from verel.ci import extract_iam_changes, iam_risk_issues, parse_terraform_plan

# A plan that grants a wildcard admin policy and opens SSH to the world — the kind of change that
# passes tests/lint/types and only bites later.
BROKEN = json.dumps({"resource_changes": [
    {"address": "aws_iam_policy.admin", "type": "aws_iam_policy", "change": {"actions": ["create"],
        "after": {"policy": json.dumps({"Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"}]})}}},
    {"address": "aws_security_group_rule.ssh", "type": "aws_security_group_rule",
        "change": {"actions": ["create"], "after": {"type": "ingress", "cidr_blocks": ["0.0.0.0/0"]}}},
    {"address": "aws_db_instance.legacy", "type": "aws_db_instance", "change": {"actions": ["delete"]}},
]})

# The fixed plan: scoped action + resource, ingress limited to the VPC, no destroy.
FIXED = json.dumps({"resource_changes": [
    {"address": "aws_iam_policy.admin", "type": "aws_iam_policy", "change": {"actions": ["create"],
        "after": {"policy": json.dumps({"Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::app/*"}]})}}},
    {"address": "aws_security_group_rule.ssh", "type": "aws_security_group_rule",
        "change": {"actions": ["create"], "after": {"type": "ingress", "cidr_blocks": ["10.0.0.0/16"]}}},
]})


def grade(label: str, plan_json: str) -> None:
    issues = parse_terraform_plan(plan_json)
    gating = [i for i in issues if i.severity.value in ("error", "critical")]
    verdict = "FAIL" if gating else "PASS"
    cls, reasons = escalate(json.loads(plan_json))
    print(f"\n{label}: {verdict}  (apply → {cls.value}{'; ' + ', '.join(reasons) if reasons else ''})")
    for i in issues:
        rule = i.detail["rule_id"]
        print(f"  [{i.severity.value:8}] {i.source.value:4} {rule:22} {i.locator}")


print("=== IAM change sensor — grade a terraform plan before apply ===")
grade("broken plan", BROKEN)
grade("fixed plan", FIXED)

n = len(iam_risk_issues(extract_iam_changes(json.loads(BROKEN))))
print(f"\n→ {n} IAM risk(s) caught in the broken plan, each grounded on a plan address. "
      "No cloud credentials, no apply — the dangerous grant never reaches AWS.")
