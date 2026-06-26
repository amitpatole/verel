"""Wiring for the IaC sensor: the `grade_iac` entry point, the `verel_iac_check` MCP tool, and the
`verel-ci iac` CLI. Offline (no terraform/cloud)."""

import json

import pytest

from verel.ci import grade_iac
from verel.ci.__main__ import main as ci_main
from verel.mcp_server import dispatch
from verel.verdict import Verdict

_DANGEROUS = json.dumps({"resource_changes": [
    {"address": "aws_iam_policy.god", "type": "aws_iam_policy", "change": {"actions": ["create"],
        "after": {"policy": json.dumps({"Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"}]})}}}]})
_CLEAN = json.dumps({"resource_changes": [
    {"address": "aws_s3_bucket.a", "type": "aws_s3_bucket", "change": {"actions": ["create"]}}]})
_RBAC = json.dumps({"kind": "ClusterRoleBinding", "metadata": {"name": "b"},
                    "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
                    "subjects": [{"kind": "User", "name": "x"}]})


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content)
    return str(p)


# --- grade_iac (the shared entry point) ----------------------------------
def test_grade_iac_plan_fails_on_iam_risk(tmp_path):
    _write(tmp_path, "plan.json", _DANGEROUS)
    rep = grade_iac(str(tmp_path), plan="plan.json")
    assert rep.verdict == Verdict.FAIL
    assert any(i.detail["rule_id"] == "WILDCARD_ACTION" for i in rep.issues)


def test_grade_iac_clean_plan_passes(tmp_path):
    _write(tmp_path, "plan.json", _CLEAN)
    assert grade_iac(str(tmp_path), plan="plan.json").verdict == Verdict.PASS


def test_grade_iac_manifests_rbac(tmp_path):
    _write(tmp_path, "m.json", _RBAC)
    rep = grade_iac(str(tmp_path), manifests="m.json")
    assert rep.verdict == Verdict.FAIL and any(i.detail["rule_id"] == "ADMIN_GRANT" for i in rep.issues)


def test_grade_iac_rejects_path_escape(tmp_path):
    with pytest.raises(ValueError):
        grade_iac(str(tmp_path), plan="../../etc/passwd")


def test_grade_iac_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        grade_iac(str(tmp_path), plan="nope.json")


# --- MCP tool ------------------------------------------------------------
def test_mcp_iac_check_registered():
    from verel.mcp_server import TOOLS
    assert "verel_iac_check" in TOOLS


def test_mcp_iac_check_dispatch(tmp_path):
    _write(tmp_path, "plan.json", _DANGEROUS)
    out = dispatch("verel_iac_check", {"repo": str(tmp_path), "plan": "plan.json"})
    assert out["verdict"] == "fail"
    assert any(i["rule_id"] == "WILDCARD_ACTION" and i["grader"] == "iam" for i in out["issues"])


def test_mcp_iac_check_requires_an_artifact(tmp_path):
    out = dispatch("verel_iac_check", {"repo": str(tmp_path)})
    assert "error" in out


def test_mcp_iac_check_bad_repo():
    out = dispatch("verel_iac_check", {"repo": "/does/not/exist", "plan": "p.json"})
    assert "error" in out


# --- CLI -----------------------------------------------------------------
def test_cli_iac_fail_exit_code(tmp_path, capsys):
    _write(tmp_path, "plan.json", _DANGEROUS)
    rc = ci_main(["iac", "--repo", str(tmp_path), "--plan", "plan.json"])
    assert rc == 1  # FAIL → non-zero
    assert "verdict=fail" in capsys.readouterr().out


def test_cli_iac_pass_exit_code(tmp_path, capsys):
    _write(tmp_path, "plan.json", _CLEAN)
    rc = ci_main(["iac", "--repo", str(tmp_path), "--plan", "plan.json"])
    assert rc == 0 and "verdict=pass" in capsys.readouterr().out


def test_cli_iac_requires_artifact(tmp_path):
    assert ci_main(["iac", "--repo", str(tmp_path)]) == 2
