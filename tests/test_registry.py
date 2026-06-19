"""Public Skill Registry + cross-tenant transfer + the H2 experiment (§2.2, §8.7). Offline."""

from verel.memory import LocalMemory, Trust
from verel.registry import (
    KILL_LINE,
    PublicRegistry,
    SkillArtifact,
    content_hash,
    export_skill,
    import_skill,
    measure_transfer,
)
from verel.toolsmith import SideEffect, ToolCase, ToolRecord, ToolRegistry

SLUG = "def slugify(s):\n    import re\n    return re.sub(r'[^a-z0-9]+','-', s.lower()).strip('-')\n"
# A tenant-specific id formatter — tenant A prefixes 'A', which won't match tenant B's cases.
IDFMT_A = "def fmt_id(n):\n    return 'A-' + str(n)\n"


def _tool(name, code, cap):
    return ToolRecord(name=name, code=code, capability=cap, side_effect=SideEffect.READ_ONLY,
                      eval_score=1.0).sign()


# ---- artifact ----
def test_artifact_content_addressed_and_signed():
    a = export_skill(_tool("slugify", SLUG, "url slug"), origin="tenant:A")
    assert a.content_hash == content_hash(SLUG) and a.verify()


def test_artifact_tamper_detected():
    a = export_skill(_tool("slugify", SLUG, "url slug"), origin="tenant:A")
    a.code = a.code + "\n# tampered\n"
    assert not a.verify()  # content_hash no longer matches code


# ---- public registry ----
def test_registry_publish_get_search(tmp_path):
    reg = PublicRegistry(tmp_path / "pub")
    a = reg.publish(export_skill(_tool("slugify", SLUG, "convert title to url slug"), origin="A"))
    assert reg.get(a.content_hash).name == "slugify"
    assert reg.search("url slug")[0].name == "slugify"
    assert len(reg.list()) == 1


def test_registry_refuses_tampered(tmp_path):
    reg = PublicRegistry(tmp_path / "pub")
    a = export_skill(_tool("x", SLUG, "c"), origin="A")
    a.code += "# evil"
    try:
        reg.publish(a)
        assert False
    except ValueError:
        pass


# ---- transfer: trust does NOT travel ----
def test_import_reverifies_against_target_corpus():
    a = export_skill(_tool("slugify", SLUG, "url slug"), origin="tenant:A")
    into = ToolRegistry(LocalMemory(), scope="tenant:B")
    res = import_skill(a, into, target_cases=[ToolCase(args=["Hello World"], expected="hello-world")],
                       sandbox=False)
    assert res.transferred and res.reverified  # universal skill re-verifies in B
    assert into.find("url slug")[0].name == "slugify"  # now verified locally


def test_import_installs_candidate_when_behavior_differs():
    a = export_skill(_tool("fmt_id", IDFMT_A, "format an id"), origin="tenant:A")
    into = ToolRegistry(LocalMemory(), scope="tenant:B")
    # tenant B expects a 'B-' prefix -> A's skill does not transfer
    res = import_skill(a, into, target_cases=[ToolCase(args=[123], expected="B-123")], sandbox=False)
    assert res.transferred and not res.reverified
    assert into.find("format an id", verified_only=True) == []  # candidate, not verified


# ---- H2 experiment ----
def test_measure_transfer_rate_and_decision():
    skills = [
        export_skill(_tool("slugify", SLUG, "url slug"), origin="A"),
        export_skill(_tool("fmt_id", IDFMT_A, "format an id"), origin="A"),
    ]
    targets = {
        "B": {"slugify": [ToolCase(args=["Hello World"], expected="hello-world")],
              "fmt_id": [ToolCase(args=[1], expected="B-1")]},
        "C": {"slugify": [ToolCase(args=["A B"], expected="a-b")],
              "fmt_id": [ToolCase(args=[2], expected="C-2")]},
    }
    rep = measure_transfer(skills, targets, sandbox=False)
    assert rep.attempts == 4
    # slugify transfers to B and C (2), fmt_id transfers to neither -> rate 0.5
    assert rep.transferred == 2 and abs(rep.rate - 0.5) < 1e-9
    assert rep.per_skill_rate()["slugify"] == 1.0 and rep.per_skill_rate()["fmt_id"] == 0.0
    assert "BUILD" in rep.decision  # 0.5 >= KILL_LINE


def test_skills_without_target_cases_not_counted():
    skills = [export_skill(_tool("slugify", SLUG, "url slug"), origin="A")]
    targets = {"B": {}}  # B has no cases for this capability
    rep = measure_transfer(skills, targets, sandbox=False)
    assert rep.attempts == 0 and rep.decision == "no data"


def test_kill_line_value():
    assert KILL_LINE == 0.20
