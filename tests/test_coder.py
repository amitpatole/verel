"""The agent FixHook (§11.1 item 5) — tested offline with a fake Coder (no network/key)."""

import asyncio
from pathlib import Path

from verel.agents import make_fix_hook
from verel.agents.coder import _extract_file, _issues_block
from verel.verdict import GateResult, GraderKind, Issue, IssueKind, Report, Severity, Verdict, assign


class _FakeCoder:
    def __init__(self, reply: str):
        self.reply = reply
        self.calls = 0

    def fix(self, source, issues_text, *, filename):
        self.calls += 1
        self.seen_issues = issues_text
        return _extract_file(self.reply)


def _reports():
    r = Report(verdict=Verdict.FAIL, summary="", grader=GraderKind.DOM,
               issues=[Issue(kind=IssueKind.OVERFLOW, severity=Severity.ERROR,
                             message="panel overflows by 1120px", locator=".panel",
                             source=GraderKind.DOM)])
    return [assign(r)]


def test_fix_hook_writes_agent_output(tmp_path: Path):
    f = tmp_path / "page.html"
    f.write_text("<div class='panel' style='width:2400px'>x</div>\n")
    coder = _FakeCoder("Here:\n```html\n<div class='panel' style='width:100%'>x</div>\n```")
    changed = asyncio.run(make_fix_hook(coder, verbose=False)(str(f), GateResult(verdict=Verdict.FAIL), _reports()))
    assert changed is True
    assert "width:100%" in f.read_text()
    assert coder.calls == 1
    # the agent was shown the grounded issue (grader + kind + locator + message)
    assert "overflow" in coder.seen_issues and ".panel" in coder.seen_issues


def test_fix_hook_gives_up_on_noop(tmp_path: Path):
    f = tmp_path / "page.html"
    original = "<div>unchanged</div>\n"
    f.write_text(original)
    coder = _FakeCoder("```\n<div>unchanged</div>\n```")  # identical content
    changed = asyncio.run(make_fix_hook(coder, verbose=False)(str(f), GateResult(verdict=Verdict.FAIL), _reports()))
    assert changed is False
    assert f.read_text() == original


def test_fix_hook_gives_up_when_coder_raises(tmp_path: Path):
    f = tmp_path / "page.html"
    f.write_text("x\n")

    class _Boom:
        def fix(self, *a, **k):
            raise RuntimeError("model down")

    changed = asyncio.run(make_fix_hook(_Boom(), verbose=False)(str(f), GateResult(verdict=Verdict.FAIL), _reports()))
    assert changed is False  # a failed agent call is a give-up, not a crash


def test_extract_file_handles_bare_and_fenced():
    assert _extract_file("```python\nprint(1)\n```") == "print(1)"
    assert _extract_file("no fence here") == "no fence here"


def test_issues_block_lists_grader_and_locator():
    block = _issues_block(_reports())
    assert "dom/error" in block and "overflow" in block and ".panel" in block
