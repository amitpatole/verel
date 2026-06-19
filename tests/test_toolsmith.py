"""Tool-smith lifecycle (§7.6) — offline with a fake chat that returns known-good code."""

from verel.memory import LocalMemory, Trust
from verel.toolsmith import SideEffect, ToolCase, ToolRegistry, ToolSmith, ToolSpec, load_callable
from verel.toolsmith.registry import ToolRecord

SLUGIFY_CODE = '''
def slugify(text):
    import re
    s = text.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-")
'''

BAD_CODE = '''
def slugify(text):
    return text  # wrong: doesn't slugify
'''


def _spec(name="slugify", side_effect=SideEffect.READ_ONLY):
    return ToolSpec(
        name=name, capability="convert a title string into a url slug",
        signature_hint="slugify(text: str) -> str", side_effect=side_effect,
        cases=[
            ToolCase(args=["Hello World"], expected="hello-world"),
            ToolCase(args=["  Verel Rocks!  "], expected="verel-rocks"),
            ToolCase(args=["A/B testing 101"], expected="a-b-testing-101"),
        ],
    )


def _smith(reply):
    reg = ToolRegistry(LocalMemory(), scope="global")
    return ToolSmith(reg, chat=lambda msgs: reply), reg


def test_good_tool_is_verified_and_registered_and_reusable():
    smith, reg = _smith(f"```python\n{SLUGIFY_CODE}\n```")
    res = smith.build(_spec())
    assert res.passed and res.trust == Trust.VERIFIED and res.registered
    assert res.score == 1.0
    # reuse: a second build with the same capability returns the registered tool, no rebuild
    res2 = smith.build(_spec())
    assert res2.reused and res2.tool.name == "slugify"
    # the registered tool actually runs
    fn = load_callable(reg.find("url slug")[0])
    assert fn("Hello World") == "hello-world"


def test_failing_tool_not_registered():
    smith, reg = _smith(f"```python\n{BAD_CODE}\n```")
    res = smith.build(_spec())
    assert not res.passed and not res.registered and "red" in res.reason
    assert reg.find("url slug", verified_only=False) == []


def test_destructive_tool_requires_human_review():
    spec = _spec(side_effect=SideEffect.DESTRUCTIVE)
    smith, reg = _smith(f"```python\n{SLUGIFY_CODE}\n```")
    # no reviewer -> registered as candidate, not verified
    res = smith.build(spec, human_review=None)
    assert res.passed and res.trust == Trust.CANDIDATE
    assert reg.find("url slug", verified_only=True) == []  # not reusable until verified
    # an approving reviewer -> verified
    smith2, reg2 = _smith(f"```python\n{SLUGIFY_CODE}\n```")
    res2 = smith2.build(_spec(side_effect=SideEffect.DESTRUCTIVE), human_review=lambda t: True)
    assert res2.trust == Trust.VERIFIED


def test_signature_tamper_is_rejected_on_load():
    import pytest

    tool = ToolRecord(name="slugify", code=SLUGIFY_CODE).sign()
    assert tool.verify()
    tool.code = BAD_CODE  # tamper after signing
    assert not tool.verify()
    with pytest.raises(ValueError, match="signature"):
        load_callable(tool)


def test_sandbox_blocks_filesystem_access():
    import pytest

    evil = ToolRecord(name="evil", code="def evil():\n    return open('/etc/passwd').read()\n").sign()
    fn = load_callable(evil)
    with pytest.raises(Exception):  # open is not in the restricted builtins -> NameError
        fn()
