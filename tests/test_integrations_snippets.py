"""R0 adoption snippets — `verel mcp install` / `verel rules` produce correct, drop-in content."""

import json

import pytest

from verel.cli import main
from verel.integrations import RULES_TARGETS, mcp_config_json, mcp_install_hint, rules_snippet


def test_mcp_config_is_valid_standard_mcp_json():
    cfg = json.loads(mcp_config_json())
    assert cfg == {"mcpServers": {"verel": {"command": "verel-mcp"}}}


def test_install_hint_lists_hosts_and_the_config():
    hint = mcp_install_hint()
    assert "verel-mcp" in hint
    assert "claude-desktop" in hint and "cursor" in hint  # names the known hosts


@pytest.mark.parametrize("target,filename", sorted(RULES_TARGETS.items()))
def test_rules_snippet_per_target(target, filename):
    fn, content = rules_snippet(target)
    assert fn == filename
    # the universal instruction: gate before done, never edit tests, the tool name
    assert "verel_gate" in content
    assert "done" in content.lower()
    assert "Never edit or weaken tests" in content
    # markdown doc targets carry an H1; rules-file targets are just the section
    assert content.startswith("# ") if target in ("claude", "agents") else content.startswith("## ")


def test_rules_unknown_target_raises():
    with pytest.raises(ValueError, match="unknown rules target"):
        rules_snippet("nope")


def test_cli_rules_write_is_idempotent(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["rules", "--target", "agents", "--write"]) == 0
    f = tmp_path / "AGENTS.md"
    assert f.exists() and "verel_gate" in f.read_text()
    once = f.read_text()
    assert main(["rules", "--target", "agents", "--write"]) == 0  # second run = no-op
    assert f.read_text() == once  # not appended twice
    assert "already contains" in capsys.readouterr().out


def test_cli_rules_appends_under_existing_content(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "AGENTS.md").write_text("# My project\n\nExisting guidance.\n")
    assert main(["rules", "--target", "agents", "--write"]) == 0
    text = (tmp_path / "AGENTS.md").read_text()
    assert "Existing guidance." in text and "verel_gate" in text  # preserved + appended


def test_cli_rules_copilot_writes_nested_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["rules", "--target", "copilot", "--write"]) == 0
    assert (tmp_path / ".github" / "copilot-instructions.md").exists()


def test_cli_mcp_install_json(capsys):
    assert main(["mcp", "install", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"mcpServers": {"verel": {"command": "verel-mcp"}}}
