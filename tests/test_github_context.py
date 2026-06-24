"""R2 — GitHub PR-context fetch: pure parsers + injectable-fetch orchestration (offline)."""

import json

from verel.integrations.github import (
    acceptance_text,
    changed_files,
    fetch_pr_context,
    linked_issue_numbers,
)


def test_linked_issue_numbers():
    body = "This fixes #12 and Closes #34. See also #99 (not a closer). resolves owner/r#34"
    assert linked_issue_numbers(body) == [12, 34]  # only the closing keywords, de-duped


def test_changed_files_parses_diff():
    diff = ("diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n+b\n"
            "diff --git a/r.md b/r.md\n--- a/r.md\n+++ b/r.md\n@@ -1 +1 @@\n-x\n+y\n"
            "diff --git a/d.py b/d.py\n--- a/d.py\n+++ /dev/null\n")
    assert changed_files(diff) == ["x.py"]  # .py only, /dev/null deletion dropped


def test_acceptance_text_assembles_intent():
    text = acceptance_text("Add tax", "Total must include tax.", ["AC: $100@10% = $110"])
    assert "# Add tax" in text and "include tax" in text and "$110" in text


def test_fetch_pr_context_with_injected_fetch():
    pr = {"title": "Apply tax", "body": "Total includes tax. Closes #7"}
    issue = {"body": "AC: total_with_tax([60,40],0.1) == 110"}
    diff = "diff --git a/taxes.py b/taxes.py\n--- a/taxes.py\n+++ b/taxes.py\n@@ -1 +1 @@\n-x\n+y\n"

    def fake_fetch(path, *, accept="application/vnd.github+json"):
        if path.endswith("/pulls/3") and "diff" in accept:
            return diff.encode()
        if path.endswith("/pulls/3"):
            return json.dumps(pr).encode()
        if path.endswith("/issues/7"):
            return json.dumps(issue).encode()
        raise AssertionError(f"unexpected path {path}")

    ctx = fetch_pr_context("o/r", 3, fetch=fake_fetch)
    assert ctx["title"] == "Apply tax"
    assert ctx["changed_files"] == ["taxes.py"]
    assert "total_with_tax" in ctx["criteria"]  # linked-issue body folded into the criteria
    assert ctx["diff"] == diff


def test_fetch_pr_context_rejects_non_http_api():
    import pytest
    with pytest.raises(ValueError, match="api must be http"):
        fetch_pr_context("o/r", 1, api="file:///etc")


def test_fetch_pr_context_rejects_hostile_repo_and_number():
    import pytest
    with pytest.raises(ValueError, match="invalid repo"):
        fetch_pr_context("o/r\r\nX: 1", 1)              # CRLF / path injection into the URL
    with pytest.raises(ValueError, match="invalid repo"):
        fetch_pr_context("../../etc", 1)
    with pytest.raises(ValueError, match="number must be"):
        fetch_pr_context("o/r", 0)


def test_linked_issue_fetch_is_capped():
    # An attacker PR body with 50 "Closes #N" must not drive 50 API calls.
    from verel.integrations.github import _MAX_LINKED_ISSUES
    body = " ".join(f"Closes #{i}" for i in range(1, 51))
    pr = {"title": "x", "body": body}
    calls = []

    def fake_fetch(path, *, accept="application/vnd.github+json"):
        calls.append(path)
        if "/pulls/" in path and "diff" in accept:
            return b"diff --git a/x.py b/x.py\n+++ b/x.py\n"
        if "/pulls/" in path:
            return json.dumps(pr).encode()
        return json.dumps({"body": "ac"}).encode()  # issue

    fetch_pr_context("o/r", 1, fetch=fake_fetch)
    issue_calls = [c for c in calls if "/issues/" in c]
    assert len(issue_calls) == _MAX_LINKED_ISSUES  # capped, not 50
