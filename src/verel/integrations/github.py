"""Pull a PR's context from GitHub — the "ticket" + diff that feed the spec/intent grader (R2).

The spec grader (B) needs two things: the **acceptance criteria** (the human-written intent — the PR
body and any linked issue) and the **changed files** (what to check against). Both already live in the
team's GitHub; this reads them rather than inventing a new `SPEC.md`. The network call is injectable
(`fetch`) so orchestration is offline-testable; the parsing helpers are pure.

Auth rides an operator-supplied token (`VEREL_GITHUB_TOKEN`); the HTTP uses the hardened transport
opener (ignores ambient proxy env, secure redirects). GitHub Enterprise via `api=`.
"""

from __future__ import annotations

import json
import re
import urllib.request

from ..transport import build_opener, make_client_context

# "Closes #123", "fixes owner/repo#45", etc. — the linked-issue references in a PR body.
_LINKED = re.compile(r"\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s+#(\d+)\b", re.IGNORECASE)
_DIFF_FILE = re.compile(r"^\+\+\+ b/(.+)$", re.MULTILINE)
_REPO_RE = re.compile(r"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")  # owner/repo — no path/URL injection
_MAX_LINKED_ISSUES = 10  # cap fetches so an attacker-crafted PR body can't drive unbounded API calls


def linked_issue_numbers(pr_body: str) -> list[int]:
    """Issue numbers a PR body closes (so their text counts as acceptance criteria too)."""
    seen: list[int] = []
    for m in _LINKED.finditer(pr_body or ""):
        n = int(m.group(1))
        if n not in seen:
            seen.append(n)
    return seen


def changed_files(diff: str, *, suffix: str = ".py") -> list[str]:
    """The files a unified diff touches (the grader's targets). Filtered by `suffix`; `/dev/null`
    (deletions) dropped. Order-preserving, de-duplicated."""
    out: list[str] = []
    for m in _DIFF_FILE.finditer(diff or ""):
        path = m.group(1).strip()
        if path != "/dev/null" and path.endswith(suffix) and path not in out:
            out.append(path)
    return out


def acceptance_text(pr_title: str, pr_body: str, issue_bodies: list[str]) -> str:
    """Assemble the human-written intent the grader reasons over: the PR title/body + each linked
    issue's body. This is the 'ticket' — never the agent's diff, so the agent can't write the spec
    to match its own bug."""
    parts = [f"# {pr_title}".strip(), (pr_body or "").strip()]
    parts += [b.strip() for b in issue_bodies if b and b.strip()]
    return "\n\n".join(p for p in parts if p)


def _default_fetch(api: str, token: str | None, cafile: str | None):
    """Build a GET fetch(path, *, accept) -> bytes over the hardened transport opener."""
    opener = build_opener(make_client_context(cafile, None))
    base = api.rstrip("/")

    def fetch(path: str, *, accept: str = "application/vnd.github+json") -> bytes:
        req = urllib.request.Request(base + path, headers={
            "Accept": accept, "User-Agent": "verel",
            **({"Authorization": f"Bearer {token}"} if token else {})})
        with opener.open(req, timeout=20) as r:  # nosec B310 — api is an operator-supplied http(s) base
            return r.read()

    return fetch


def fetch_pr_context(repo_full_name: str, number: int, *, token: str | None = None,
                     api: str = "https://api.github.com", cafile: str | None = None,
                     fetch=None) -> dict:
    """Fetch `{title, body, diff, criteria, changed_files}` for a PR. `fetch(path, *, accept)` is
    injectable for testing; by default it GETs GitHub over the transport opener."""
    if not api.lower().startswith(("https://", "http://")):
        raise ValueError(f"api must be http(s), got {api!r}")
    if not _REPO_RE.match(repo_full_name):
        raise ValueError(f"invalid repo {repo_full_name!r} — expected owner/repo")
    if not isinstance(number, int) or number <= 0:
        raise ValueError("number must be a positive int")  # never interpolate untrusted text into the path
    fetch = fetch or _default_fetch(api, token, cafile)
    pr = json.loads(fetch(f"/repos/{repo_full_name}/pulls/{number}"))
    diff = fetch(f"/repos/{repo_full_name}/pulls/{number}",
                 accept="application/vnd.github.v3.diff").decode("utf-8", "replace")
    issue_bodies = []
    for n in linked_issue_numbers(pr.get("body") or "")[:_MAX_LINKED_ISSUES]:
        try:
            issue = json.loads(fetch(f"/repos/{repo_full_name}/issues/{n}"))
            issue_bodies.append(issue.get("body") or "")
        except Exception:  # a missing/forbidden linked issue must not sink the whole fetch
            continue
    return {
        "title": pr.get("title") or "",
        "body": pr.get("body") or "",
        "diff": diff,
        "criteria": acceptance_text(pr.get("title") or "", pr.get("body") or "", issue_bodies),
        "changed_files": changed_files(diff),
    }
