"""Spec / intent conformance grader (Verified Review, grader B) — "the ticket says A, the code does B".

The naive move ("ask an LLM if the code matches the ticket") is just another unreliable opinion. This
keeps Verel's invariant — **the LLM proposes, execution verifies, only an executed check gates**:

1. **Extract** checkable acceptance criteria from the TICKET (the human-written PR/issue text — never
   the agent's diff, so the agent can't write the spec to match its own bug).
2. **Compile** each criterion to N independent `pytest` checks that assert it against the repo's API.
3. **Execute** each check in a sandboxed subprocess (no network, wall-clock timeout, rlimits).
4. **Majority-vote** per criterion over the *conclusive* checks: a strict majority FAIL → the criterion
   is **violated** → a grounded `INTENT_MISMATCH` ERROR that GATES (a single wrong generated test can't
   false-fail a merge). All checks errored/unrunnable → **unverified** → an advisory WARNING (we never
   claim to verify what we couldn't execute).

The model only ever proposes checks; a hallucinated judge can neither block a good merge (a wrong
check is outvoted / inconclusive → advisory) nor pass a broken one (it can't make a failing executed
test pass). The grader signs a `RunReceipt` over the frozen generated suite, like the CONTRACT grader.
"""

from __future__ import annotations

import ast
import functools as _functools
import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field

from ..verdict.fingerprint import assign
from ..verdict.gate import sign_receipt
from ..verdict.models import (
    GraderKind,
    Issue,
    IssueKind,
    Report,
    RunReceipt,
    Severity,
    Verdict,
    report_result_digest,
)

# A chat function returns the model's text for a list of messages (injectable for tests; the real one
# is `lambda msgs: verel.agents.llm.chat(msgs).content`).
SpecChatFn = Callable[[list[dict]], str]


@dataclass
class Criterion:
    id: str
    statement: str
    kind: str = "behavioral"  # only "behavioral" criteria are grounded into tests; others → advisory


@dataclass
class CriterionResult:
    criterion: Criterion
    verdict: str  # "satisfied" | "violated" | "unverified"
    checks: list[str] = field(default_factory=list)  # per-check outcomes: pass|fail|error


def _json_block(text: str):
    """Pull the first JSON array/object out of an LLM reply (tolerating ``` fences and prose)."""
    text = re.sub(r"^```[a-z]*\n?|\n?```$", "", text.strip(), flags=re.MULTILINE)
    for opn, cls in (("[", "]"), ("{", "}")):
        i, j = text.find(opn), text.rfind(cls)
        if i != -1 and j > i:
            try:
                return json.loads(text[i:j + 1])
            except json.JSONDecodeError:
                continue
    return None


def public_api(repo: str, files: list[str]) -> str:
    """A compact 'module: name, name' summary of the changed files' top-level defs/classes, so the
    generator knows what to import and assert against. Pure `ast` — never imports the code."""
    lines = []
    for rel in files:
        path = os.path.join(repo, rel)
        try:
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
        except (OSError, SyntaxError):
            continue
        names = [n.name for n in tree.body if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef
                                                         | ast.ClassDef)]
        mod = rel[:-3].replace("/", ".") if rel.endswith(".py") else rel
        if names:
            lines.append(f"{mod}: {', '.join(names)}")
    return "\n".join(lines)


def extract_criteria(criteria_text: str, *, chat: SpecChatFn) -> list[Criterion]:
    """LLM → a list of checkable acceptance criteria. Non-JSON / empty replies yield []."""
    if not criteria_text.strip():
        return []
    msgs = [
        {"role": "system", "content":
         "Extract the CHECKABLE acceptance criteria from a ticket. Return ONLY a JSON array of "
         '{"id","statement","kind"} where kind is "behavioral" (verifiable by running code) or '
         '"other". Keep statements concrete and testable. No prose.'},
        {"role": "user", "content": criteria_text},
    ]
    data = _json_block(chat(msgs)) or []
    out = []
    for i, c in enumerate(data if isinstance(data, list) else []):
        if isinstance(c, dict) and c.get("statement"):
            out.append(Criterion(id=str(c.get("id") or f"c{i + 1}"),
                                  statement=str(c["statement"]), kind=str(c.get("kind") or "behavioral")))
    return out


def generate_checks(criterion: Criterion, api_summary: str, *, chat: SpecChatFn, n: int = 2) -> list[str]:
    """LLM → up to `n` independent pytest test sources asserting `criterion` against the repo API."""
    checks: list[str] = []
    for k in range(n):
        msgs = [
            {"role": "system", "content":
             "Write ONE self-contained pytest test that asserts the given acceptance criterion against "
             "the repository's public API. Import only from the listed modules. Output ONLY Python "
             "code (no prose, no fences). The test must FAIL if the criterion is not met. Vary the "
             f"approach (attempt {k + 1})."},
            {"role": "user", "content":
             f"Acceptance criterion: {criterion.statement}\n\nAvailable modules:\n{api_summary}"},
        ]
        code = re.sub(r"^```[a-z]*\n?|\n?```$", "", chat(msgs).strip(), flags=re.MULTILINE)
        if "def test" in code:
            checks.append(code)
    return checks


def _rlimit_preexec(cpu_s: int, mem_bytes: int, *, nproc: int | None = 96):
    """A preexec_fn that caps the child's CPU, address space, file size, and (optionally) fork count
    before exec — so an injection-crafted test can't exhaust memory/CPU or write large files.
    `nproc=None` skips RLIMIT_NPROC (used on the bwrap launcher, where a system-wide per-UID process
    cap could block bwrap's own setup — there, seccomp's deny-clone handles fork-bombs instead).
    Best-effort (POSIX only); the wall-clock timeout is the always-on backstop."""
    def _apply():  # pragma: no cover - runs in the forked child
        import resource
        limits = [(resource.RLIMIT_CPU, cpu_s), (resource.RLIMIT_AS, mem_bytes),
                  (resource.RLIMIT_FSIZE, 16 * 1024 * 1024)]
        if nproc is not None:
            limits.append((resource.RLIMIT_NPROC, nproc))
        for res, soft in limits:
            try:
                resource.setrlimit(res, (soft, soft))
            except (ValueError, OSError):
                pass
    return _apply


# A generated spec-check only ever needs to import the repo's own modules + assert with the stdlib.
# Everything an injection would need (os/subprocess/socket/shutil/urllib/…) is OUT. This is the
# load-bearing defense: ticket-injected exfil/destruction code is REFUSED before it ever executes.
_STDLIB_OK = {"pytest", "math", "decimal", "fractions", "json", "re", "datetime", "statistics",
              "itertools", "functools", "collections", "string", "typing", "dataclasses", "enum"}
_FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__", "open", "globals", "vars", "locals",
                    "input", "breakpoint", "memoryview", "getattr", "setattr", "delattr", "hasattr"}
_FORBIDDEN_NAMES = {"__builtins__", "__loader__", "__spec__"}  # recovery handles for open/import


def is_safe_check(test_source: str, allowed_modules: set[str]) -> bool:
    """True iff the generated test only imports the repo's modules + a stdlib assertion whitelist and
    calls no code-exec/file/process builtins. Unparseable or anything outside the allowlist → False
    (refused, never executed). This contains prompt-injection: the model can't smuggle `import os`."""
    try:
        tree = ast.parse(test_source)
    except SyntaxError:
        return False
    allowed = allowed_modules | _STDLIB_OK
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(a.name.split(".")[0] not in allowed for a in node.names):
                return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in _FORBIDDEN_CALLS:
                return False
        elif isinstance(node, ast.Name) and node.id in _FORBIDDEN_NAMES:
            return False  # no __builtins__/__loader__ recovery handles (defense-in-depth)
        elif isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            return False  # no dunder attribute access (getattr/__globals__/__builtins__ escapes)
    return True


class SpecIsolationError(RuntimeError):
    """Raised when generated checks must run but no OS-isolation (bwrap) is available."""


@_functools.lru_cache(maxsize=1)
def _memory_scope_prefix() -> tuple[str, ...]:
    """A `systemd-run --user --scope -p MemoryMax=…` prefix that bounds the jail's TOTAL memory at the
    kernel (cgroup v2) — incl. the RAM-backed /tmp tmpfs that RLIMIT_AS can't cap. Empty tuple when
    systemd-run / a user memory cgroup isn't available (then RLIMIT_AS + the hardened static filter +
    the wall-clock timeout are the bounds, and a tmpfs-fill is a documented residual)."""
    import shutil
    if not shutil.which("systemd-run"):
        return ()
    try:
        probe = subprocess.run(  # nosec B603/B607 — fixed argv, probing our own user scope
            ["systemd-run", "--user", "--scope", "-q", "-p", "MemoryMax=64M", "--", "true"],
            capture_output=True, timeout=10)
        if probe.returncode == 0:
            return ("systemd-run", "--user", "--scope", "-q", "-p", "MemoryMax=1G", "-p",
                    "TasksMax=128", "--")
    except (OSError, subprocess.SubprocessError):
        pass
    return ()


def _already_memory_bounded() -> bool:
    """True if THIS process already runs in a cgroup-v2 with a finite `memory.max` (e.g. a k8s pod or
    a `docker --memory` container) — then the bwrap payload inherits that bound and the RAM /tmp can't
    exhaust the host even without a fresh systemd scope."""
    try:
        with open("/proc/self/cgroup", encoding="utf-8") as f:
            rel = f.read().strip().rsplit("::", 1)[-1].lstrip("/")
        with open(os.path.join("/sys/fs/cgroup", rel, "memory.max"), encoding="utf-8") as f:
            return f.read().strip() != "max"
    except (OSError, IndexError):
        return False


def _classify(returncode: int) -> str:
    return {0: "pass", 1: "fail"}.get(returncode, "error")  # 0=pass, 1=failed, else=collection/usage


def _run_in_container(repo: str, test_file_dir: str, test_file: str, *, timeout: int) -> str:
    """Run the generated pytest test inside the toolsmith bwrap sandbox — the SECURITY BOUNDARY for
    ticket-injected code. Layers: `--unshare-all` (NO NETWORK), read-only fs binds (nothing on the
    host is writable), ephemeral /tmp tmpfs, an unprivileged user namespace (CapEff=0, NoNewPrivs),
    a **seccomp-bpf denylist** (deny clone/fork/socket/ptrace/mount…) when libseccomp is present, AND
    **rlimits** (address space / CPU / file size) so a pure-stdlib memory/CPU bomb can't exhaust the
    HOST. A getattr→os.system RCE runs here harmlessly; a `[0]*(10**12)` hits RLIMIT_AS → MemoryError."""
    import sys
    import sysconfig
    import tempfile as _tf

    from ..toolsmith.container import _bwrap_cmd
    from ..toolsmith.seccomp import PROFILE_DENYLIST, build_bpf, seccomp_available

    repo_r = os.path.realpath(repo)
    # Invoke the fully-resolved real interpreter (a venv symlink may chain through uv paths that
    # aren't bound). pytest lives in the venv site-packages → put it on PYTHONPATH with the repo.
    py = os.path.realpath(sys.executable)
    purelib = sysconfig.get_path("purelib")
    binds = {repo_r, os.path.realpath(test_file_dir), os.path.realpath(sys.prefix),
             os.path.realpath(sys.base_prefix), os.path.realpath(purelib), os.path.dirname(py)}
    # A kernel memory cgroup bounds the jail's TOTAL RAM — the one thing rlimits miss (the --tmpfs
    # /tmp page cache). Prefer a fresh systemd user scope; else rely on an inherited container/pod
    # memory limit. FAIL CLOSED if neither exists rather than run an unbounded RAM jail for untrusted
    # ticket-derived code (a tmpfs-fill could OOM the host). The static filter is only defense-in-depth.
    scope = _memory_scope_prefix()
    if not scope and not _already_memory_bounded():
        return "error"  # no memory bound available → refuse to execute (criterion stays advisory)
    cmd = list(scope) + _bwrap_cmd()
    for src in binds:
        cmd += ["--ro-bind", src, src]         # read-only views only — nothing is writable on the host

    sec_file = None
    pass_fds: tuple[int, ...] = ()
    if seccomp_available():                     # syscall denylist (fork/socket/ptrace/mount/…)
        sec_file = _tf.TemporaryFile()  # noqa: SIM115 — fd must outlive the subprocess; closed in finally
        build_bpf(sec_file, profile=PROFILE_DENYLIST, allow=None)
        sec_file.flush()
        sec_file.seek(0)
        cmd += ["--seccomp", str(sec_file.fileno())]
        pass_fds = (sec_file.fileno(),)

    cmd += ["--setenv", "PYTHONPATH", f"{repo_r}:{purelib}", "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
            "--chdir", repo_r, py, "-B", "-m", "pytest", test_file, "-q", "-p", "no:cacheprovider"]
    # rlimits on the bwrap launcher are inherited by the jailed payload (caps host memory/CPU). NPROC
    # is left to seccomp's deny-clone — a per-UID NPROC cap on the launcher could block bwrap's setup.
    preexec = _rlimit_preexec(cpu_s=max(2, timeout), mem_bytes=768 * 1024 * 1024, nproc=None) \
        if os.name == "posix" else None
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,  # nosec B603 — argv, no shell, bwrap+seccomp+rlimit jailed
                           preexec_fn=preexec, start_new_session=True, pass_fds=pass_fds)
    except subprocess.TimeoutExpired:
        return "error"
    finally:
        if sec_file is not None:
            sec_file.close()
    return _classify(r.returncode)


def run_check(repo: str, test_source: str, *, timeout: int = 30, allowed_modules: set[str] | None = None,
              isolation: str = "container") -> str:
    """Execute one LLM-generated pytest test against `repo`. Returns pass|fail|error.

    The generated test is UNTRUSTED (steered by a possibly-hostile ticket), so by default it runs ONLY
    inside real OS isolation (`isolation="container"`: bwrap no-net + read-only fs + seccomp). When
    bwrap is unavailable it **fails closed** — `error` (the check is NOT run, the criterion stays
    unverified → advisory). Static analysis (`is_safe_check`) is a cheap defense-in-depth pre-filter,
    NEVER the boundary (a blocklist can't sandbox a Turing-complete language). `isolation="subprocess"`
    is an explicit, documented opt-out for a TRUSTED-LOCAL repo+ticket only (rlimit subprocess, no
    network isolation) — never use it on external-contributor PR text."""
    if not is_safe_check(test_source, allowed_modules or set()):
        return "error"  # cheap pre-filter only — the container below is the actual boundary
    with tempfile.TemporaryDirectory(prefix="verel-spec-") as d:
        tf = os.path.join(d, "test_verel_spec_check.py")
        with open(tf, "w", encoding="utf-8") as fh:
            fh.write(test_source)
        from ..toolsmith.container import bwrap_available
        if bwrap_available():
            return _run_in_container(repo, d, tf, timeout=timeout)
        if isolation == "container":
            return "error"  # FAIL CLOSED — never execute untrusted generated code without isolation
        # isolation="subprocess": TRUSTED-LOCAL opt-out only. Minimal env + rlimits, NO net isolation.
        env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": os.path.realpath(repo),
               "PYTHONDONTWRITEBYTECODE": "1", "HOME": d, "TMPDIR": d}
        preexec = _rlimit_preexec(cpu_s=max(2, timeout), mem_bytes=768 * 1024 * 1024) \
            if os.name == "posix" else None
        try:
            r = subprocess.run(  # nosec B603 — fixed argv, no shell; trusted-local opt-out tier only
                ["python", "-B", "-m", "pytest", tf, "-q", "-p", "no:cacheprovider"],
                cwd=repo, capture_output=True, text=True, timeout=timeout, env=env,
                preexec_fn=preexec, start_new_session=True)
        except subprocess.TimeoutExpired:
            return "error"
        return _classify(r.returncode)


def tally(check_results: list[str]) -> str:
    """Majority vote over conclusive checks. Strict majority of fails → 'violated'; else if any
    conclusive → 'satisfied'; all errored/none → 'unverified'. Conservative: a tie does NOT gate."""
    fails = check_results.count("fail")
    passes = check_results.count("pass")
    if fails == 0 and passes == 0:
        return "unverified"
    return "violated" if fails > passes else "satisfied"


def grade_spec(repo: str, criteria_text: str, changed_files: list[str], *, chat: SpecChatFn,
               n: int = 2, timeout: int = 30, runner_identity: str = "spec-grader",
               isolation: str = "container") -> Report:
    """Grade the diff against the ticket's intent. Returns a signed `CONTRACT` Report: a grounded
    `INTENT_MISMATCH` ERROR per violated criterion (gates), an advisory WARNING per unverified one.

    `isolation="container"` (default) runs each generated check under bwrap OS-isolation and FAILS
    CLOSED (the criterion stays unverified/advisory) when bwrap is absent — never executing untrusted
    ticket-derived code in-process. Use `isolation="subprocess"` ONLY for a trusted-local repo+ticket."""
    criteria = extract_criteria(criteria_text, chat=chat)
    api_summary = public_api(repo, changed_files)
    # The modules a generated check may import: the changed files' module names (so it can assert the
    # repo's own API). Anything else is refused by is_safe_check before execution.
    allowed = {f[:-3].replace("/", ".").split(".")[0] for f in changed_files if f.endswith(".py")}
    issues: list[Issue] = []
    results: list[CriterionResult] = []
    for crit in criteria:
        if crit.kind != "behavioral":
            results.append(CriterionResult(crit, "unverified", []))
            issues.append(_advisory(crit, "non-behavioral criterion — not auto-verifiable"))
            continue
        checks = generate_checks(crit, api_summary, chat=chat, n=n)
        outcomes = [run_check(repo, c, timeout=timeout, allowed_modules=allowed, isolation=isolation)
                    for c in checks]
        verdict = tally(outcomes)
        results.append(CriterionResult(crit, verdict, outcomes))
        if verdict == "violated":
            issues.append(Issue(
                kind=IssueKind.INTENT_MISMATCH, severity=Severity.ERROR, source=GraderKind.CONTRACT,
                message=f"the code does not satisfy the ticket: {crit.statement}",
                locator=f"criterion:{crit.id}", detail_json=json.dumps({"checks": outcomes})))
        elif verdict == "unverified":
            issues.append(_advisory(crit, "could not ground this criterion into a runnable check"))
    # Honesty / anti-suppression: a NON-empty ticket that yields ZERO criteria must NOT read as a
    # confident PASS — a hostile PR body could prompt-inject the extractor into emitting none. Absence
    # of verification is WARN (advisory), never assurance.
    if not criteria and criteria_text.strip():
        from ..verdict.models import Confidence
        issues.append(Issue(
            kind=IssueKind.INTENT_MISMATCH, severity=Severity.WARNING, confidence=Confidence.LOW,
            source=GraderKind.LLM_JUDGE, locator="criteria",
            message="no checkable acceptance criteria were extracted from the ticket — intent NOT "
                    "verified (a non-empty ticket should usually yield at least one)"))
    report = Report(
        verdict=Verdict.FAIL if any(i.severity == Severity.ERROR for i in issues) else (
            Verdict.WARN if issues else Verdict.PASS),
        summary=f"spec conformance: {sum(r.verdict=='violated' for r in results)} violated, "
                f"{sum(r.verdict=='unverified' for r in results)} unverified, of {len(criteria)} criteria",
        issues=issues, grader=GraderKind.CONTRACT)
    report = assign(report)
    report.run_receipt = _receipt(repo, criteria_text, changed_files, report, runner_identity)
    return report


def default_chat(**kw) -> SpecChatFn:
    """The real LLM chat as a `SpecChatFn` (returns the model's text). Lazy-imports the provider so
    the grader's pure helpers stay importable without an LLM configured."""
    from ..agents.llm import chat as _chat
    return lambda msgs: _chat(msgs, **kw).content


def grade_pr(repo: str, repo_full_name: str, number: int, *, token: str | None = None,
             api: str = "https://api.github.com", chat: SpecChatFn | None = None, n: int = 2) -> Report:
    """R2→B: fetch a PR's acceptance criteria + changed files from GitHub, then grade the repo against
    that intent. The 'ticket' comes from the team's GitHub, not a new format."""
    from ..integrations.github import fetch_pr_context
    ctx = fetch_pr_context(repo_full_name, number, token=token, api=api)
    return grade_spec(repo, ctx["criteria"], ctx["changed_files"], chat=chat or default_chat(), n=n)


def _advisory(crit: Criterion, why: str) -> Issue:
    # Advisory = ceiling-clamped to WARNING (Confidence.LOW), so an unverifiable criterion informs but
    # never gates — we never let "couldn't verify" render as a pass, but we also never block on a guess.
    from ..verdict.models import Confidence
    return Issue(kind=IssueKind.INTENT_MISMATCH, severity=Severity.WARNING, confidence=Confidence.LOW,
                 source=GraderKind.LLM_JUDGE, message=f"intent unverified: {crit.statement} ({why})",
                 locator=f"criterion:{crit.id}")


def _receipt(repo: str, criteria_text: str, files: list[str], report: Report,
             runner_identity: str) -> RunReceipt:
    suite = hashlib.blake2s((criteria_text + "\x1f".join(sorted(files))).encode()).hexdigest()[:16]
    rr = RunReceipt(
        suite_sha=suite,
        inputs_digest=hashlib.blake2s("\x1f".join(sorted(files)).encode()).hexdigest()[:16],
        coverage_assertion=f"scanned files: {','.join(files) or 'spec'}",
        runner_identity=runner_identity, result_digest=report_result_digest(report), signature="")
    rr.signature = sign_receipt(rr)
    return rr
