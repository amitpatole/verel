"""Business-rule / invariant grader (Verified Review, grader C) — "business rules get ignored".

Declared invariants — *"an order total always includes tax", "a refund never exceeds the charge"* —
compiled to executable property checks and run against the repo; a falsified invariant gates. Unlike
the spec grader (B), the rules are **human-declared** (a `verel_invariants.yaml`/`.txt` in the repo,
or passed in), not extracted from a possibly-hostile ticket — so the injection surface is smaller.
Everything else reuses B's hardened pipeline: the LLM compiles N independent checks per invariant,
they run under the SAME bwrap OS-isolation + fail-closed (`verel.ci.spec.run_check`), a **majority
vote** decides (one wrong generated check can't false-fail a merge), and a signed receipt is emitted.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Sequence
from dataclasses import dataclass

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
from .spec import Criterion, SpecChatFn, generate_checks, public_api, run_check, tally

_INVARIANT_FILES = ("verel_invariants.yaml", "verel_invariants.yml", "verel_invariants.txt")


@dataclass
class Invariant:
    id: str
    statement: str


def load_invariants(repo: str) -> list[Invariant]:
    """Read declared invariants from `verel_invariants.{yaml,yml,txt}` in `repo`. One per non-empty,
    non-`#` line (a leading `id: ` is optional). Returns [] if no file is present."""
    for name in _INVARIANT_FILES:
        path = os.path.join(repo, name)
        if not os.path.isfile(path):
            continue
        out: list[Invariant] = []
        with open(path, encoding="utf-8") as fh:
            for i, raw in enumerate(fh):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                rid, sep, rest = line.partition(":")
                statement = rest.strip() if sep and rid.strip().isidentifier() else line
                out.append(Invariant(id=(rid.strip() if sep and rest.strip() else f"inv{i + 1}"),
                                     statement=statement))
        return out
    return []


def grade_invariants(repo: str, invariants: Sequence[Invariant | str], changed_files: list[str], *,
                     chat: SpecChatFn, n: int = 2, timeout: int = 30,
                     runner_identity: str = "invariant-grader", isolation: str = "container") -> Report:
    """Grade the repo against declared invariants. Returns a signed `CONTRACT` Report: a grounded
    ERROR per falsified invariant (gates), an advisory WARNING per one that couldn't be grounded."""
    invs = [Invariant(f"inv{i + 1}", s) if isinstance(s, str) else s
            for i, s in enumerate(invariants)]
    api_summary = public_api(repo, changed_files)
    allowed = {f[:-3].replace("/", ".").split(".")[0] for f in changed_files if f.endswith(".py")}
    issues: list[Issue] = []
    violated = unverified = 0
    for inv in invs:
        checks = generate_checks(Criterion(inv.id, inv.statement), api_summary, chat=chat, n=n)
        outcomes = [run_check(repo, c, timeout=timeout, allowed_modules=allowed, isolation=isolation)
                    for c in checks]
        verdict = tally(outcomes)
        if verdict == "violated":
            violated += 1
            issues.append(Issue(
                kind=IssueKind.OTHER, severity=Severity.ERROR, source=GraderKind.CONTRACT,
                message=f"business rule violated: {inv.statement}",
                locator=f"invariant:{inv.id}", detail_json=json.dumps({"checks": outcomes})))
        elif verdict == "unverified":
            unverified += 1
            from ..verdict.models import Confidence
            issues.append(Issue(
                kind=IssueKind.OTHER, severity=Severity.WARNING, confidence=Confidence.LOW,
                source=GraderKind.LLM_JUDGE, locator=f"invariant:{inv.id}",
                message=f"invariant unverified (could not ground a runnable check): {inv.statement}"))
    report = Report(
        verdict=Verdict.FAIL if violated else (Verdict.WARN if issues else Verdict.PASS),
        summary=f"invariants: {violated} violated, {unverified} unverified, of {len(invs)} declared",
        issues=issues, grader=GraderKind.CONTRACT)
    report = assign(report)
    suite = hashlib.blake2s(("\x1f".join(i.statement for i in invs)).encode()).hexdigest()[:16]
    inputs = hashlib.blake2s("\x1f".join(sorted(changed_files)).encode()).hexdigest()[:16]
    rr = RunReceipt(
        suite_sha=suite, inputs_digest=inputs,
        coverage_assertion=f"scanned files: {','.join(changed_files) or 'invariants'}",
        runner_identity=runner_identity, result_digest=report_result_digest(report), signature="")
    rr.signature = sign_receipt(rr)
    report.run_receipt = rr
    return report
