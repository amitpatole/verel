"""Promotion-on-eval gate (§5.7, §7.7, §11.1 item 4) — the wedge that compounds.

A consolidated DesignRule (`grounding: inferred`, `trust: candidate`) earns promotion to
`verified` ONLY by passing a graded eval against a **held-out, agent-inaccessible** corpus,
WITH a valid signed `run_receipt` (attestation), AND with no leakage-canary contamination.

Faithful invariants from the design:
- **Eval cases are human-owned and agent-INACCESSIBLE.** Agents get a *verdict*, never the
  rubric or the held-out cases. `HeldOutCorpus` is deliberately NOT a `MemoryView` and is
  never returned by `recall()`.
- **An LLM never solely gates a consequential, compounding action.** The grader here is
  DETERMINISTIC (precision/recall of the rule's induced matcher over labeled cases).
- **Leakage canary:** a planted token that must never appear in agent-accessible memory. If
  it does, the corpus is considered compromised and promotion FAILS (not silently passes).
- **Demote on regression** is handled by the failure ledger (§7.5); promotion only ratifies.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

from ..verdict.gate import gate, sign_receipt
from ..verdict.models import GraderKind, Report, RunReceipt, Verdict
from .view import MemoryRecord, MemoryView

PROMOTE_F1 = 0.8  # held-out F1 threshold to promote candidate -> verified


@dataclass
class EvalCase:
    text: str
    covers_kind: str
    label: str  # "prevent" (rule SHOULD apply) | "allow" (rule should NOT apply)
    canary: bool = False


@dataclass
class HeldOutCorpus:
    """Signed, human-owned, agent-inaccessible eval set. NOT a MemoryView."""

    cases: list[EvalCase] = field(default_factory=list)
    canary_token: str = "VEREL-CANARY-DO-NOT-STORE"

    def sha(self) -> str:
        blob = json.dumps([(c.text, c.covers_kind, c.label, c.canary) for c in self.cases],
                          sort_keys=True)
        return hashlib.blake2s(blob.encode()).hexdigest()[:16]


def _subtokens(keywords: list[str]) -> set[str]:
    """Split hyphenated compounds the LLM emits ("max-width"->{max,width}) and keep meaty
    parts, so the matcher isn't defeated by surface formatting."""
    out: set[str] = set()
    for k in keywords:
        for part in k.lower().split("-"):
            if len(part) > 3:
                out.add(part)
    return out


def _rule_applies(rule: MemoryRecord, case: EvalCase) -> bool:
    """The induced rule's deterministic matcher: same kind AND a stem of >=1 induced keyword
    appears in the case (prefix match, so "overflow" matches "overflows")."""
    if rule.detail.get("covers_kind") != case.covers_kind:
        return False
    kws = _subtokens(rule.detail.get("keywords", []))
    words = re.findall(r"[a-z0-9]+", case.text.lower())
    return any(
        (w.startswith(kw) or kw.startswith(w)) and min(len(w), len(kw)) > 3
        for kw in kws
        for w in words
    )


@dataclass
class PromotionResult:
    promoted: bool
    f1: float
    verdict: Verdict
    reason: str
    report: Report


def evaluate_rule(rule: MemoryRecord, corpus: HeldOutCorpus) -> tuple[float, dict]:
    """Deterministic precision/recall/F1 of the rule's matcher over the held-out cases."""
    tp = fp = fn = 0
    graded = [c for c in corpus.cases if not c.canary]
    for c in graded:
        applies = _rule_applies(rule, c)
        should = c.label == "prevent"
        if applies and should:
            tp += 1
        elif applies and not should:
            fp += 1
        elif not applies and should:
            fn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return f1, {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "n": len(graded)}


def _leaked(mem: MemoryView, canary_token: str) -> bool:
    return any(canary_token in r.text or canary_token in json.dumps(r.detail)
              for r in mem.all())


class PromotionGate:
    """Ratifies candidate rules into `verified` through the verdict bus, attested + held-out."""

    def __init__(self, mem: MemoryView, corpus: HeldOutCorpus,
                 runner_identity: str = "promotion-runner",
                 f1_threshold: float = PROMOTE_F1):
        self.mem = mem
        self.corpus = corpus
        self.runner_identity = runner_identity
        self.f1_threshold = f1_threshold

    def _receipt(self, rule_id: str) -> RunReceipt:
        rr = RunReceipt(
            suite_sha=self.corpus.sha(),
            inputs_digest=hashlib.blake2s(rule_id.encode()).hexdigest()[:16],
            coverage_assertion=f"scanned files: rule:{rule_id}",
            runner_identity=self.runner_identity,
            signature="",
        )
        rr.signature = sign_receipt(rr)  # separate-trust-domain runner signs
        return rr

    def consider(self, rule: MemoryRecord) -> PromotionResult:
        # 0) leakage canary — a compromised corpus must FAIL, not silently pass.
        if _leaked(self.mem, self.corpus.canary_token):
            rep = Report(verdict=Verdict.FAIL, summary="leakage canary found in agent memory",
                         grader=GraderKind.CONTRACT)
            return PromotionResult(False, 0.0, Verdict.FAIL, "leakage canary contamination", rep)

        f1, stats = evaluate_rule(rule, self.corpus)
        passed = f1 >= self.f1_threshold
        report = Report(
            verdict=Verdict.PASS if passed else Verdict.FAIL,
            summary=f"held-out eval F1={f1:.2f} (>= {self.f1_threshold} to promote); {stats}",
            grader=GraderKind.CONTRACT,
            run_receipt=self._receipt(rule.id),
        ).model_copy(update={"errored": False})

        # Gate through the verdict bus WITH attestation (hollow-gate guard applies).
        gr = gate([report], required={GraderKind.CONTRACT},
                  frozen_suites={GraderKind.CONTRACT: self.corpus.sha()},
                  diff_files={f"rule:{rule.id}"})

        if gr.verdict == Verdict.PASS and passed:
            updated = self.mem.promote(rule.id)
            if updated is not None:
                updated.with_detail(grounding="verified", promotion_f1=round(f1, 3))
                self.mem.write(updated)
            return PromotionResult(True, f1, Verdict.PASS, "passed held-out attested eval", report)
        return PromotionResult(False, f1, gr.verdict,
                               gr.reason or f"F1 {f1:.2f} < {self.f1_threshold}", report)
