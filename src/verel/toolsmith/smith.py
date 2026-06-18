"""Tool-smith — agent-built tooling lifecycle (§7.6): detect → scaffold → test → register → reuse.

A capability request is first checked against the registry (reuse beats rebuild). If missing,
an LLM scaffolds a self-contained function; it is tested against a held-out case set; and it
is admitted to procedural memory ONLY on a passing, attested eval — verified-and-auto for
read-only/idempotent tools, human-review-gated for destructive ones. No tool enters red.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Callable

from pydantic import BaseModel, Field

from ..agents import llm
from ..memory.view import Trust
from ..verdict.gate import gate, sign_receipt
from ..verdict.models import GraderKind, Report, RunReceipt, Verdict
from .registry import AUTO_PROMOTABLE, SideEffect, ToolRecord, ToolRegistry, load_callable

_FENCE = re.compile(r"```(?:[a-zA-Z0-9_+-]*)?\n(.*?)```", re.DOTALL)
PASS_THRESHOLD = 1.0  # tools must pass ALL held-out cases — no tool enters red

ChatFn = Callable[[list[dict]], str]


class ToolCase(BaseModel):
    args: list = Field(default_factory=list)
    kwargs: dict = Field(default_factory=dict)
    expected: object = None


class ToolSpec(BaseModel):
    name: str  # must be a valid python identifier; the function is named this
    capability: str  # natural-language description (semantic reuse key)
    signature_hint: str = ""  # e.g. "slugify(text: str) -> str"
    side_effect: SideEffect = SideEffect.READ_ONLY
    cases: list[ToolCase] = Field(default_factory=list)  # held-out eval cases

    def suite_sha(self) -> str:
        blob = json.dumps([(c.args, c.kwargs, c.expected) for c in self.cases], sort_keys=True, default=str)
        return hashlib.blake2s(blob.encode()).hexdigest()[:16]


@dataclass
class BuildResult:
    tool: ToolRecord | None
    reused: bool
    passed: bool
    score: float
    trust: Trust | None
    registered: bool
    reason: str = ""


_SYSTEM = (
    "You write ONE small, self-contained, dependency-free Python function. No imports unless "
    "from the stdlib `re`/`math`/`string`. The function name MUST match exactly. No I/O, no "
    "network, no file access, no globals. Return ONLY a fenced python code block."
)


def _default_chat(messages: list[dict]) -> str:
    return llm.chat(messages).content


def _extract(reply: str) -> str:
    m = _FENCE.search(reply)
    return (m.group(1) if m else reply).strip("\n")


class ToolSmith:
    def __init__(self, registry: ToolRegistry, *, chat: ChatFn | None = None,
                 runner_identity: str = "toolsmith-runner"):
        self.registry = registry
        self.chat = chat or _default_chat
        self.runner_identity = runner_identity

    # ---- detect ----
    def detect(self, spec: ToolSpec) -> ToolRecord | None:
        for t in self.registry.find(spec.capability, verified_only=True, k=3):
            return t  # a verified tool already covers this capability -> reuse
        return None

    # ---- scaffold ----
    def scaffold(self, spec: ToolSpec) -> str:
        user = (
            f"Function name: {spec.name}\nCapability: {spec.capability}\n"
            f"Signature: {spec.signature_hint or '(infer)'}\n"
            "Write the function now."
        )
        return _extract(self.chat([{"role": "system", "content": _SYSTEM},
                                   {"role": "user", "content": user}]))

    # ---- test ----
    def evaluate(self, code: str, spec: ToolSpec) -> tuple[bool, float, str]:
        probe = ToolRecord(name=spec.name, code=code, side_effect=spec.side_effect).sign()
        try:
            fn = load_callable(probe)
        except Exception as e:  # noqa: BLE001
            return False, 0.0, f"load failed: {e}"
        if not spec.cases:
            return False, 0.0, "no held-out cases"
        passed = 0
        for c in spec.cases:
            try:
                got = fn(*c.args, **c.kwargs)
            except Exception as e:  # noqa: BLE001
                return False, passed / len(spec.cases), f"case raised: {e}"
            if got == c.expected:
                passed += 1
        score = passed / len(spec.cases)
        return score >= PASS_THRESHOLD, score, f"{passed}/{len(spec.cases)} cases"

    def _receipt(self, spec: ToolSpec) -> RunReceipt:
        rr = RunReceipt(
            suite_sha=spec.suite_sha(),
            inputs_digest=hashlib.blake2s(spec.name.encode()).hexdigest()[:16],
            coverage_assertion=f"scanned files: tool:{spec.name}",
            runner_identity=self.runner_identity, signature="",
        )
        rr.signature = sign_receipt(rr)
        return rr

    # ---- build (detect → scaffold → test → register) ----
    def build(self, spec: ToolSpec, *, human_review: Callable[[ToolRecord], bool] | None = None,
              ts: float = 0.0) -> BuildResult:
        if (reuse := self.detect(spec)) is not None:
            return BuildResult(reuse, True, True, reuse.eval_score, Trust.VERIFIED, True, "reused")

        code = self.scaffold(spec)
        passed, score, detail = self.evaluate(code, spec)

        # Attested gate: the eval ran the frozen suite and covered the tool (hollow-gate guard).
        report = Report(verdict=Verdict.PASS if passed else Verdict.FAIL,
                        summary=f"tool eval {detail} (score={score:.2f})",
                        grader=GraderKind.CONTRACT, run_receipt=self._receipt(spec))
        gr = gate([report], required={GraderKind.CONTRACT},
                  frozen_suites={GraderKind.CONTRACT: spec.suite_sha()},
                  diff_files={f"tool:{spec.name}"})

        tool = ToolRecord(name=spec.name, capability=spec.capability, code=code,
                          doc=spec.signature_hint, side_effect=spec.side_effect,
                          provenance=[f"toolsmith:{spec.suite_sha()}"], eval_score=score)

        if not (passed and gr.verdict == Verdict.PASS):
            return BuildResult(tool, False, False, score, None, False,
                               f"eval failed ({detail}); no tool enters red")

        # Destructive tools require a human-review verdict before they can be `verified`.
        if spec.side_effect not in AUTO_PROMOTABLE:
            approved = bool(human_review and human_review(tool))
            if not approved:
                self.registry.register(tool, trust=Trust.CANDIDATE, ts=ts)
                return BuildResult(tool, False, True, score, Trust.CANDIDATE, True,
                                   "destructive: registered candidate, awaiting human review")
        self.registry.register(tool, trust=Trust.VERIFIED, ts=ts)
        return BuildResult(tool, False, True, score, Trust.VERIFIED, True, "verified + registered")
