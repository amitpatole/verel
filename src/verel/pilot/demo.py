"""`verel pilot demo` — no API key, no media files: a synthetic 200-artifact pilot that shows the whole
arc (shadow-record → label → evaluate → graduate only what earned it). Deterministic (fixed pattern,
no RNG), so the output is reproducible and the numbers are real outputs of the real gate."""

from __future__ import annotations

import tempfile
from pathlib import Path

from ..verdict.fingerprint import assign
from ..verdict.models import GraderKind, Issue, IssueKind, Report, Severity, Verdict
from .evaluate import Label, evaluate
from .log import ShadowLog
from .mode import Mode
from .render import render
from .shadow import run_pilot

N = 200


def _report(grader: GraderKind, bad: bool, kind: IssueKind, aid: str) -> Report:
    issues = [Issue(kind=kind, severity=Severity.ERROR, message=f"{kind.value} detected",
                    locator=f"{aid}@0-1000ms", source=grader)] if bad else []
    return assign(Report(verdict=Verdict.FAIL if bad else Verdict.PASS,
                         summary="synthetic", issues=issues, grader=grader))


def run_demo() -> int:
    with tempfile.TemporaryDirectory() as d:
        log = ShadowLog(Path(d) / "pilot.jsonl")
        labels: list[Label] = []
        for i in range(N):
            aid = f"asset-{i:03d}"
            defect = i % 4 == 0                      # 50 real defects out of 200
            labels.append(Label(artifact_id=aid, defect=defect))
            # DSP (precise): misses every 5th real defect, 1 false alarm on a clean asset.
            dsp_bad = (defect and i % 20 != 0) or i == 7
            # AUDIO_LLM (advisory): catches most defects but fires on ~1 in 3 clean assets.
            llm_bad = defect or (not defect and i % 3 == 1)
            run_pilot(
                [_report(GraderKind.DSP, dsp_bad, IssueKind.LOUDNESS, aid),
                 _report(GraderKind.AUDIO_LLM, llm_bad, IssueKind.OTHER, aid)],
                artifact_id=aid, mode=Mode.SHADOW, log=log,
            )
        print(f"recorded {log.verify()} shadow decisions (hash chain verified); "
              f"the pipeline was never blocked.\n")
        ev = evaluate(log.records(), labels, min_samples=30, min_precision=0.85)
        print(render(ev))
    ready = [g.grader for g in ev.graders if g.ready_to_enforce]
    held = [g.grader for g in ev.graders if not g.ready_to_enforce]
    print(f"\nRecommend graduating to ENFORCE: {', '.join(ready) or 'none'}. "
          f"Keep in shadow/advisory: {', '.join(held) or 'none'}. A human makes the call.")
    return 0
