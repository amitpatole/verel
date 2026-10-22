# Pilot — shadow mode and earned enforcement

Putting a new gate into a real pipeline is a trust problem, not a technical one. `verel.pilot` lets
you run Verel **beside** your existing process first, measure it against human judgment, and enforce
only what the evidence supports.

## The three modes

| Mode | What the pipeline sees | Use it to |
|---|---|---|
| `shadow` | always PASS; the real verdict is logged | prove Verel is safe to attach (no blocked deliveries) |
| `advisory` | FAIL is downgraded to WARN | surface problems to humans without stopping work |
| `enforce` | the real verdict | block on graders that have earned it |

An unknown mode name is an **error**, never a silent default. A crash inside the gate is treated as
FAIL: it blocks in `enforce` and is recorded as `gate_error` in every mode, so a broken grader shows
up in the pilot evidence instead of hiding.

## Workflow

```bash
# 1. In the pipeline: grade each artifact, log the would-be verdict. Exit code follows the MODE.
verel pilot record --reports reports.json --artifact-id ep-2041-en --log pilot.jsonl

# 2. Reviewers label a sample: [{"artifact_id": "ep-2041-en", "defect": true}, ...]

# 3. Score the pilot. Recommends graders that earned enforcement; changes nothing.
verel pilot eval --log pilot.jsonl --labels labels.json

# 4. Integrity: the log is hash-chained. Record the head somewhere else to also catch truncation.
verel pilot verify --log pilot.jsonl --expect-head <head hash>
```

`--reports` takes one Report or a list, in the shared `agentsensory` / verdict-bus JSON shape, so
output from AgentVision, Audel or any other organ goes straight in. From Python:
`run_pilot(reports, artifact_id=..., mode="shadow", log=ShadowLog("pilot.jsonl"))`.

## What "earned enforcement" means

For each grader, over the latest verdict per labeled artifact: precision, recall and false-positive
rate, plus the **Wilson lower bound** of precision, so a small lucky sample can't look precise. A
grader is recommended for `enforce` only with at least `--min-samples` flagged artifacts (default 30)
**and** a precision lower bound of at least `--min-precision` (default 0.95). Defaults are
deliberately strict; tune them to the cost of a false block in your pipeline.

Also reported: `labels_without_record` (labeled artifacts the pipeline never graded, a coverage
hole), `unlabeled_records`, and graders that **errored**, which are excluded from their own stats
rather than counted as passes.

## Real output

`verel pilot demo` (synthetic, no API key, deterministic):

```text
recorded 200 shadow decisions (hash chain verified); the pipeline was never blocked.

labeled=200  unlabeled_records=0  labels_without_record=0  gate_errors=0
  GATE         tp=40  fp=1   tn=149 fn=10  precision= 97.6% (lb 87.4%) recall= 80.0% fpr=  0.7%  
  audio_llm    tp=50  fp=50  tn=100 fn=0   precision= 50.0% (lb 40.4%) recall=100.0% fpr= 33.3%  -> keep in shadow/advisory: precision lower bound 0.40 < 0.85
  dsp          tp=40  fp=1   tn=149 fn=10  precision= 97.6% (lb 87.4%) recall= 80.0% fpr=  0.7%  -> READY to enforce: precision lower bound 0.87 >= 0.85 over 41 flags

Recommend graduating to ENFORCE: dsp. Keep in shadow/advisory: audio_llm. A human makes the call.
```

## Honest limits

- The log is **tamper-evident, not tamper-proof**. Anyone with write access can replace the whole file;
  anchor the head hash in a system they don't control.
- `verel pilot record` trusts the Report JSON it is handed (it does not demand signed receipts). Feed it
  output from graders in your own pipeline; use `run_pilot(..., required=..., frozen_suites=...)` from
  Python when you need receipt verification during the pilot.
- Appends take an exclusive file lock and re-verify the chain, so parallel workers share one log safely
  on one host. That costs O(n) per append, fine for pilot volumes. Multi-host pilots need a shared
  filesystem with working `flock`, or one collector process.
- Metrics are only as good as the labels. Label a sample that matches production, including clean
  artifacts, or precision and false-positive rate are meaningless.
- Graduation is a recommendation from evidence. A human decides.
