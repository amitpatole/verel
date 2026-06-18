# `verel` — Phase 0 walking skeleton

The smallest thing that proves Verel's thesis end-to-end: **render → perceive → gate → fix
→ re-render, terminating on a verdict Verel computes itself.**

```
verdict/         The Verdict bus (§7) — unified eval contract
  models.py        Report / Issue / Percept / RunReceipt / GateResult, enums
  constants.py     SEV_ORDER, GATING_SEVERITY, ADVISORY_CEIL, PRECISE/ADVISORY graders, W
  fingerprint.py   canonicalize() + scrubbed per-grader fingerprint() + issue_signature()
  gate.py          clamp_ceiling() · gate() (dead/hollow-gate + advisory ceiling) ·
                   gating_failures() · progressed()  (strict-subset shrinkage)
senses/          Perception that feeds the bus (§8)
  sight.py         AgentVision adapter — grader identity off Issue.source, split per source,
                   CLASSIC_CAPABILITIES imported from source (drift-proof)
  percept_log.py   Verel-owned episodic log + progressed/stuck (crash-safe, not LoopSession's)
loop.py          The single-worker ultracode loop (§7.3, §8.5) with a pluggable FixHook
```

## Try it

```bash
pip install -e ".[dev]"          # verdict bus + tests (32 tests, sight tests skip)
pip install -e ".[sight]"        # + AgentVision for the real perception path
python examples/demo_overflow_loop.py
```

The demo plants a real horizontal overflow, lets the loop perceive it (AgentVision),
gate it (Verel), fix it, and re-render — terminating on a **self-computed `pass`**. If the
fix doesn't actually clear the issue, Verel detects `stuck` and stops instead of thrashing.

## What is deliberately NOT here (Phase 0 cut)

No memory/brain, no fleet/orchestration, no consolidation, no agent-built tooling, no
worker fencing. The `FixHook` is the seam where a coding subagent plugs in later. See
`../../docs/VEREL_DESIGN.md` §11 for the full roadmap and kill-list.
