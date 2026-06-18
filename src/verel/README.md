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
agents/          The seam where models author work the bus then gates (§11.1 item 5)
  llm.py           dependency-free provider-agnostic chat (Ollama Cloud default; OpenAI; Claude-ready)
  coder.py         Coder protocol + LLMCoder + make_fix_hook() — agent sees only grader findings
memory/          The trust layer Verel owns over a rentable backend (§5, §7.5)
  view.py          MemoryView protocol + records: split epistemic_confidence vs retrieval_strength,
                   interference rule, documented ranking, exact prune rule
  local.py         zero-dep sqlite MemoryView (mem0 is the drop-in behind the same Protocol)
  failure_ledger.py  record failures → mark fixed on PASS → regression-guard gates reintroductions
  consolidate.py   episodic failures → CANDIDATE `inferred` DesignRule (Ollama Cloud; cluster=evidence)
  promotion.py     held-out, attested, agent-inaccessible eval gate: inferred→verified; leakage canary
fleet/           Agents managing agents — the v1-cut control plane (§6)
  task.py          Task DAG model, roles, retry, budget lease
  scheduler.py     single-writer scheduler: deps/barriers (all|k_of_n|optional), concurrency,
                   retry/quarantine, hard budget, WAL resume; gates every node via the verdict bus
  manager.py       fan-out decision + plane validation (independence/acyclicity/clamp)
  worker.py        worker adapter — runs ultracode_loop, so a worker can't self-declare done
loop.py          The single-worker ultracode loop (§7.3, §8.5); FixHook + optional memory ledger
```

## Demos

```bash
python examples/demo_overflow_loop.py   # deterministic fix → self-computed pass
python examples/demo_agent_loop.py       # real LLM agent fixes it (Ollama Cloud)
python examples/demo_memory_loop.py      # fix → remember → reintroduce → memory blocks it
python examples/demo_promotion.py        # induce → held-out attested eval → verified (+canary)
python examples/demo_fleet_loop.py       # manager fans out workers; each gated by its own eyes
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
