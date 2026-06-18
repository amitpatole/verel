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
  mem0_backend.py  Mem0Memory — the rented mem0 store behind the SAME MemoryView Protocol
toolsmith/       Agents building their own tools (§7.6)
  registry.py      signed, versioned tool registry as SKILL records; sandboxed load_callable
  smith.py         detect → scaffold (LLM) → test (held-out) → register (gated) → reuse
ci/              Agent-run CI/CD on the verdict bus (§7.4)
  graders.py       tests/lint/types as senses → attested verdict-bus Reports (pure parsers)
  pipeline.py      inner-loop + pre-commit stages: gate + failure-memory regression check
  medic.py         classify failures → retry / regen-lockfile / quarantine-flaky / fix-branch
  rollback.py      deterministic policy engine — destructive actions never use advisory evidence
  hooks.py + __main__.py   `python -m verel.ci {check,precommit,install}` for git hooks/agents
fleet/           Agents managing agents — the v1-cut control plane (§6)
  task.py          Task DAG model, roles, retry, budget lease
  scheduler.py     single-writer scheduler: deps/barriers (all|k_of_n|optional), concurrency,
                   retry/quarantine, hard budget, WAL resume; gates every node via the verdict bus
  manager.py       fan-out decision + plane validation (independence/acyclicity/clamp)
  llm_manager.py   LLM-driven manager (Ollama) — model proposes, plane disposes; safe fallback
  worktree.py      isolated git worktree per worker + exclusive advisory lease (§6.1/§6.3 v1)
  worker.py        worker adapters — ultracode_loop, and worktree_ultracode_worker (isolated)
loop.py          The single-worker ultracode loop (§7.3, §8.5); FixHook + optional memory ledger
```

## Demos

```bash
python examples/demo_overflow_loop.py   # deterministic fix → self-computed pass
python examples/demo_agent_loop.py       # real LLM agent fixes it (Ollama Cloud)
python examples/demo_memory_loop.py      # fix → remember → reintroduce → memory blocks it
python examples/demo_promotion.py        # induce → held-out attested eval → verified (+canary)
python examples/demo_fleet_loop.py       # manager fans out workers; each gated by its own eyes
python examples/demo_toolsmith.py        # agent scaffolds+verifies a tool, reuses it, gates destructive
python examples/demo_fleet_worktrees.py  # LLM manager fans out → workers fix pages in isolated worktrees
python examples/demo_cicd.py             # real pytest grader gates FAIL→PASS; medic + rollback engine
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
