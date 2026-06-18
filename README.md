# Verel

> The agent framework where nothing is **"done"** until a grader returns a verdict —
> checked by real senses including **eyes** ([AgentVision](../Eyes_For_AI_Agents)) —
> and only verified work is allowed to compound into the fleet's shared memory.

## Documents

- **[docs/VEREL_DESIGN.md](docs/VEREL_DESIGN.md)** — definitive architecture & build plan
  (positioning, the moat, the five organs, the Brain/memory architecture, the Fleet,
  the Verdict bus, AgentVision-as-eyes, claimable inventions, risks, phased roadmap,
  open decisions).
- **[docs/CRITIC_CONVERGENCE.md](docs/CRITIC_CONVERGENCE.md)** — the adversarial critic-loop
  score record that the design was iterated against until diminishing returns.

## The five organs

```
Brain (memory)  ─┐
Fleet (agents managing agents) ─┤
Verdict bus (eval-driven everything) ─┼─► nothing merges on a self-asserted "done"
Senses (AgentVision eyes + logs/tests/metrics) ─┤
Tool-smith (agent-built tooling) ─┘
```

## Smallest first useful thing (Phase 0, ~2–4 weeks)

Unified `Report`/`Percept` schema + `gate()` + scrubbed-fingerprint `progressed()`,
wired to the AgentVision `sight` adapter over MCP, driving a single-worker ultracode loop
on one real repo's UI. **Done = Verel fixes a real UI overflow and the loop terminates on
a `pass` verdict it computed itself.** No memory, no fleet, no consolidation yet.
