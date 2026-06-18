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

## Install

```bash
pip install verel                 # core: the verdict bus + memory + fleet + tool-smith + CI
pip install "verel[sight]"        # + AgentVision (the eyes)
pip install "verel[mem0,mcp]"     # + rented memory backend, + MCP server
```

```bash
verel doctor                      # check the environment
verel heal --repo .               # self-healing CI: failing tests → agent fixes → green
verel loop dashboard.html         # fix a UI until AgentVision returns a pass verdict
verel fleet "fix the pages" --artifacts a.html b.html
```

Default LLM is **Ollama Cloud** (`~/.config/ollama/key`, model `qwen3-coder:480b`); set
`VEREL_LLM_PROVIDER=openai` to switch. Claude is one branch away in `agents/llm.py`.

## What's built (all five organs, end-to-end)

| Organ | Module | What works |
|---|---|---|
| **Verdict bus** | `verel.verdict` | one schema for vision **+ tests + lint + types**; advisory ceiling, grader attestation, scrubbed fingerprints, strict-subset stuck/progress |
| **Eyes** | `verel.senses` | AgentVision adapter — perception feeds the bus and memory |
| **Agents** | `verel.agents` | coder (fixes UIs) + code-fixer (patches source); Ollama Cloud |
| **Brain** | `verel.memory` | trust layer (LocalMemory / mem0), failure ledger + regression guard, consolidation, **held-out attested promotion gate** |
| **Fleet** | `verel.fleet` | single-writer scheduler (barriers/budget/WAL), **LLM-driven manager**, **isolated git worktrees** |
| **Tool-smith** | `verel.toolsmith` | detect → scaffold → test → register → reuse; signed registry; sandboxed exec |
| **Agent-run CI/CD** | `verel.ci` | tests/lint/type graders, inner-loop/pre-commit/pre-merge stages, **self-healing**, ci-medic, deterministic rollback engine, git hook + CLI |
| **Surfaces** | `verel.cli`, `verel.mcp_server` | `verel` CLI, MCP server, `verel-ci` |

**106 tests, 9 runnable demos.** Code + module guide: [`src/verel/`](src/verel/README.md).
Design & roadmap: [docs/VEREL_DESIGN.md](docs/VEREL_DESIGN.md). Changelog: [CHANGELOG.md](CHANGELOG.md).
