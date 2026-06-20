# Verel — Verified Agents 👁️🧠

<p align="center">
  <img src="https://raw.githubusercontent.com/amitpatole/verel/main/media/hero.png" alt="Verel — nothing is done until a grader returns a verdict" width="100%">
</p>

> **Problem:** AI agents declare work *"done"* on their own say-so — shipping broken UIs,
> failing tests and unverified claims they can't actually check.
> **Result:** Verel makes *"done"* a **verdict**, not an opinion — every action is graded by
> real senses (including **eyes**, via [AgentVision](https://github.com/amitpatole/agent-vision)),
> and **only verified work compounds** into the fleet's shared memory.

```bash
pip install verel
verel doctor                 # check your environment
verel heal --repo .          # self-healing CI: failing tests → agent fixes → green
```

One **verdict bus** unifies vision + tests + lint + types into a single `pass / warn / fail`,
so *progress*, *"done"*, and *what compounds* are all decided in one place — with grader
attestation so a hollow check can't mint green.

## The five organs

| Organ | Module | What it does |
|---|---|---|
| 🧠 **Brain** | `verel.memory` | Memory that compounds — only verified facts/skills graduate (held-out, attested promotion gate); lifecycle controls keep it from becoming a junk drawer. |
| 👁️ **Eyes** | `verel.senses` | **AgentVision** as a perception organ (DOM/contrast/OCR grounded, intent conformance, temporal `watch`) feeding the verdict bus and the brain. |
| ⚖️ **Verdict bus** | `verel.verdict` | One schema for every sense — advisory ceiling clamp, grader attestation, strict-subset stuck/progress. |
| 🚁 **Fleet** | `verel.fleet` | Agents managing agents — LLM manager fans out, workers in isolated git worktrees, each gated by the bus. |
| 🔧 **Tool-smith** | `verel.toolsmith` | Agents build their own tools, sandboxed, admitted only on a passing attested eval. |
| ♻️ **Agent-run CI/CD** | `verel.ci` | Self-healing pipeline + deterministic rollback that never acts on advisory evidence. |

## Eyes & brain

**[AgentVision](https://amitpatole.github.io/agent-vision/) is the eyes; Verel is the brain.**
The eyes perceive and grade (including *does it match what we set out to build?* and *does the
video actually play?*); the brain decides with attestation and **compounds only verified work**
into memory; then the eyes look again.

<p align="center">
  <img src="https://raw.githubusercontent.com/amitpatole/verel/main/media/unified-architecture.png" alt="Eyes & Brain — AgentVision perceives; Verel decides and compounds verified work" width="100%">
</p>

## Next

- **[Get started](getting-started.md)** — install, the gate, CI/agents adoption.
- **[Architecture](ARCHITECTURE.md)** — the five organs and the eval-driven loop.

Install: `pip install verel` · Source: [GitHub](https://github.com/amitpatole/verel) ·
Package: [PyPI](https://pypi.org/project/verel/) · License: MIT.
