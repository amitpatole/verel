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
attestation (a signed receipt of what actually ran) so a *hollow check* — a grader that claims
success with no evidence — can't mint green.

## Is Verel for you?

- **Agents that write code**, and you need a grader that re-runs the *real* tests so the agent can't
  fake "done"? → **yes.** Start: **[5-minute tutorial](tutorial.md)**.
- **A fleet of agents sharing one brain**, where a hallucination (or one bad actor) must not become
  trusted memory? → **yes.** Start: **[Memory in 5 minutes](memory-quickstart.md)**.
- **Agents that render UIs but never look at them** (overflow, contrast, 404s, video stalls)? → **yes**,
  with [AgentVision](https://amitpatole.github.io/agent-vision/) as the eyes.
- **Paying too much for context** because you replay the whole memory into every prompt? → **yes** —
  budgeted, graded-first recall cuts a 40-fact brain ~**80%** (679→135 tok/turn). [Cost →](comparison.md#cost-what-graded-budgeted-recall-saves)
- **Just want a memory layer for a single agent with a human curator?** → Verel works, but **Mem0** is
  simpler. Here's the honest [when-to-use comparison](comparison.md).

## The six organs

| Organ | Module | What it does |
|---|---|---|
| 🧠 **Brain** | `verel.memory` | Memory that compounds — only verified facts/skills graduate (held-out, attested promotion gate); lifecycle controls keep it from becoming a junk drawer. **Pluggable backend** (`VEREL_MEMORY_BACKEND`): local SQLite, a shared hosted brain, or an external DB. |
| 👁️ **Eyes** | `verel.senses` | **AgentVision** as a perception organ (DOM/contrast/OCR grounded, intent conformance, temporal `watch`) feeding the verdict bus and the brain. |
| ⚖️ **Verdict bus** | `verel.verdict` | One schema for every sense — advisory ceiling clamp, grader attestation, strict-subset stuck/progress. |
| 🚁 **Fleet** | `verel.fleet` | Agents managing agents — LLM manager fans out, workers in isolated git worktrees, each gated by the bus. |
| 🔧 **Tool-smith** | `verel.toolsmith` | Agents build their own tools, sandboxed, admitted only on a passing attested eval. |
| ♻️ **Agent-run CI/CD** | `verel.ci` | Self-healing pipeline + deterministic rollback that never acts on advisory evidence; graders span Python/JS-TS/Go, perf, security, mutation, spec/intent — and **IaC / cloud-IAM / Kubernetes-RBAC** (catch dangerous Terraform/cloud grants *before apply*). |

## Eyes & brain

**[AgentVision](https://amitpatole.github.io/agent-vision/) is the eyes; Verel is the brain.**
The eyes perceive and grade (including *does it match what we set out to build?* and *does the
video actually play?*); the brain decides with attestation and **compounds only verified work**
into memory; then the eyes look again.

<p align="center">
  <img src="https://raw.githubusercontent.com/amitpatole/verel/main/media/unified-architecture.png" alt="Eyes & Brain — AgentVision perceives; Verel decides and compounds verified work" width="100%">
</p>

## Next

- **[Memory in 5 minutes](memory-quickstart.md)** — extract → grade → recall, offline, no key. The
  fastest standalone win if you came for the memory.
- **[Verel vs Mem0 / Engram / Zep](comparison.md)** — honest when-to-use, and a "coming from Mem0" mapping.
- **[Try it yourself](try-it.md)** — a from-scratch, copy-paste walkthrough (no API key): catch a
  real bug, fix it, watch Verel remember it so it can't come back.
- **[Get started](getting-started.md)** — install, the gate, CI/agents adoption.
- **[5-minute tutorial](tutorial.md)** — gate a repo, heal failing tests, watch a bug get remembered.
- **[Use cases](use-cases.md)** — where Verel fits: agent loops, CI/CD, fleets, shared memory.
- **[Real-world scenarios](examples.md)** — runnable demos with real captured output for each.
- **[Architecture](ARCHITECTURE.md)** — the six organs and the eval-driven loop.

Install: `pip install verel` · Source: [GitHub](https://github.com/amitpatole/verel) ·
Package: [PyPI](https://pypi.org/project/verel/) · License: MIT.
