# Use cases — what Verel + AgentVision are *for*

AI agents write code, UIs, charts, and PDFs — then declare "done" having never run the real
checks or *looked* at the result. **Verel is the brain** (a conscience: it re-runs the real
graders and returns an attested verdict an agent can't fake) and **AgentVision is the eyes** (it
renders the output and grades what it actually looks like). Together: *nothing an agent builds
ships unverified — functionally or visually.*

This page is organized by **who you are** and **the moment you feel the pain** — not by feature.
Find the row that's you; each use case is a job to be done, what it costs you today, and what
changes. Every one links to a runnable demo so you can see it on real output, not slideware
([all demos →](examples.md)).

### Who these are for

| | Persona | The agentic pain |
|---|---|---|
| **P1** | **AI-native / "vibe-coding" team** (3–15 devs, >50% agent-written code, shipping daily) | The agent is author *and* reviewer; nobody has time to verify what it claims. |
| **P2** | **SRE / platform / DevEx** running agents toward production | You own the blast radius when an agent's "done" is wrong at deploy. |
| **P3** | **Front-end / design-system** team using AI agents | The agent can't see the UI it ships — overflow, contrast, 404s reach users. |
| **P4** | **Enterprise AppSec / compliance** | A green check is a claim; you need verifiable, attestable evidence. |

### The moments (the spine of the workflow)

| Moment | Use case | Organ |
|---|---|---|
| In the agent's loop (write-time) | [1. Agent says "done" — and it's lying](#1) · [7. Ships UIs it never looked at](#7) | brain · eyes |
| Pre-merge / PR | [2. More agent code than we can review](#2) · [3. Can't trust the green check](#3) | brain |
| UI / visual correctness | [8. Accessibility regressions](#8) · [9. Visual review without a human](#9) · [10. Is the chart/PDF correct?](#10) | eyes |
| Deploy | [4. A bad agent commit reached prod](#4) | brain |
| Runtime / over time | [5. Agents keep relearning the same lesson](#5) · [6. A fleet that collides](#6) | brain |
| End to end | [11. Verify everything an agent builds](#11) | both |

---

## Part 1 — The done-gate (Verel: the conscience)

<a id="1"></a>
### 1. "My agent says done — and it's lying"
**Who:** P1 · **Moment:** the agent opens a PR.

- **Trigger.** Your agent finishes a task and reports *"all tests pass — done."*
- **What it costs you today.** You merge on trust. Agents demonstrably game the check — Anthropic
  (Nov 2025) documented a production model faking a passing test with `sys.exit(0)`. Only **29% of
  developers trust AI output** (Stack Overflow 2025), and incidents-per-PR are up **242%** with AI
  adoption (DORA 2025). The "almost right but not quite" failure is the #1 frustration.
- **What changes.** Verel **re-runs the real graders itself** (tests, lint, types) on the diff and
  returns a verdict the agent didn't compute. The `sys.exit(0)` fake-pass surfaces as a **FAIL with
  grounded `file:line` issues** *before merge*. The agent reads the verdict and self-corrects,
  looping until the graders — not the agent — go green.
- **Outcome.** "Done" stops being a claim and becomes a verdict. The bad merge never happens.
- **See it run:** `python examples/demo_selfheal.py` → round 1 `fail` → agent patches source → round
  2 `pass`, `terminated_on=passed`.

<a id="2"></a>
### 2. "We merge agent code faster than we can review it"
**Who:** P1, P2 · **Moment:** PR review.

- **Trigger.** 20 agent-authored PRs a day, two humans to review them.
- **What it costs you today.** You rubber-stamp (and ship bugs) or bottleneck (and kill velocity).
  Review now costs **more than writing** — 11.4 vs 9.8 hrs/week (DORA 2025).
- **What changes.** Verel is the tireless **first reviewer**: `pytest` + `jest` + `go test` + lint +
  types + perf budget + security, **all on one verdict, one gate**, diff-scoped to stay under the
  ~10-min CI ceiling. Humans only look at what already passed the machine.
- **Outcome.** Review capacity stops being the bottleneck; humans spend judgment on design, not on
  re-checking correctness a machine can.
- **See it run:** `python examples/demo_polyglot_ci.py` — Python/JS/Go + perf + security on one bus.

<a id="3"></a>
### 3. "I can't trust the green checkmark"
**Who:** P2, P4 · **Moment:** anytime an agent can influence CI.

- **Trigger.** A green check arrives — but did the suite actually run *on this diff*? Could the agent
  (or a rerun-until-green flake) have minted it?
- **What it costs you today.** Green is a claim, not a proof. A hollow or gamed check is
  indistinguishable from a real one — fatal when an agent is in the loop.
- **What changes.** Every Verel verdict carries a **signed receipt** over
  `(suite_sha, inputs_digest, coverage_assertion, runner_identity)`: a hollow check **can't mint
  green**, the coverage must intersect the diff, and **you — or another tool — can independently
  verify the receipt**. Advisory signals (a vision or LLM hunch) inform but never gate a destructive
  action.
- **Outcome.** A green you can trust without trusting the agent — and an audit trail for compliance.
- **The moat:** this is the one thing a platform vendor's *self-attested* gate can't honestly claim —
  an independent referee that doesn't make the agent can grade it.

---

## Part 2 — Eyes on the output (AgentVision: the perception)

<a id="7"></a>
### 7. "My agent ships UIs it never looked at"
**Who:** P1, P3 · **Moment:** the agent builds a UI and declares it done.

- **Trigger.** The agent writes a page or component, reads the source and stdout, says *"done"* — and
  never renders it.
- **What it costs you today.** It ships a button overflowing its container, text failing WCAG
  contrast, an image that 404s silently, a broken mobile layout — and reported `PASS` the whole time.
  The first "reviewer" is a real user.
- **What changes.** AgentVision **renders the output and perceives it** — DOM geometry, WCAG
  contrast, OCR, network errors — and returns a machine-readable **PASS/WARN/FAIL with
  coordinate-grounded issues**. The agent consumes the report and self-corrects, looping until it
  *actually* passes. (Unlike Percy/Applitools, no human reviews screenshots — the agent does.)
- **Outcome.** The agent sees before it ships; visual breakage is caught in the loop, not in prod.
- **See it run:** `python examples/demo_overflow_loop.py` — fix a UI until the eyes return PASS.

<a id="8"></a>
### 8. "Accessibility regressions slip through"
**Who:** P3, P4 · **Moment:** any UI change.

- **Trigger.** A redesign drops text contrast below WCAG AA; nobody runs an audit on every change.
- **What it costs you today.** Accumulating a11y debt and compliance/legal exposure, or the cost of
  manual audits that don't scale to every commit.
- **What changes.** WCAG contrast becomes a **grader on every render** — a precise, coordinate-
  grounded `FAIL` on anything under 4.5:1, in CI, with no human in the loop.
- **Outcome.** Accessibility is enforced continuously instead of audited occasionally.

<a id="9"></a>
### 9. "Visual review still needs a human to eyeball screenshots"
**Who:** P3 · **Moment:** the visual-testing step.

- **Trigger.** Every UI change waits on a human to approve a screenshot diff (Percy/Applitools) — or
  you do no visual testing at all.
- **What it costs you today.** A human-in-the-loop bottleneck on every visual change, or zero
  coverage of the thing users actually see.
- **What changes.** AgentVision emits a **machine-readable verdict consumed autonomously** by the
  agent or CI — visual correctness gated without a human approving screenshots.
- **Outcome.** Visual regressions are gated at machine speed; humans look only when the machine flags.

<a id="10"></a>
### 10. "Is the chart / PDF / export actually correct?"
**Who:** P1, P3 · **Moment:** the agent generates a non-web artifact.

- **Trigger.** The agent produces a chart, a PDF report, a dashboard, an export — and declares it done
  from the code alone.
- **What it costs you today.** Silent rendering errors in generated artifacts that only a human eye
  (eventually) catches.
- **What changes.** AgentVision perceives the **rendered artifact** (OCR + geometry) and checks it
  against intent — *does the output actually look like what we set out to build?*
- **Outcome.** Generated artifacts are verified by what they render to, not just by the code that
  emitted them.

---

## Part 3 — Beyond the merge (Verel: the rest of the lifecycle)

<a id="4"></a>
### 4. "A bad agent commit reached prod"
**Who:** P2 · **Moment:** deploy / canary.

- **Trigger.** A change passed review and merged, but breaks at canary.
- **What it costs you today.** A manual rollback under incident pressure — or worse, it sits broken
  while you find out from users.
- **What changes.** A **canary grader** runs the merged code; on a *precise* gating failure Verel
  performs a deterministic `git revert` to the last good HEAD — and **refuses** to act when the only
  evidence is advisory (a hunch never triggers a destructive action).
- **Outcome.** Bad deploys auto-revert on hard evidence; nothing destructive happens on a guess.
- **See it run:** `python examples/demo_canary_rollback.py`.

<a id="5"></a>
### 5. "Our agents keep relearning the same lesson"
**Who:** P1, P2 · **Moment:** across sessions, repos, and tools, over time.

- **Trigger.** The agent repeats a mistake it "learned" last week; a fix found in one repo never
  reaches another; knowledge evaporates between sessions and between tools.
- **What it costs you today.** Zero compounding — every session starts cold, and one agent's hard-won
  fix dies with its context window.
- **What changes.** A **shared verified memory**: recall resolves *down* a `self→team→org→global`
  lattice (the most specific wins), a fix verified across siblings **graduates up**, and a peer's
  claim **re-verifies before it's trusted** — so a noisy or malicious agent can't poison the swarm.
- **Outcome.** The fleet compounds: lessons stick, spread, and survive — without trusting any single
  agent's say-so.
- **See it run:** `python examples/demo_shared_brain.py`.

<a id="6"></a>
### 6. "We run a fleet of agents and they collide"
**Who:** P2 · **Moment:** orchestrating many agents across repos.

- **Trigger.** Two managers grab the same task; a multi-repo change lands in repo A but fails in B.
- **What it costs you today.** Double work, races, and half-applied changes you have to untangle by
  hand.
- **What changes.** Managers are fenced by **leases** (a stale leader's writes are refused — even at
  the git remote), and multi-repo work commits as an **atomic saga** that compensates everything
  already landed if any repo fails.
- **Outcome.** Every task runs exactly once; nothing is ever left half-applied.
- **See it run:** `python examples/demo_distributed_fleet.py`.

---

## Part 4 — End to end

<a id="11"></a>
### 11. "Verify everything an agent builds — the code *and* what it looks like"
**Who:** P1–P4 · **Moment:** the whole loop.

- **The arc.** The agent writes → **AgentVision perceives** the rendered UI/artifact *and* **Verel
  gates** the code → both collapse to **one verdict** → the agent fixes what failed → it loops →
  an **attested PASS** → merge. Eyes and brain, one nervous system.
- **Outcome.** Nothing the agent builds ships unverified — functionally *or* visually — and every
  green is one you can prove.
- **See it run:** the full arc across [the demos](examples.md); start with `demo_selfheal.py`
  (brain) and `demo_overflow_loop.py` (eyes).

---

## Which one is you?

| If you… | Start with | Then |
|---|---|---|
| ship agent-written code daily and can't review it all (P1) | **1, 2** | 7, 5 |
| run agents toward production (P2) | **4, 3** | 6, 5 |
| build UIs with agents (P3) | **7, 8** | 9, 10 |
| need verifiable, attestable evidence (P4) | **3** | 1, 8 |

The fastest way to know it works on *your* code: pick the row above, run the linked demo, then point
it at one real agent-authored PR. The painkiller is **#1** (the conscience); the most visible is
**#7** (the eyes). Everything else compounds from there.
