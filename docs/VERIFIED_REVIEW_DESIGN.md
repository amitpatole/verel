# Verified Review — design doc (internal)

> Status: **proposal, for review**. Not yet built. Internal (excluded from the public docs site).
> Scope: new graders that make Verel catch the failure modes of AI-authored PRs — *"the ticket says
> A, the code does B,"* vacuous tests, ignored business rules, and needless abstraction.

## 1. Context — the problem this solves

A Tech Lead's complaint (r/Anthropic, "AI is ruining my job as Tech Lead") is, read as a spec, a
precise list of what today's gates *don't* catch on agent-authored code:

1. **"The ticket says A, the code does B."** — the change doesn't implement what was asked.
2. **"Tests exist, but don't actually test anything useful."** — green suites that assert nothing.
3. **"Business rules get ignored."** — declared invariants silently violated.
4. **"Random abstractions appear for problems nobody was trying to solve."** — over-engineering.

Result: review time triples, the human is the only real check, and they "can't approve and hope."

**Where Verel stands today** (verified against the code):
- Intent conformance exists **only for visual output** (`senses/sight.py` → AgentVision "matches the
  brief"). There is **no code/logic spec grader**. `GraderKind.LLM_JUDGE` exists in the vocabulary
  (`verdict/models.py:102`) but is **advisory-only** (`constants.py:28`) and **has no runnable
  implementation**.
- We enforce **coverage-of-diff** (a receipt must prove the suite touched the changed files —
  `gate.py:112 coverage_satisfied`) and reject **hollow passes** (a required grader needs a verified
  `RunReceipt`). But a test can touch a file and assert nothing — there is **no test-effectiveness
  (mutation) grader**.
- There is **no business-rule/invariant grader** and **no over-engineering/complexity grader**
  (the latter is the smell organ **`olfel`**'s job; `~/WORKSPACE/olfel` is a skeleton today).

**Conclusion:** the verdict-bus architecture already anticipates these (the `LLM_JUDGE`, `CONTRACT`,
`COST` kinds exist), but the graders that answer *"is this the RIGHT change, are the tests
MEANINGFUL, is it over-built"* are not implemented. This doc designs them.

## 1.5 Strategy — adoption first, one organism later (decided)

**Verel does *everything* for now — the boundary/gateway *enforcement* that will eventually belong to
`immel` (immune/boundary) and `actel` (hands/act-then-verify), AND the code-smell/over-engineering
grading that will eventually belong to `olfel` (smell).** None of those organs are **scheduled** for
development yet, and the priority is unambiguous:

> **Get adopted at scale → earn trust → *then* segregate.** Popularize Verel as the single,
> plug-and-play entry point that catches the AI-PR pain anywhere. Once it's trusted and `immel`/`actel`
> are scheduled, factor the enforcement/action-path responsibilities out into them.

Consequence for this design: **build the gateway/enforcement AND the over-engineering smell inside
`verel` now, behind clean seams** so the later extraction (enforcement → `immel`/`actel`; smell →
`olfel`) is a package move, not a rewrite. Keep *verdict* (what Verel decides) separate from
*enforcement* (forward/block/rollback the action) and *action adapters*; keep the smell grader a
self-contained module emitting standard `agentsensory` Reports. Until extraction, the actel/immel
non-negotiables (**fail-closed, dry-run by default, human approval for irreversible/destructive
actions, rollback hooks**) live in `verel`'s gateway and are honored from day one — adoption must not
come at the cost of an unsafe action path.

## 2. The design principle — grounded judgment, never a vibe

The naive fix — *"ask an LLM if the code matches the ticket"* — reproduces the exact thing the post
is angry about: an unreliable opinion. Verel's gate deliberately makes LLM judgment **advisory**
(clamped to `WARNING`, can never gate — `constants.py: ADVISORY_GRADERS`, `clamp_ceiling`). So the
move that is *true to Verel's thesis* is:

> **The LLM proposes; execution verifies. Only an executed, signed, coverage-bound check gates.**

The single lever the codebase already gives us (`verdict/constants.py`):
- A grader in **`PRECISE_GRADERS`** emitting an issue at **`ERROR`** → **gates** (fails the merge).
- A grader in **`ADVISORY_GRADERS`** (or any issue with `Confidence.LOW`) → **clamped to `WARNING`**
  → informs, never gates.

So every capability below splits cleanly into:
- a **grounded, gating** part (a generated/declared check that actually ran, with a `RunReceipt`),
- and an **advisory** part (what the model suspects but couldn't ground), emitted honestly as a
  ceiling-clamped warning — *"couldn't verify this; human, look here."*

A hallucinated judge therefore can neither **block** a good merge (its opinion is advisory) nor
**approve** a broken one (it cannot forge a passing executed check + valid receipt — `gate.py`
hollow-gate guard: signature verify + `suite_sha` + `inputs_digest` + coverage ∩ diff +
`result_digest`). **That is the difference between this and "ask GPT to review the PR."**

## 3. The four capabilities

Each reuses the existing grader contract (`ci/graders.py`: `GraderSpec` → `run_grader()` → `Report`
+ signed `RunReceipt`; gated via `gate(required={...}, frozen_suites={...}, diff_files={...})`). The
`CONTRACT` grader in `memory/promotion.py` / `toolsmith/smith.py` (frozen suite + signed receipt +
gate) is the working template.

### 3.1 Spec / intent conformance grader (code) — `verel` — **the headline**

**Catches:** "the ticket says A, the code does B."

**How it grounds (LLM proposes → execution verifies):**
1. **Extract** checkable acceptance criteria from the **ticket** (human-authored, trusted input —
   *not* the diff): each criterion is `{id, statement, kind: behavioral|api|data|ui, ground_as}`.
   LLM step, advisory by itself.
2. **Compile** each criterion to an **executable check**:
   - `behavioral` → a generated `pytest` case asserting the criterion;
   - `api` → a signature/contract check (the named symbol/endpoint exists with the stated shape);
   - `ui` → delegate to the **eyes** (AgentVision intent conformance, `senses/sight.py`);
   - `data` → a property/schema assertion.
3. **Execute** the compiled checks through the normal `run_grader()` path (in the **sandbox** —
   §6), producing real pass/fail + a signed receipt over the **frozen** generated suite.

**Gating model:**
- A criterion whose grounded check **fails** → `Issue(kind=INTENT_MISMATCH, severity=ERROR,
  source=CONTRACT)` → **gates**. (Reuse `IssueKind.INTENT_MISMATCH`, already in `models.py:82`.)
- A criterion the model proposed but **could not ground** into an executable check → advisory
  `WARNING` (source `LLM_JUDGE`): *"intent coverage is partial — this criterion is unverified."* We
  never claim to verify what we didn't execute.

**Why it can't be gamed:** criteria come from the **ticket**, independent of the agent's code, and
the coding agent never sees the generated spec-checks (same hiding as self-heal hides the tests).
An injected *"ignore all criteria"* in code/comments can't make a failing generated test pass.

**New surface:** a `spec_conformance_spec(repo, ticket, diff)` factory + a parser; reuse
`GraderKind.CONTRACT` (or add `SPEC`). Generated checks executed in the toolsmith sandbox.

### 3.2 Test-effectiveness grader — `verel` — **ships first (deterministic)**

**Catches:** "tests exist but don't test anything useful."

**How it grounds (fully deterministic — no LLM in the gating path):**
- **Mutation testing, diff-scoped:** inject faults into the **changed lines only** (an AST mutator;
  or `mutmut`/`cosmic-ray` behind an extra), run the existing suite. A **surviving mutant** = the
  tests don't actually constrain the change → `Issue(kind=SURVIVED_MUTANT, severity=ERROR)`.
- **Assertion presence:** a changed/added test with **no assertion**, or that never imports the
  changed module → `WARNING`/`ERROR`.
- Diff-scoping keeps it under the CI time budget (mutate only what changed).

**Gating model:** new `GraderKind.MUTATION` placed in **`PRECISE_GRADERS`** → gates at `ERROR`.
Signed receipt over the frozen mutation set; `coverage_assertion` = the mutated files (∩ diff).

**Why first:** self-contained, deterministic, highest trust, no prompt-injection surface — proves
the "grounded gating" approach end-to-end before the LLM-assisted graders build on it.

### 3.3 Business-rule / invariant grader — `verel`

**Catches:** "business rules get ignored."

**How it grounds:** rules are **declared** by humans (a `rules.yaml`, decorators, or property specs)
— e.g. *"an order total always includes tax,"* *"a refund never exceeds the original charge."* Each
declared rule compiles to an **executable property check** (a `hypothesis` property or assertion)
run over the changed code. Declared-by-humans = independent of the agent's diff, like the ticket.

**Gating model:** reuse `GraderKind.CONTRACT` (or add `INVARIANT`), **precise** → gates at `ERROR`
when a rule's property is falsified, with the falsifying example as the issue's `detail_json`.
Shares the generated-check + sandbox + receipt machinery with §3.1.

### 3.4 Over-engineering / scope-creep smell — **`verel` now (seam to `olfel` later)**

**Catches:** "random abstractions for problems nobody was trying to solve."

**Home:** this is eventually the **smell organ `olfel`**'s job (ORGANISM.md: smell = "grades anomalies
/ code smells"; `~/WORKSPACE/olfel` is a skeleton). But per §1.5, `olfel` is **not scheduled**, so
**build it inside `verel` now** as a self-contained module (`verel.senses.smell` or `verel.smell`)
that emits standard verdict-bus Reports — a clean seam so it lifts into `olfel` later unchanged.

**How it grounds:**
- **Deterministic (gating-eligible):** cyclomatic-complexity delta over budget; new indirection
  layers / abstractions **not referenced** outside their own module (speculative generality); dead
  code introduced by the diff; **diff-size vs ticket-size** mismatch (a 1-line ticket, a 12-file
  diff) as a scope-creep signal.
- **Advisory (LLM):** *"this abstraction solves a problem not present in the ticket"* — clamped to
  `WARNING` (it's a judgment), routed through `LLM_JUDGE`.

**Cross-organ:** `olfel` depends on `agentsensory` (the shared contract); its grader plugs into
`verel`'s `premerge_stage` as an optional sense, gating only on the deterministic metrics.

## 4. Verdict-bus integration

All four are **additive** — no change to the gate's core logic, only new specs + (where gating) new
`GraderKind`s registered in `PRECISE_GRADERS`. Stage assembly follows the existing optional-grader
pattern (`pipeline.py: premerge_stage` already does this for `security`/`perf`):

```python
def premerge_stage(repo, *, spec_conformance=None, mutation=False, invariants=None,
                   smell=None, ...):
    ...
    if mutation:                 # §3.2
        graders.append(mutation_spec(repo, covers)); required.add(GraderKind.MUTATION)
    if spec_conformance:         # §3.1 — pass the ticket
        graders.append(spec_conformance_spec(repo, ticket, covers)); required.add(GraderKind.CONTRACT)
    if invariants:               # §3.3
        graders.append(invariant_spec(repo, invariants, covers)); required.add(GraderKind.CONTRACT)
    if smell:                    # §3.4 — olfel sense, gating only on deterministic metrics
        graders.append(smell); required.add(GraderKind.OTHER)
```

- **Gating ones** (mutation, spec-fail, invariant-fail, complexity-over-budget) → `PRECISE_GRADERS`,
  signed receipt, coverage ∩ diff, in `required`. They **fail the merge**.
- **Advisory ones** (unverifiable criteria, "needless abstraction") → `LLM_JUDGE` / `Confidence.LOW`
  → clamped to `WARNING`. They **annotate**, never block.

## 5. Memory — caught misses compound (v0.41.0 brain)

Every confirmed gating miss is a `FailureLedger` entry (`memory/failure_ledger.py`), so:
- a reintroduced spec-miss / surviving-mutant is **blocked from memory** (the regression guard, as in
  the [Try it yourself](try-it.md) walkthrough);
- consolidation (`consolidate_failures`) induces **DesignRules** — e.g. *"changes touching `billing/`
  must assert tax is applied"* — which graduate to `verified` only via the held-out promotion gate.
  The review layer thus **learns the team's recurring intent/business gaps** and pre-empts them.

This is the compounding loop the post's Tech Lead never gets from a stateless LLM reviewer.

## 6. Trust & security (this is attack surface — full security cadence applies)

- **Generated/declared checks EXECUTE code** (§3.1, §3.3). That is the toolsmith's exact threat
  model → run every generated check in the existing **sandbox** (`toolsmith/sandbox.py` `python -I
  -S` + rlimits, or `toolsmith/container.py` bwrap+seccomp). Never `exec` in-process.
- **Prompt-injection surface:** criteria-extraction reads the **ticket** (semi-trusted) and may see
  **code/comments** (untrusted). Treat code as untrusted context; the **execution** is what gates,
  so an injected instruction can't make a failing check pass. Frozen suites (`suite_sha`) + signed
  receipts prevent a tampered check from minting green.
- **Honesty rule:** report *intent coverage* explicitly (criteria grounded vs unverifiable). Never
  let "we couldn't verify it" render as a pass. Unverified criteria are advisory warnings, surfaced.
- Each gating grader gets a **regression-pinned exploit test** (a surviving mutant must FAIL; a
  spec-miss must FAIL; an injected "ignore criteria" must not flip a fail to pass).

## 6.5 Integration — plug into the team's existing stack (plug-and-play, "anywhere with anything")

**Principle:** Verel grades **artifacts** (diffs, renders, tests, receipts), not the agent's
internals — it sits at the *output boundary*, so it is inherently agnostic to which model / host /
framework produced the work. Adoption = exposing that boundary gate through every channel a team
already uses, and pulling context *from* the tools they already run. **Do not ask teams to adopt a
new workflow; insert into theirs.**

**Three integration directions:**

1. **Verel-as-MCP-server (exists — `verel-mcp`).** The agent, in its own host (Claude Code/Desktop,
   Cursor, Cline, Windsurf, Continue, any MCP host), calls `verel_gate` before declaring "done." One
   line in their MCP config. *Enhancement:* ship host config snippets + a `verel mcp install` that
   writes them.
2. **Verel-as-MCP-*client* (NEW) — consume THEIR tools for context.** The §3.1 spec grader needs the
   ticket's acceptance criteria and the diff. **Do not invent a `SPEC.md`** — teams already expose
   these via MCP servers they run (Jira/Linear/Asana = tickets; GitHub/GitLab = PR+diff;
   Notion/Confluence = specs; Figma = design intent). Verel reads the acceptance criteria **from
   wherever the team already keeps them**, riding the host's already-authenticated connections. (This
   is the resolution of §8.2 — the "ticket" is *discovered from their stack*, not a new format.)
3. **Verel-as-gateway/proxy (NEW) — wrap their tools, gate the boundary.** An MCP proxy between the
   agent host and the team's downstream tools. The agent calls its normal tools (`write_file`,
   `create_pr`, `deploy`); Verel intercepts the consequential/irreversible ones, runs the gate on the
   resulting artifact, and forwards only on PASS — else returns the grounded FAIL so the agent
   self-corrects. The agent needn't know Verel exists. This is enforcement that will *eventually* be
   `immel`/`actel`'s job — but **in scope NOW, built inside `verel`** (per §1.5: `immel`/`actel` aren't
   scheduled, and adoption needs it). Build behind a **clean seam** — `verdict` (decide) separate from
   `enforce` (forward/block/rollback) separate from the `action adapters` — so it lifts out to
   `immel`/`actel` later without a rewrite. Honors the non-negotiables from day one: **fail-closed,
   dry-run default, human approval for irreversible/destructive, rollback hooks.**

**Adapter matrix** (the verdict bus + `agentsensory` Report contract are the stable core; each
channel is a thin shim over `dispatch()`/`gate()` — ORGANISM.md already mandates "CLI + MCP + REST +
Skill adapters"):

| Channel | State | Role |
|---|---|---|
| MCP server | have | agent calls the gate |
| MCP client | gap | pull ticket/diff/spec from their existing MCP |
| MCP gateway/proxy | gap | intercept + gate boundary actions (`immel`-adjacent) |
| CLI / pre-commit / GH Action | have | gate in CI |
| REST / PR webhook | gap | language-agnostic; GitHub/GitLab PR → gate → check-run |
| Rules-file snippets (`.cursorrules`/`CLAUDE.md`/`AGENTS.md`/copilot-instructions) | gap | tell *any* agent "call `verel_gate` before done" |
| Agent-SDK shims (Claude Agent SDK, LangGraph, CrewAI, AutoGen, OpenAI Assistants) | gap | one hook into the done-step |
| LLM provider | have-ish | provider-agnostic (Ollama/OpenAI today; add Anthropic + any OpenAI-compatible) so Verel's own LLM-graders run on what the team already pays for |

**Security of the integration surface (full cadence — real attack surface):**
- **MCP-client path ingests untrusted ticket text** → prompt-injection into criteria extraction. The
  grounding principle still holds (the *executed* check gates, never the text), but treat ticket/PR
  text as untrusted and **ride the host's existing auth — do not store new third-party creds**
  (external-service creds, if unavoidable, under `~/.config` per the rule).
- **Gateway path puts Verel in the action path** = `immel`'s threat model → **fail-closed, dry-run by
  default, human approval for irreversible/destructive actions, rollback hooks** (the actel/immel
  non-negotiable). Never a confused deputy that forwards an unverified destructive action.

**Sequencing note:** the MCP-client-for-spec-input (direction 2) is **not extra work** — it is the
*right* way to feed grader §3.1 B, so it lands *with* B. **All channels in the matrix are in scope**
(decided); adoption-friction is the priority, so the lowest-effort/highest-reach channels (rules-file
snippets, `verel mcp install`, REST/PR-webhook) land EARLY to drive adoption, the graders deliver the
visible value, and the gateway (direction 3) is the capstone — built in `verel` behind the extraction
seam (§1.5).

## 7. Recommended phasing (one release per item, full gate + security cadence)

Two interleaved tracks — **Reach** (plug-and-play distribution, the §1.5 adoption priority) and
**Graders** (the visible value). Adoption-friction work is cheap and goes early; the deterministic
grader proves the approach; the headline + gateway follow.

| Phase | Track | Item | Organ | Why here |
|---|---|---|---|---|
| **R0** | Reach | Rules-file snippets (`.cursorrules`/`CLAUDE.md`/`AGENTS.md`/copilot-instructions) + `verel mcp install` (writes host MCP config) | `verel` | Near-zero effort, instant "drop Verel into any agent" — pure adoption |
| **A** | Graders | Test-effectiveness (mutation, diff-scoped) | `verel` | Deterministic, self-contained, no injection surface — proves grounded-gating, ships fast, first "it caught something real" |
| **R1** | Reach | REST / PR-webhook gate (GitHub/GitLab PR → gate → check-run) | `verel` | Language- & host-agnostic; reaches teams not on MCP at all |
| **R2** | Reach | MCP-**client** adapter (GitHub first: PR+diff+linked-issue criteria; then Linear/Jira) | `verel` | Feeds grader B its input — lands WITH B, not extra |
| **B** | Graders | Spec/intent conformance (code) | `verel` | The headline; reuses CONTRACT/receipt + sandbox; ticket via R2; UI criteria → eyes |
| **R3** | Reach | Agent-SDK shims (Claude Agent SDK, LangGraph, CrewAI, AutoGen, OpenAI Assistants) | `verel` | One hook into each framework's done-step |
| **C** | Graders | Business-rule / invariant | `verel` | Shares B's generated-check + sandbox machinery |
| **D** | Graders | Over-engineering / scope-creep smell | `verel` (seam to `olfel`) | olfel not scheduled → built in verel now as a self-contained smell module, lifts to olfel later |
| **G** | Reach | MCP-**gateway/proxy** (intercept + gate boundary actions) — the capstone | `verel` (seam to `immel`/`actel`) | Heaviest security burden; built behind the §1.5 extraction seam, fail-closed/dry-run/human-approval |

Each item: build → gate (lint+types+tests + dogfood verdict) → security cadence (sandbox, injection,
frozen-suite, ≥3 red-team rounds; the gateway adds action-path fail-closed/dry-run/approval) → docs in
lockstep → release. **All items ship in `verel`** for now (per §1.5: `olfel`/`immel`/`actel` unscheduled
→ D and G are built in `verel` behind extraction seams). Order is a recommendation, not a contract —
R0/A can ship in either order; R2 must precede/accompany B.

## 8. Open questions (decide before/while building)

1. **New `GraderKind`s** (`MUTATION`, `SPEC`, `INVARIANT`) vs reusing `CONTRACT`/`TEST`? New kinds
   give cleaner grounding/per-kind config but touch the shared `agentsensory` contract — confirm the
   contract owner. (Leaning: `MUTATION` new + in `PRECISE_GRADERS`; reuse `CONTRACT` for spec/invariant.)
2. **Ticket source — RESOLVED (see §6.5 direction 2):** pull acceptance criteria from the team's
   **existing** issue/spec tools via an MCP-client adapter (Jira/Linear/GitHub/Notion…), discovered
   from the PR's linked issue — not a new `SPEC.md`. Fallback when no MCP source is connected: the PR
   body / a linked issue URL / an explicit MCP arg. Verel rides the host's existing auth.
3. **Mutation tooling:** a built-in minimal AST mutator (zero dep, in base wheel) vs `mutmut`/
   `cosmic-ray` behind a `verel[mutation]` extra. (Leaning: tiny built-in for the diff-scoped common
   case; extra for full runs.)
4. **olfel — RESOLVED (§1.5):** not scheduled → grader D is built **inside `verel`** now as a
   self-contained smell module (`verel.smell` / `verel.senses.smell`) emitting standard verdict-bus
   Reports, behind a seam so it lifts into `olfel` later. No olfel pre-phase needed now.
5. **Cost/latency budget:** spec + mutation add LLM calls and re-runs; keep diff-scoped and cache by
   `inputs_digest`. Gate must stay under the ~10-min CI ceiling (the use-cases.md promise).
6. **Gateway scope — RESOLVED (§1.5):** in scope NOW, built in `verel` behind the verdict/enforce/
   action-adapter seam so it extracts to `immel`/`actel` later. It's the capstone (phase G), after the
   graders + the lower-friction Reach channels, because adoption-first.
7. **Integration priority — RESOLVED:** all four channels in scope. Order: rules-file snippets +
   `verel mcp install` (R0) → REST/PR-webhook (R1) → MCP-client GitHub-first then Linear/Jira (R2) →
   agent-SDK shims (R3) → gateway (G). GitHub is the first MCP-client integration (PR+diff nearly
   universal, and it's grader B's input).
8. **Extraction seam (§1.5):** define the exact module boundary now — e.g. `verel.verdict` (decide)
   vs a new `verel.enforce` (forward/block/rollback) vs `verel.adapters.*` (MCP-client/gateway/REST/
   SDK) — so the later lift to `immel`/`actel` is a package move. Confirm the boundary before G.
