# FAQ & troubleshooting

## What does Verel actually do?

It makes *"done"* a **verdict, not an opinion.** One verdict bus fuses every sense — tests,
lint, types, and the **eyes** (AgentVision: visual defects, intent match, playback) — into a
single `pass / warn / fail`, with grader attestation so a hollow check can't mint green. Only
verified work compounds into memory.

## Do I need an LLM key?

Not for the **gate**. `verel-ci check --repo .` runs tests + lint + types and returns a
verdict with no LLM. A key is only needed for the *agentic* parts — `verel heal`, `fleet`,
the tool-smith — which write code. Default provider is Ollama Cloud; set
`VEREL_LLM_PROVIDER=openai` for OpenAI.

## Does it work on a non-Verel / plain repo?

Yes. `verel-ci check --repo .` runs the standard graders (pytest / ruff / mypy) over any
Python repo and maps them onto the verdict bus. See [Get started](getting-started.md).

## What's the relationship to AgentVision?

[AgentVision](https://amitpatole.github.io/agent-vision/) is the **eyes**; Verel is the
**brain.** Install `verel[sight]` and visual perception (defects, intent conformance, temporal
`watch`) joins the verdict bus as one grounded sense. They version independently but stay in
sync.

## Why didn't a vision finding fail the build?

Trust is per-source: **precise** graders (tests, DOM/OCR/CV) gate; **advisory** ones (the
vision LLM, LLM-judge) are clamped to `warn` and can never trigger a destructive action like a
rollback. That's by design — see [What makes it trustworthy](index.md).

## What are `VEREL_REGISTRY_SECRET` / `VEREL_RUNNER_SECRET`?

Signing secrets (skill-registry artifacts, grader run-receipts). They ship with **dev
defaults** so examples run; set real values in production. See [Configuration](configuration.md).

## How do I gate my CI / commits?

GitHub Action or pre-commit hook — see [Get started](getting-started.md). Exit code is `0`
unless the verdict is `fail`.

## Memory

### Can an agent's hallucination poison the shared memory?

No. An extracted fact enters as `CANDIDATE` (untrusted) and **never graduates** to `VERIFIED`
unless it's (1) **attested** by a signature, or (2) corroborated by **≥2 authenticated** sources.
One agent — or an attacker — repeating a lie N times, or minting N self-asserted source labels,
stays `CANDIDATE`. A value that was ever **rejected** stays un-promotable. See
[Memory in 5 minutes](memory-quickstart.md).

### Is the verel memory like Mem0? Should I switch?

Same *extraction* idea, different *trust* model: Mem0 extracts-and-believes; Verel
extracts-then-verifies. Keep Mem0 for a single agent with a human curator; reach for Verel when a
**fleet** writes memory and a wrong fact would propagate. Honest
[when-to-use comparison + a "coming from Mem0" mapping](comparison.md).

### Does memory work offline / without an LLM key?

Recall is fully offline — `LocalMemory` uses **FTS5 BM25** (a term-weighted keyword ranker, the
default for SQLite/Elasticsearch; matches keywords with no embeddings) plus the trust-aware rank.
Only *extraction* from a raw conversation needs an LLM (the injected `chat`); you can run the
[quickstart](memory-quickstart.md) offline with a fake one. Set `VEREL_EMBEDDER=openai` for
semantic recall (e.g. *"UI overflow"* matching *"text clipped"*).

### Which memory backend should I use?

`local` (SQLite, zero-config) for one process; a shared **hosted** brain (`MemoryServer`/
`RemoteMemory`) or **Postgres**/**Redis**/**LanceDB** for a fleet across machines — all behind the
same `MemoryView`, so the trust layer is identical. See
[Memory backends](memory-backends.md) and [Recipes](recipes.md).

## What is "grader attestation"?

A required grader must present a signed `run_receipt` proving it actually ran the suite over the
changed files. *"I ran the tests and they passed, trust me"* = hollow (fails the gate). *"Here's my
signed receipt for suite X over files [a, b, c]"* = precise and gating. This is what stops an agent
from minting a green check it didn't earn.

## Is the verdict bus a bottleneck?

No. The gate is diff-scoped, parallel graders run concurrently, and slow I/O (e.g. cloud-IAM checks)
is async. Tune scope/timeouts in [Configuration](configuration.md); see per-grader wall times in
[Graders](graders.md).
