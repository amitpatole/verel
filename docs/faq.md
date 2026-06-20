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
