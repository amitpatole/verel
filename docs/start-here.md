# Start here

> **Verel is the framework where nothing is "done" until a grader returns a verdict.** An agent (or a
> human) does some work; a *grader* checks it and emits a signed `pass` / `warn` / `fail`; only verified
> work is allowed to compound. This page gets you from zero to your first verdict in about two minutes.

## What problem it solves

An LLM agent that grades its own work is both author and reviewer — so "done" means nothing. Verel makes
"done" a **verdict from a real check, not a claim**: deterministic graders (tests, types, lint, security,
telecom config/KPIs, IaC, …) each return an `agentsensory.Report` = *verdict + grounded issues + a signed
receipt*. A report that says `pass` with no receipt of a grader actually running **fails the gate** — you
cannot claim success without evidence.

## Install + first verdict (no API key needed)

The graders are deterministic and offline — grading needs **no LLM and no key**. Install the dev graders
and check a repo:

```bash
pip install "verel[dev]"      # core + the pytest / ruff / mypy graders
verel doctor                  # sanity-check your environment (what's installed, what's missing)
verel-ci check --repo .       # grade this repo → one signed verdict
```

`verel-ci check` runs the graders over your repo and prints a `pass` / `warn` / `fail` with grounded
issues. Each grader's result is bound into a signed receipt (see the [trust model](trust-model.md)) — the
gate rejects a "hollow" pass that has no receipt behind it.

## The one idea

- **Precise graders gate.** Tests / types / lint / security / telecom-config / KPI / IaC failures are
  deterministic evidence → they can `fail` the build.
- **Advisory graders never fail.** Open-ended model judgment (vision, LLM-as-judge) is clamped to
  `warn` — it can inform, never block.
- **A verdict without a receipt is not a pass.** Missing grader, or a grader with no signed receipt → the
  gate fails closed.

That's the whole contract. Everything else — memory that only compounds verified work, a fleet, the
senses (eyes/ears), the telecom and IaC grader tracks, the act-then-verify actuators — is built on it.

## Where to go next

| You want to… | Go to |
|---|---|
| A hands-on 5-minute walkthrough | [5-minute tutorial](tutorial.md) |
| Run it against your own repo | [Try it yourself](try-it.md) |
| Pick the right install for your use case | [Install & extras](install-extras.md) |
| Understand what's cryptographically guaranteed | [Trust model](trust-model.md) |
| Give an agent trusted, compounding memory | [Memory in 5 minutes](memory-quickstart.md) |
| Gate 5G RAN/Core changes | [Telecom RAN / 5G Core](use-cases-telecom.md) |
| Gate Terraform / cloud-IAM / K8s | [SRE / Platform / Cloud](use-cases-infra.md) |

> Agentic features that *write* code (e.g. `verel heal --repo .`, which fixes a red build and re-grades
> until green) need an LLM configured — Ollama by default, or `VEREL_LLM_PROVIDER=openai`. Grading itself
> never does.
