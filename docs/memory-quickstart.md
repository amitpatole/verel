# Memory in 5 minutes

Verel extracts facts from a conversation like Mem0/Engram — but a fact **only compounds after it's
graded**. A one-off, a hallucination, or an attacker repeating a lie stays a `CANDIDATE` and is never
trusted; a fact becomes `VERIFIED` only when it's **attested** (a signed receipt) or corroborated by
**≥2 authenticated sources**. That's the whole difference: *extract-then-verify* vs *extract-and-believe*.

> New here for the memory and nothing else? You're in the right place — this page is standalone. The
> rest of Verel (the verdict bus, fleets, eyes) is the *depth*, not a prerequisite.

## Install

```bash
pip install verel        # the memory layer is in the base package — no extras, no API key
```

## Extract → grade → recall (offline, no key)

The LLM extractor is **injected** as a `chat` callable, so you can run the whole thing offline with a
fake one (in production you pass your real LLM). Copy-paste this:

```python
import json
from verel.memory import LocalMemory, remember_conversation, recall_budgeted
from verel.memory.view import make_id, make_key

mem = LocalMemory()                       # zero-config SQLite (":memory:" by default)

# A stand-in LLM extractor: returns the SPO facts a real model would propose.
def fake_chat(facts):
    return lambda _messages: json.dumps([{"subject": s, "predicate": p, "object": o} for s, p, o in facts])

def trust(subject, predicate, scope):
    rec = mem.get(make_id(make_key(subject, predicate, scope)))
    return rec.trust.value if rec else "—"

# 1) Extract from a conversation — facts enter as CANDIDATE (not trusted).
remember_conversation(mem, "I'm Dana and I prefer dark mode.", scope="user:dana",
                      chat=fake_chat([("Dana", "prefers", "dark mode")]))
print("after one say-so:", trust("Dana", "prefers", "user:dana"))      # candidate

# 2) A SECOND authenticated source corroborates → it graduates to VERIFIED.
#    `authenticate` maps a source label to a verified principal id (in prod: validate a token, not echo it).
auth = {"session-A": "alice", "session-B": "bob"}.get
for src in ("session-A", "session-B"):
    remember_conversation(mem, "(later) Dana: still dark mode", scope="user:dana", source=src,
                          chat=fake_chat([("Dana", "prefers", "dark mode")]), authenticate=auth)
print("after 2 authenticated sources:", trust("Dana", "prefers", "user:dana"))   # verified

# 3) Recall — token-budgeted, graded-first, fenced as untrusted DATA.
ctx = recall_budgeted(mem, "Dana preferences", scope="user:dana", token_budget=200)
print(ctx.text)            # a <recalled_memory> block; verified facts rank first
print(ctx.used_tokens, "tokens,", ctx.dropped, "dropped")
```

Run the full narrated version (hallucination stays candidate, a correction supersedes, budgeted recall):

```bash
python -m pip install verel
python -c "import urllib.request; print(urllib.request.urlopen('https://raw.githubusercontent.com/amitpatole/verel/main/examples/demo_memory.py').read().decode())" > demo_memory.py
python demo_memory.py     # offline, no API key
```

## What you just got (that a plain memory store doesn't)

- **Graded trust** — `Trust.CANDIDATE → VERIFIED` only via attestation or ≥2 *authenticated* principals.
  Raw repetition never promotes, so one agent (or attacker) can't poison a shared brain.
- **Graded-first recall** — `recall_budgeted` ranks a `VERIFIED` fact above an equally-relevant
  `CANDIDATE` (BM25 relevance + a trust term), fits a token budget, and **fences** the result as
  untrusted DATA so a stored note can't smuggle an instruction into your prompt (a second-order
  prompt-injection defense).
- **Corrections, not overwrites** — a changed value *supersedes* the old one with a queryable
  correction chain; a value that was ever **rejected** stays un-promotable.
- **Lower token bill** — budgeted, graded-first recall means you stop replaying the whole brain into
  every prompt. Measured: a 40-fact brain drops from **679 → 135 tokens/turn (80% less)** at a 100-token
  budget, hallucinations excluded. See the [cost breakdown](comparison.md#cost-what-graded-budgeted-recall-saves)
  and run `python examples/demo_token_savings.py`.

## Use your real LLM

Drop the fake — pass any `chat` callable that takes a list of `{role, content}` messages and returns a
string. Verel's default (`from verel.ci.spec import default_chat`) resolves the provider from env
(Ollama Cloud or OpenAI); or wire your own:

```python
def my_llm(messages):
    return my_provider.complete(messages)        # returns the model's text
remember_conversation(mem, transcript, scope="user:dana", chat=my_llm)
```

The LLM only **proposes**; the grade gate decides what's trusted — so a flaky or jailbroken extractor
can't mint trusted memory.

## Where next

- **[Verel memory vs Mem0 / Engram / Zep](comparison.md)** — when to use which, and a "coming from Mem0" mapping.
- **[Memory backends](memory-backends.md)** — Postgres / Redis / LanceDB / a shared hosted brain, the
  scope lattice (`self → team → org → global`), consolidation, and HA replication.
- **[From an MCP host](memory-backends.md#conversational-memory)** — `verel_remember_conversation` +
  a budgeted `verel_recall`, so an agent extracts, grades, and recalls through its MCP tools.
