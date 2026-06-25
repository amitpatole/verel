# Memory backends

The Verel **brain** (`verel.memory`) is a *trust layer* over a pluggable store. Every backend
implements one `MemoryView` contract, so the entire trust layer — recall ranking, consolidation, the
scope lattice, the promotion gate, replication, lifecycle flags — works **identically whichever store
you pick**. You choose a store; Verel owns the cognition.

Select a backend by name with `VEREL_MEMORY_BACKEND` (no code change); the registry resolves it and
calls its `from_env()` factory. `verel doctor` prints the selected backend and the available names.

```python
from verel.memory import known_backends, load_backend
print(known_backends())     # ['lancedb', 'local', 'postgres', 'redis', 'remote']
brain = load_backend("local")   # honours VEREL_MEMORY_BACKEND / the per-backend env below
```

!!! note "The names are always listed; the *extra* adds the dependency"
    `known_backends()` lists `local`, `remote`, `postgres`, `lancedb`, and `redis` even before you
    install any extra — the name is built in. What `pip install verel[postgres]` (etc.) adds is the
    heavy **driver**; selecting a backend whose driver is missing fails closed with a clear
    `pip install verel[<name>]` hint. Third-party packages can register more names under the
    `verel.memory_backends` entry-point group.

## Which backend? (decision matrix)

| Backend | Name | Install | Writers | ANN recall | Choose it when… |
|---|---|---|---|---|---|
| **SQLite** | `local` | *(core)* | single process | lexical (or via embedder) | a single agent/process; zero infra; the default. |
| **LanceDB** | `lancedb` | `verel[lancedb]` | single process | embedded ANN | you want real vector recall with **no server** — a directory on disk. |
| **Postgres + pgvector** | `postgres` | `verel[postgres]` | **many machines** | pgvector ANN | a fleet on different machines shares **one** verified brain in a real DB. |
| **Redis** | `redis` | `verel[redis]` | **many machines** | client-side (cosine) | a shared brain on infra you already run; works on any Redis. |
| **Hosted HTTP** | `remote` | *(core)* | many machines (one server) | inherits the server's store | you front any store with a `MemoryServer` and share it over HTTP(S) with auth/TLS. |
| **mem0** | *(code only)* | `verel[mem0]` | single process | semantic (vector) | you already run mem0 and want it as the store. **Not** `VEREL_MEMORY_BACKEND`-selectable — see below. |

The trust layer is the same on all of them. The axis that matters is **single-writer vs.
multi-writer** (can several machines write the same brain concurrently and keep the interference
rule correct?) and **embedded vs. networked** (is there a server to run?).

---

## `local` — zero-dependency SQLite (default)

The bundled, dependency-free default. A single SQLite file; the full trust layer; crash-safe (WAL +
`synchronous=FULL`). Single-process — front it with `remote` (below) to share it.

**Install:** nothing extra (ships with `verel`).

**Env:**

| Env var | Default | Purpose |
|---|---|---|
| `VEREL_MEMORY_BACKEND` | `local` | Select this backend. |
| `VEREL_MEMORY_STORE` | `~/.config/verel/brain.db` | SQLite path (`:memory:` for ephemeral). |
| `VEREL_EMBEDDER` | `lexical` | Recall signal — see [Embeddings](#embeddings). |

**Example (runnable, no key):**

```python
from verel.memory import LocalMemory, MemoryRecord, MemoryKind
from verel.memory.view import make_key

mem = LocalMemory()                       # or LocalMemory(":memory:") / a path
mem.write(MemoryRecord(
    kind=MemoryKind.FACT, subject="auth", predicate="uses",
    text="sessions are JWT, 15-min expiry", scope="repo:app",
    subj_pred_key=make_key("auth", "uses", "repo:app")))
for h in mem.recall("how does login work", scope="repo:app", k=3):
    print(h.trust.value, h.text)
```

Or select it by env, code-free:

```bash
export VEREL_MEMORY_BACKEND=local
export VEREL_MEMORY_STORE=~/.config/verel/brain.db
```

**Choose `local`** for a single agent or process, local dev, and tests. It is the zero-config
baseline; reach for another backend only when you need ANN recall (`lancedb`) or a brain shared
across machines (`postgres` / `redis` / `remote`).

---

## `lancedb` — embedded vector store (zero-infra ANN)

An **embedded** columnar/vector store — a directory on disk, no server — so it is the
zero-infrastructure way to get real approximate-nearest-neighbour recall (a vector-native upgrade
over SQLite). With an embedder, recall is ANN over a Lance index; without one it falls back to the
same lexical recall as `local`.

**Install:** `pip install "verel[lancedb]"`

**Env:**

| Env var | Default | Purpose |
|---|---|---|
| `VEREL_MEMORY_BACKEND` | — | Set to `lancedb`. |
| `VEREL_LANCEDB_PATH` | `~/.config/verel/lance` | Dataset directory (created if absent). |
| `VEREL_LANCEDB_TABLE` | `memory` | Table name within the dataset. |
| `VEREL_EMBEDDER` | `lexical` | Set to `hash`/`openai` for ANN — see [Embeddings](#embeddings). |

**Example:**

```bash
pip install "verel[lancedb]"
export VEREL_MEMORY_BACKEND=lancedb
export VEREL_LANCEDB_PATH=~/.config/verel/lance   # a directory
export VEREL_EMBEDDER=hash                          # offline vectors → ANN recall
```

```python
from verel.memory import load_backend, MemoryRecord, MemoryKind
from verel.memory.view import make_key

mem = load_backend("lancedb")             # reads VEREL_LANCEDB_PATH + VEREL_EMBEDDER
mem.write(MemoryRecord(
    kind=MemoryKind.DESIGN_RULE, subject="cards", predicate="rule",
    text="use max-width to prevent overflow on narrow screens", scope="repo:app",
    subj_pred_key=make_key("cards", "rule", "repo:app")))
# with an embedder, this matches by MEANING even with no shared words:
print([h.text for h in mem.recall("panel runs off the screen", scope="repo:app", k=2)])
```

!!! warning "The embedder is fixed per dataset"
    The vector dimension is baked into the dataset at create time, so `VEREL_EMBEDDER` (and the
    model) **must stay the same** for a given `VEREL_LANCEDB_PATH`. Reopening with a different
    embedder **fails closed with a clear error** — point a fresh `VEREL_LANCEDB_PATH` /
    `VEREL_LANCEDB_TABLE` at the new configuration.

**Single-writer**, like `local`: one dataset is owned by one process. For multi-process/multi-machine
sharing, front it with a hosted `MemoryServer` (use the `remote` backend on the clients).

**Choose `lancedb`** when you want semantic recall but don't want to run a database server.

---

## `postgres` — Postgres + pgvector (the flagship multi-machine brain)

An **external, multi-machine** brain: many agents on different machines write directly to one
Postgres, and the trust layer (corroborate / supersede / decay) stays correct under concurrent
writers — every mutation serializes per `(subject, predicate, scope)` key behind a Postgres advisory
lock, and `decay()` is set-based SQL. With an embedder, recall uses pgvector ANN; without one it
falls back to lexical.

**Requires Postgres 16+** (the set-based decay uses the `IS JSON` predicate) with the **pgvector**
extension. Recommended image: `pgvector/pgvector:pg16`.

**Install:** `pip install "verel[postgres]"`

**Env:**

| Env var | Default | Purpose |
|---|---|---|
| `VEREL_MEMORY_BACKEND` | — | Set to `postgres`. |
| `VEREL_POSTGRES_URL` / `VEREL_POSTGRES_DSN` | — | Connection string (URL or keyword DSN). **Required.** |
| `VEREL_PG_SSLMODE` | from DSN | TLS mode. A **routable host is refused** unless `verify-full`/`verify-ca` (fail closed); loopback is exempt. |
| `VEREL_PG_CACERT` | — | CA bundle that signed the server cert (`sslrootcert`), for `verify-full`. |
| `VEREL_EMBEDDER` | `lexical` | `hash`/`openai` → pgvector ANN — see [Embeddings](#embeddings). |

**Example:**

```bash
# one-time: enable the extension in the target database
#   CREATE EXTENSION IF NOT EXISTS vector;
pip install "verel[postgres]"
export VEREL_MEMORY_BACKEND=postgres
export VEREL_POSTGRES_URL="postgresql://user:pw@db.internal:5432/verel?sslmode=verify-full"
export VEREL_PG_CACERT=/etc/ssl/certs/db-ca.pem    # required for a routable host
export VEREL_EMBEDDER=hash                          # optional: ANN recall
```

```python
from verel.memory import load_backend, MemoryRecord, MemoryKind
from verel.memory.view import make_key

brain = load_backend("postgres")          # from_env(): fails closed without a DSN / validating TLS
brain.write(MemoryRecord(
    kind=MemoryKind.FACT, subject="deploy", predicate="via",
    text="deploys go through the pipeline, never manual", scope="team:platform",
    subj_pred_key=make_key("deploy", "via", "team:platform")))
print([h.text for h in brain.recall("how do we deploy", scope="team:platform")])
```

For a local trial, a loopback DSN needs no TLS:
`postgresql://postgres:postgres@127.0.0.1:5432/verel`.

**Security:** the credential is never logged or echoed in an error; all queries are parameterized; a
statement timeout bounds every query; a routable host without validating TLS is refused.

**Choose `postgres`** when several machines share one verified brain and you want it in a real,
operable database with concurrency-correct writes and ANN recall.

---

## `redis` — networked shared brain on plain Redis

A **networked, multi-writer** brain on any Redis: many agents/machines write to one Redis and the
trust layer stays correct under concurrent writers — each mutation is atomic via `WATCH`/`MULTI`
optimistic concurrency with bounded retry. Recall scans the index and ranks in Python (cosine with an
embedder, lexical otherwise). No Redis modules required.

**Install:** `pip install "verel[redis]"`

**Env:**

| Env var | Default | Purpose |
|---|---|---|
| `VEREL_MEMORY_BACKEND` | — | Set to `redis`. |
| `VEREL_REDIS_URL` | — | Connection URL. **Required.** A **routable host must be `rediss://` (validated TLS) with a password** (fail closed); loopback is exempt. |
| `VEREL_REDIS_PREFIX` | `verel` | Key namespace (`{prefix}:mem:*` + `{prefix}:ids`) — lets several brains share one Redis. |
| `VEREL_REDIS_CACERT` | — | CA bundle that signed the server's TLS cert (for `rediss://`). |
| `VEREL_EMBEDDER` | `lexical` | `hash`/`openai` → cosine recall — see [Embeddings](#embeddings). |

**Example:**

```bash
pip install "verel[redis]"
export VEREL_MEMORY_BACKEND=redis
# routable host → rediss:// + AUTH are mandatory:
export VEREL_REDIS_URL="rediss://default:PASSWORD@redis.internal:6379/0"
export VEREL_REDIS_CACERT=/etc/ssl/certs/redis-ca.pem
```

```python
from verel.memory import load_backend, MemoryRecord, MemoryKind
from verel.memory.view import make_key

brain = load_backend("redis")
brain.write(MemoryRecord(
    kind=MemoryKind.FACT, subject="oncall", predicate="policy",
    text="page the owning team first", scope="team:platform",
    subj_pred_key=make_key("oncall", "policy", "team:platform")))
print([h.text for h in brain.recall("who do we page", scope="team:platform")])
```

For a local trial, a loopback URL needs no TLS/AUTH: `redis://127.0.0.1:6379/0`.

**Security:** the URL/password is never logged or echoed; Redis's RESP protocol is injection-safe;
any `ssl*` query param in the URL is refused so TLS config can't be weakened from the URL.

**Choose `redis`** when you already run Redis and want a shared brain on it (vs. `postgres` for a
full DB with native ANN).

---

## `remote` — a hosted brain shared over HTTP(S)

Wrap **any** durable `MemoryView` in a tiny HTTP service (`MemoryServer`) and point a fleet at it
with `RemoteMemory` — a drop-in `MemoryView`, so `lattice_recall`, `graduate`, consolidation, and the
promotion gate all run against the shared store unchanged. The server is the **single writer** (every
access lock-serialized), so the interference rule stays correct with no split-brain.

**Install:** nothing extra (ships with `verel`).

**Env (client side):**

| Env var | Default | Purpose |
|---|---|---|
| `VEREL_MEMORY_BACKEND` | `remote` if `VEREL_BRAIN_URL` set | Select this backend. |
| `VEREL_BRAIN_URL` | — | URL of a `MemoryServer`. **Required.** |
| `VEREL_BRAIN_TOKEN` | — | Bearer token (required for any non-loopback bind). |
| `VEREL_BRAIN_CACERT` | — | CA that signed the server's TLS cert. |
| `VEREL_BRAIN_CLIENT_CERT` / `VEREL_BRAIN_CLIENT_KEY` | — | Client cert/key for mTLS. |
| `VEREL_BRAIN_PIN` | — | Pin the server cert SHA-256 (comma-separated for a set). |
| `VEREL_BRAIN_INSECURE` | `0` | Opt-out letting a token ride a cleartext hop (only behind a TLS-terminating proxy). |
| `VEREL_CLUSTER_TOKEN` | — | Replication-channel credential (cluster ops). |
| `VEREL_PRINCIPAL_SEED` | — | 64 hex chars: the identity that authors *signed* beliefs (multi-principal servers). |

**Example (runnable, no key — loopback server + two clients):**

```python
import tempfile
from verel.memory import MemoryServer, RemoteMemory, MemoryRecord, MemoryKind
from verel.memory.view import make_key

with tempfile.TemporaryDirectory() as d:
    srv = MemoryServer(f"{d}/brain.db", auth_token="team-key").start()   # loopback by default
    try:
        alice = RemoteMemory(srv.url, auth_token="team-key")            # machine 1
        bob   = RemoteMemory(srv.url, auth_token="team-key")            # machine 2
        alice.write(MemoryRecord(
            kind=MemoryKind.FACT, subject="oncall", predicate="policy",
            text="page the owning team first", scope="team:frontend",
            subj_pred_key=make_key("oncall", "policy", "team:frontend")))
        print([r.text for r in bob.recall("who do we page", scope="team:frontend")])
    finally:
        srv.stop()
```

In production, bind a routable host with TLS + a token (a routable bind without a token refuses to
start). On the clients, set the env above and `load_backend("remote")`:

```bash
export VEREL_MEMORY_BACKEND=remote
export VEREL_BRAIN_URL=https://brain.internal:8800
export VEREL_BRAIN_TOKEN=…           # bearer token
export VEREL_BRAIN_CACERT=/etc/ssl/certs/brain-ca.pem
```

```python
srv = MemoryServer("/var/lib/verel/brain.db", host="0.0.0.0", port=8800,
                   auth_token="…", certfile="server.crt", keyfile="server.key").start()
```

**Choose `remote`** to share one brain across machines while keeping the *store* you like (the server
can wrap `local`, or you can pass any `MemoryView` as `store=`).

---

## mem0 — the rented store (code-construction only)

mem0 is the optional rented backend behind the same `MemoryView` Protocol. Verel does **not** use
mem0's LLM auto-extraction (`infer=False`) — mem0 is pure storage + vector recall; Verel keeps its
own gated consolidation and its documented `rank()`. Because Ollama Cloud serves no embeddings
endpoint, mem0's vector recall uses an **OpenAI** embedder, so it needs an OpenAI key; the default
vector store is a local Chroma directory.

!!! note "mem0 is not `VEREL_MEMORY_BACKEND`-selectable"
    Unlike the backends above, mem0 has **no registry name** — `VEREL_MEMORY_BACKEND=mem0` is not
    valid. Construct it in code with `make_ollama_mem0()` (or `Mem0Memory(client)` against your own
    configured mem0 client).

**Install:** `pip install "verel[mem0]"` (pulls `mem0ai` + `chromadb`). Set `OPENAI_API_KEY` (or
`~/.config/OpenAI/key`) for the embedder.

**Example:**

```python
from verel.memory import make_ollama_mem0, MemoryRecord, MemoryKind   # needs verel[mem0]
from verel.memory.view import make_key

mem = make_ollama_mem0()                  # infer=False; OpenAI embedder; local Chroma store
mem.write(MemoryRecord(
    kind=MemoryKind.FACT, subject="auth", predicate="uses",
    text="sessions are JWT, 15-min expiry", scope="repo:app",
    subj_pred_key=make_key("auth", "uses", "repo:app")))
print([h.text for h in mem.recall("login session model", scope="repo:app")])
```

**Choose mem0** only if you already standardize on it. For embedded semantic recall without an
OpenAI dependency, `lancedb` with `VEREL_EMBEDDER=hash` is usually the simpler choice.

---

## Embeddings (`VEREL_EMBEDDER`)

The recall relevance signal is configured **once**, the same way for every backend. Without an
embedder, recall is lexical token-overlap (zero-config, and the only option that works with Ollama,
which serves no embeddings endpoint). With one, recall ranks by cosine similarity of dense vectors —
so *"the panel runs off the screen"* matches a rule about *"overflow"* with no shared words.

| Env var | Default | Purpose |
|---|---|---|
| `VEREL_EMBEDDER` | `lexical` | `none`/`lexical` (token overlap), `hash` (offline, dependency-free vectors — surface overlap, **not** meaning), or `openai` (real semantic vectors). Unknown values fail closed. |
| `VEREL_EMBED_MODEL` | `text-embedding-3-small` | OpenAI embedding model when `VEREL_EMBEDDER=openai` (e.g. `text-embedding-3-large`). |
| `VEREL_EMBED_DIM` | model native | Override the vector width for an unknown model or a truncated-dimensions deployment. |

The `openai` embedder resolves its key from `OPENAI_API_KEY`, else `~/.config/OpenAI/key`. Its `.dim`
must match what the model returns (1536 for `-3-small`, 3072 for `-3-large`); a fixed-dim store
(LanceDB / pgvector) bakes that width in, so don't change the model/dim under an existing dataset.

```bash
export VEREL_EMBEDDER=openai
export VEREL_EMBED_MODEL=text-embedding-3-small
export OPENAI_API_KEY=sk-…
```

---

## Trust-layer features (the same on every backend)

Whichever store you select, the cognition is Verel's and is identical. The pieces:

### Lifecycle flags — pin / volatile / TTL / correction chains / adaptive decay

Each record carries **two orthogonal quantities**: `epistemic_confidence` (belief — moved *only* by
`corroborate`/`contradict`) and `retrieval_strength` (reachability — decays with disuse, resets on
recall). Lifecycle controls keep the brain from becoming a junk drawer:

```python
from verel.memory import LocalMemory, MemoryRecord, MemoryKind, correction_chain
from verel.memory.view import make_key

mem = LocalMemory()
r = mem.write(MemoryRecord(kind=MemoryKind.FACT, subject="branch", predicate="is",
    text="current branch is feature/x", scope="repo:app",
    subj_pred_key=make_key("branch", "is", "repo:app")))

mem.pin(r.id)                              # exempt from decay + prune forever
mem.unpin(r.id)
mem.set_flags(r.id, volatile=True)         # volatile-until-confirmed: expires if never corroborated
mem.set_flags(r.id, ttl_s=3600)            # hard TTL for an ephemeral env fact (1 hour)

# correction chain: writing a new value for the SAME (subject, predicate, scope) supersedes,
# keeping the prior values queryable rather than overwriting them.
mem.write(MemoryRecord(kind=MemoryKind.FACT, subject="branch", predicate="is",
    text="current branch is main", scope="repo:app",
    subj_pred_key=make_key("branch", "is", "repo:app")))
print([c["text"] for c in correction_chain(mem.get(r.id))])   # ['current branch is feature/x']

mem.decay(half_life_s=604800.0, now=...)   # power-law decay + prune what the rule allows
```

Decay is **adaptive**: a record's effective half-life stretches with demonstrated usefulness
(`support_count` + `epistemic_confidence`) up to 6×, so a corroborated, believed memory persists much
longer than a weak one-off. Decay never touches truth. A record is pruned **only** when *all* hold:
`retrieval_strength < 0.15` and `epistemic_confidence < 0.4` and `support_count < 2` and `trust !=
verified` — and never if pinned. Defaults: volatile TTL 1 day, staleness flag after 30 days.

### Consolidation & the librarian (the brain's "sleep")

Recurring failures consolidate into candidate, structured `DesignRule`s (`condition → action`),
those into a multi-hop **schema hierarchy**, and a pattern recurring across repos into a `global`
rule. The `librarian_pass` runs the whole gated upkeep cycle — consolidate, induce, graduate, prune —
and never *mints* trust (everything it writes is a candidate):

```python
from verel.memory import consolidate_failures, induce_hierarchy, librarian_pass

rules  = consolidate_failures(mem, scope="repo:app", min_cluster=2)   # → candidate DesignRules
levels = induce_hierarchy(mem, scope="repo:app", min_size=2)          # → order-2/3 principles
report = librarian_pass(mem, scope="repo:app", children=["repo:a", "repo:b"])
print(report.summary())   # "librarian[repo:app]: +N rules, +N schemas, +N graduated, -N pruned"
```

### The scope lattice — `self → team → org → global` shared brain

A memory's `scope` places it in a hierarchy. **Resolve down:** `lattice_recall` surfaces what self,
team, and org know at once, the most specific scope winning ties. **Graduate up:** a belief
independently *verified* across sibling scopes becomes a parent-level **candidate** that must re-earn
`verified`.

```python
from verel.memory import ScopeLattice, lattice_recall, graduate, Trust

lat = ScopeLattice({"repo:a": "team:f", "repo:b": "team:f", "team:f": "global"})
hits = lattice_recall(mem, "logging policy", scope="repo:a", lattice=lat, k=4)   # self + team + org
grad = graduate(mem, parent="team:f", children=["repo:a", "repo:b"], min_scopes=2)  # verified-in-both → team candidate
```

### The promotion gate — trust is earned, never asserted

A candidate reaches `verified` **only** by passing a held-out, agent-inaccessible eval (with a
leakage canary) carrying a signed run-receipt:

```python
from verel.memory import PromotionGate, HeldOutCorpus, EvalCase

corpus = HeldOutCorpus([
    EvalCase(text="a card overflows the viewport on a 320px screen",
             covers_kind="overflow", label="prevent"),   # "prevent" | "allow"
    EvalCase(text="the layout is fine on desktop", covers_kind="overflow", label="allow"),
])
result = PromotionGate(mem, corpus).consider(rule)        # rule: a candidate DesignRule
print(result.promoted, round(result.f1, 2), result.reason)
```

### Cross-agent trust — sharing safely

On a shared (`remote`) brain, a peer's belief enters as a **candidate** and **re-verifies before it's
trusted** (`import_belief`), and **author reputation** (`AuthorTrust`, stored in the brain itself)
means a noisy agent's claims need more corroboration — one bad actor can't poison the swarm. On a
multi-principal `MemoryServer`, authored writes are **signed** (`remember_signed`); a bare bearer
token can't forge authorship or trust.

### Replication / HA — no single point of failure

For high availability, `ReplicatedMemory` runs the store as a **leader-fenced** cluster: one leader
at a time, mutations replicate verbatim to followers (a dead follower can't block writes; a
`write_quorum` sets durability), a deposed leader is fenced out (no split-brain), and a lagging node
self-heals via the background `AntiEntropy` reconciler. Reads are local/eventual by default,
`read_consistency="strong"` (route to the leader) for read-your-writes, or `"quorum"` — versioned
records let a point read poll replicas and return the freshest, so a read **survives the leader being
down**.

```python
from verel.fleet import InMemoryLeaseStore          # or SqliteLeaseStore / the HTTP control plane
from verel.memory import ReplicatedMemory, LocalMemory, AntiEntropy

leases = InMemoryLeaseStore()
follower = ReplicatedMemory(LocalMemory(), leases=leases, cluster_key="brain", owner="B")
leader   = ReplicatedMemory(LocalMemory(), leases=leases, cluster_key="brain", owner="A",
                            peers=[follower], write_quorum=1)
```

A full runnable walkthrough (resolve-down, graduate-up, cross-agent trust, the librarian, hosted, and
the HA cluster with failover + quorum reads) is in
[`examples/demo_shared_brain.py`](https://github.com/amitpatole/verel/tree/main/examples/demo_shared_brain.py):

```bash
python examples/demo_shared_brain.py
```

### From an MCP host

`verel-mcp` exposes the brain to any MCP host: **`verel_recall`** reads the shared verified brain
(resolving *down* the scope lattice) and surfaces trust/confidence/provenance; **`verel_remember`**
writes — and *trust does not travel*, so a claim enters as a candidate (the caller's self-asserted
trust is ignored) until it earns `verified` via a fact-bound attestation or the held-out gate.

---

See also [Configuration → Memory backend](configuration.md#memory-backend) for the full env-var
reference and [Architecture → The Brain](ARCHITECTURE.md#the-brain) for the design rationale.