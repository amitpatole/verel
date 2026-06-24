# Security residuals (internal)

Known security findings that are **not yet closed in code**, why, and when to recheck. Internal — NOT
in the public mkdocs nav. Process: a residual is either (a) deferred-by-design to a scoped follow-up,
or (b) unfixable at Verel's layer (upstream dependency / OS) — in which case, if upstream is open
source, we open an issue + PR and shepherd it to merge. Recheck on the date and close when fixed.

| ID | Finding | Severity | Why open | Plan | Recheck |
|----|---------|----------|----------|------|---------|
| R-001 | Hosted `/all` returns the whole table to any bearer-authenticated peer (no row limit, no scope-confidentiality, memory-amplification). `MemoryServer` handler in `src/verel/memory/hosted.py` (`/all` in `_SIGNED_MODE_POST`). Surfaced by the v0.49.0 Postgres red-team but is **cross-backend** (affects `local`/`remote`/`postgres` alike — it is the HTTP layer, not the pg store). | Low | Deferred-by-design: the correct fix (require the **cluster credential** for `/all`, or add a server-side `LIMIT` + keyset-pagination cursor) is a `hosted.py` change that also touches `RemoteMemory.all()` callers (the scope lattice, consolidation, anti-entropy). Rushing it into the pg-backend release risks breaking fleet replication. The pg backend's own `all()` is correctly an admin/diagnostic method; `recall()` (the agent-facing hot path) **is** bounded (k clamped + `LIMIT`). | Dedicated `hosted.py` hardening pass: gate `/all` behind cluster auth and/or paginate it, with regression tests that the lattice/consolidation paths still work. Not unfixable — scoped follow-up, ours. | 2026-06-27 |

## Closed

_(none yet)_
