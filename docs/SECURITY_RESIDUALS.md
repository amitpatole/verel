# Security residuals (internal)

Known security findings that are **not yet closed in code**, why, and when to recheck. Internal — NOT
in the public mkdocs nav. Process: a residual is either (a) deferred-by-design to a scoped follow-up,
or (b) unfixable at Verel's layer (upstream dependency / OS) — in which case, if upstream is open
source, we open an issue + PR and shepherd it to merge. Recheck on the date and close when fixed.

_(none open)_

## Closed

| ID | Finding | Severity | Resolution |
|----|---------|----------|------------|
| R-001 | Hosted `/all` returned the whole brain to any bearer-authenticated peer (cross-backend HTTP layer in `src/verel/memory/hosted.py`). | Low | **Fixed in v0.51.1.** In signed-writes mode an **unscoped** `/all` (full-brain dump of every scope/principal) requires the **cluster credential** (`X-Cluster-Token`); a **scoped** `/all` stays a normal bearer read (the scope-lattice recall + consolidation use it, and a client could already `/recall` that scope). Legacy single-trust mode unchanged. Pinned by `test_signed_mode_unscoped_all_requires_cluster_credential`; a focused adversarial review ran live coercion exploits (empty/null/wildcard/list scope) and confirmed the boundary holds (all backends use exact-match scope equality; gate and sink read the same value → no parse differential). |
