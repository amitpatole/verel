"""Shared team brain — the scope lattice (§5), offline.

Knowledge lives in a hierarchy of scopes: a repo sits under a team, under an org, under `global`.
Two moves turn that into a shared brain:

  RESOLVE DOWN — an agent recalls across self + team + org at once; the most specific scope wins
  ties, so a repo override beats the team default, but the team's knowledge is still in view.

  GRADUATE UP — a belief independently verified in several sibling repos is promoted to a team-level
  CANDIDATE: collective knowledge no single agent decreed, which must re-earn `verified` at the top.

No key, no infra — pure logic over any MemoryView.  Run:  python examples/demo_shared_brain.py
"""

from __future__ import annotations

from verel.memory import (
    LocalMemory,
    MemoryKind,
    MemoryRecord,
    ScopeLattice,
    Trust,
    graduate,
    lattice_recall,
)
from verel.memory.view import make_key


def fact(subj: str, text: str, scope: str, trust: Trust = Trust.VERIFIED) -> MemoryRecord:
    return MemoryRecord(kind=MemoryKind.FACT, subject=subj, predicate="rule", text=text,
                        scope=scope, trust=trust, epistemic_confidence=0.8,
                        subj_pred_key=make_key(subj, "rule", scope))


def main() -> None:
    mem = LocalMemory()
    lat = ScopeLattice({
        "repo:web-app": "team:frontend", "repo:billing": "team:frontend",
        "team:frontend": "org:acme", "org:acme": "global",
    })

    # org-wide convention, a team default, and a repo-specific override on the same topic
    mem.write(fact("review", "every change needs review", "org:acme"))
    mem.write(fact("review", "two approvals required", "team:frontend"))
    mem.write(fact("review", "two approvals required", "repo:web-app"))   # repo agrees with team
    mem.write(fact("secrets", "secrets only from the vault", "org:acme"))

    print("RESOLVE DOWN — an agent in repo:web-app recalls 'review approvals & secrets':")
    for r in lattice_recall(mem, "review approvals and secrets policy",
                            scope="repo:web-app", lattice=lat, k=4):
        print(f"  [{r.scope:14}] {r.text!r}")

    # both frontend repos independently verified the same logging rule
    mem.write(fact("logging", "emit structured JSON logs", "repo:web-app"))
    mem.write(fact("logging", "emit structured JSON logs", "repo:billing"))
    # ...and a one-repo quirk that should stay local
    mem.write(fact("style", "prefer tabs", "repo:web-app"))

    print("\nGRADUATE UP — promote what's verified across the team's repos:")
    grad = graduate(mem, parent="team:frontend",
                    children=["repo:web-app", "repo:billing"], min_scopes=2)
    for g in grad:
        print(f"  → {g.scope}: {g.text!r}  (trust={g.trust.value}, from {g.detail['graduated_from']})")
    promoted = {g.subject for g in grad}
    print(f"  stayed local (only one repo): {'style' if 'style' not in promoted else '—'}")

    print("\nThe graduated belief is a team CANDIDATE — collective, but it still has to re-earn")
    print("`verified` at the team level via the held-out promotion gate. Trust is never decreed.")

    _hosted()


def _hosted() -> None:
    """The same brain, but shared across a fleet over HTTP — agents on different machines."""
    import tempfile

    from verel.memory import MemoryServer, RemoteMemory

    print("\n── Hosted: a fleet shares ONE brain over HTTP ──")
    with tempfile.TemporaryDirectory() as d:
        srv = MemoryServer(f"{d}/brain.db", auth_token="team-key").start()
        try:
            alice = RemoteMemory(srv.url, auth_token="team-key")   # agent on machine 1
            bob = RemoteMemory(srv.url, auth_token="team-key")     # agent on machine 2
            alice.write(fact("oncall", "page the owning team first", "team:frontend"))
            seen = bob.recall("who do we page on call", scope="team:frontend")
            print(f"  Alice writes → Bob ({srv.url}) recalls: {[r.text for r in seen]}")
            print("  RemoteMemory is a drop-in MemoryView — lattice_recall, graduate, the promotion")
            print("  gate, and consolidation all work against the shared store unchanged.")
        finally:
            srv.stop()


if __name__ == "__main__":
    main()
