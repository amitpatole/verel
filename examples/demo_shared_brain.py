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

    _cross_agent_trust()
    _librarian()
    _hosted()
    _replicated_ha()


def _replicated_ha() -> None:
    """High availability: a leader-fenced, fault-tolerant cluster — no SPOF, no split-brain."""
    from verel.fleet import InMemoryLeaseStore
    from verel.memory import ReplicatedMemory

    print("\n── Replicated HA: leader-fenced, fault-tolerant, no split-brain ──")
    leases = InMemoryLeaseStore()       # the control plane in production
    clk = {"t": 0.0}

    class DownFollower:                  # a peer that's currently unreachable
        def apply_replica_fenced(self, record, token):
            raise ConnectionError("follower down")

    b = ReplicatedMemory(LocalMemory(), leases=leases, cluster_key="brain", owner="B",
                         ttl=10, clock=lambda: clk["t"])
    a = ReplicatedMemory(LocalMemory(), leases=leases, cluster_key="brain", owner="A",
                         peers=[b, DownFollower()], ttl=10, clock=lambda: clk["t"])

    a.write(fact("deploy", "via the pipeline", "team:frontend"))
    print(f"  leader A wrote despite a dead follower — status {a.replication_status()}")
    print(f"  healthy follower B has the replica: {[r.text for r in b.all(scope='team:frontend')]}")

    clk["t"] = 100.0                     # A's lease lapses → B takes over
    b.peers = [a]
    b.write(fact("oncall", "page owner", "team:frontend"))
    print(f"  failover: B is now leader (token {leases.current_token('brain')}); A is fenced out.")
    try:
        a.write(fact("x", "stale", "team:frontend"))
    except Exception as e:               # noqa: BLE001
        print(f"  deposed leader A refused: {type(e).__name__} — no split-brain.")


def _librarian() -> None:
    """The maintenance cycle that keeps the brain compounding — consolidate, graduate, prune."""
    from verel.memory import librarian_pass

    print("\n── Librarian: the gated upkeep pass (the brain's 'sleep') ──")
    mem = LocalMemory()

    def overflow(text, scope="repo:web-app"):
        return MemoryRecord(kind=MemoryKind.FAILURE, subject=text[:10], predicate="f", text=text,
                            scope=scope, subj_pred_key=make_key(text + scope, "f", scope)).with_detail(kind="overflow")

    def junk(subj):
        return MemoryRecord(kind=MemoryKind.FACT, subject=subj, predicate="p", text="ephemeral note",
                            scope="repo:web-app", trust=Trust.CANDIDATE, epistemic_confidence=0.3,
                            retrieval_strength=0.1, support_count=1, created_ts=0.0,
                            subj_pred_key=make_key(subj, "p", "repo:web-app"))

    mem.write(overflow("card overflows the viewport"))
    mem.write(overflow("panel overflows on mobile"))      # recurring → consolidate into a rule
    mem.write(junk("scratch1")); mem.write(junk("scratch2"))   # stale → prune

    stub = lambda m: '{"subject":"cards","condition":"fixed px width","action":"use max-width","applies_to":"narrow"}'  # noqa: E731
    rep = librarian_pass(mem, scope="repo:web-app", chat=stub, half_life_s=1.0, now=10**9)
    print(f"  {rep.summary()}")
    print("  Nothing was decreed: consolidated rules enter as candidates (face the promotion gate),")
    print("  and prune only drops what the §5 rule allows — never verified or pinned memories.")


def _cross_agent_trust() -> None:
    """Sharing safely: a peer's belief re-verifies before it's trusted, and authors earn reputation."""
    from verel.memory import AuthorTrust, import_belief

    print("\n── Cross-agent trust: trust does not travel; authors earn reputation ──")
    mem = LocalMemory()
    rep = AuthorTrust(mem)

    def claim(text, author):
        return MemoryRecord(kind=MemoryKind.FACT, subject=text[:8], predicate="rule", text=text,
                            scope="team:frontend", trust=Trust.VERIFIED, epistemic_confidence=0.99,
                            subj_pred_key=make_key(text[:8], "rule", "team:frontend")).with_detail(author=author)

    # a peer asserts VERIFIED + 0.99 — but it only counts if MY check agrees
    good = import_belief(mem, claim("retry transient errors 3x", "agent-A"),
                         verify=lambda r: True, author_trust=rep)
    bad = import_belief(mem, claim("disable all timeouts", "agent-B"),
                        verify=lambda r: False, author_trust=rep)
    print(f"  agent-A's belief (my check passes): {'VERIFIED locally' if good.reverified else 'candidate'}")
    print(f"  agent-B's belief (my check fails):  {'verified' if bad.reverified else 'stayed CANDIDATE — trust did not travel'}")

    # reputation accrues: a steady contributor vs a noisy one
    for _ in range(9):
        import_belief(mem, claim("solid rule", "agent-A"), verify=lambda r: True, author_trust=rep)
    for i in range(9):
        import_belief(mem, claim("shaky rule", "agent-B"),
                      verify=lambda r, i=i: i % 3 == 0, author_trust=rep)
    print(f"  reputations → agent-A prior={rep.prior('agent-A'):.2f} {rep.standing('agent-A')}, "
          f"agent-B prior={rep.prior('agent-B'):.2f} {rep.standing('agent-B')}")
    print("  → a new claim from agent-A starts more believed; agent-B's needs more corroboration.")


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
