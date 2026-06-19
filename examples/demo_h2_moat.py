"""H2 — the corpus-transfer experiment that DECIDES the moat (§8.7).

The design's biggest feasibility bet: the public Skill Registry is only a moat if verified
skills transfer across tenants. So we measure it instead of assuming it. Tenant A builds
skills (Ollama Cloud); we export them as signed artifacts; then we try to RE-VERIFY each one
against tenants B and C — who each have their OWN held-out cases. A universal skill re-earns
`verified` everywhere; a tenant-specific one doesn't. The measured rate prints the verdict.

Run:  python examples/demo_h2_moat.py     (needs ~/.config/ollama/key)
"""

from __future__ import annotations

from verel.agents.llm import have_key
from verel.memory import LocalMemory
from verel.registry import export_skill, measure_transfer
from verel.toolsmith import ToolCase, ToolRegistry, ToolSmith, ToolSpec

# Tenant A's skills. `slugify` is universal; `tax_total` encodes A's tax rate (8%) — a
# tenant-specific rule that should NOT transfer to tenants with different rates.
A_SPECS = [
    ToolSpec(name="slugify", capability="convert a title to a url slug",
             signature_hint="slugify(text: str) -> str (lowercase, non-alphanumerics to single '-', trim '-')",
             cases=[ToolCase(args=["Hello World"], expected="hello-world"),
                    ToolCase(args=["Verel Rocks"], expected="verel-rocks")]),
    ToolSpec(name="tax_total", capability="add 8 percent sales tax to a price, round to 2dp",
             signature_hint="tax_total(price: float) -> float",
             cases=[ToolCase(args=[100.0], expected=108.0), ToolCase(args=[50.0], expected=54.0)]),
]


def main() -> int:
    if not have_key():
        print("SKIP: no Ollama Cloud key (~/.config/ollama/key).")
        return 0

    # 1) Tenant A builds + verifies its skills with the tool-smith.
    reg_a = ToolRegistry(LocalMemory(), scope="tenant:A")
    smith = ToolSmith(reg_a, sandbox=True)
    artifacts = []
    print("── Tenant A builds skills (Ollama Cloud, sandboxed eval) ──")
    for spec in A_SPECS:
        res = smith.build(spec)
        print(f"  {spec.name}: {res.trust.value if res.trust else 'unbuilt'} ({res.reason})")
        if res.tool and res.trust and res.trust.value == "verified":
            artifacts.append(export_skill(res.tool, origin="tenant:A"))

    # 2) Tenants B and C have their OWN held-out cases. B is also 8% tax; C is 10%.
    targets = {
        "B": {"slugify": [ToolCase(args=["Big News"], expected="big-news")],
              "tax_total": [ToolCase(args=[200.0], expected=216.0)]},          # 8% — matches A
        "C": {"slugify": [ToolCase(args=["Hello There"], expected="hello-there")],
              "tax_total": [ToolCase(args=[100.0], expected=110.0)]},          # 10% — differs from A
    }

    print("\n── Measuring cross-tenant transfer (re-verify against each tenant's corpus) ──")
    report = measure_transfer(artifacts, targets, sandbox=True, log=print)

    print(f"\n  transfer rate: {report.transferred}/{report.attempts} = {report.rate:.0%}")
    rates = report.per_skill_rate()
    for skill, r in rates.items():
        kind = "universal" if r == 1.0 else ("tenant-specific" if r < 0.5 else "partial")
        print(f"  per-skill: {skill} {r:.0%} ({kind})")
    print(f"  MOAT DECISION: {report.decision}")
    print("\nInterpretation: skills that re-verify everywhere are fungible (a real network "
          "effect); skills that re-verify only where the tenant's rules happen to match are "
          "lock-in, not a moat. §8.7 says measure THIS on real skills before building the "
          "public registry — which is exactly what this harness does.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
