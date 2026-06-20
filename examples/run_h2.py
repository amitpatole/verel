"""Run the H2 corpus-transfer experiment FOR REAL (§8.7) — the moat's gating decision.

Builds a real corpus with the tool-smith (Ollama Cloud → OpenAI fallback), then measures how
often each verified skill RE-VERIFIES against other tenants' own held-out cases. The corpus is
deliberately mixed:

  * universal skills (slugify, snake_case, is_palindrome, word_count, initials) — pure functions
    that SHOULD transfer to every tenant;
  * tenant-specific skills (tax_total@8%, round_half_even, price_label) — encode tenant A's rules,
    which SHOULD transfer only to tenants whose rules match.

The aggregate transfer rate is the honest answer to "is a public skill registry a real moat?".
Writes a markdown summary to docs/H2_RESULTS.md.

Run:  python examples/run_h2.py     (needs ~/.config/ollama/key; falls back to OpenAI)
"""

from __future__ import annotations

import os
from pathlib import Path

from verel.agents import llm
from verel.memory import LocalMemory
from verel.registry import export_skill, measure_transfer
from verel.toolsmith import ToolCase, ToolRegistry, ToolSmith, ToolSpec

# ---- source corpus (tenant A) ----------------------------------------------------------------
UNIVERSAL = [
    ToolSpec(name="slugify", capability="convert a title to a url slug",
             signature_hint="slugify(text: str) -> str (lowercase; runs of non-alphanumerics -> single '-'; trim '-')",
             cases=[ToolCase(args=["Hello World"], expected="hello-world"),
                    ToolCase(args=["  Verel Rocks! "], expected="verel-rocks")]),
    ToolSpec(name="snake_case", capability="convert a phrase to snake_case",
             signature_hint="snake_case(text: str) -> str (lowercase words joined by underscores)",
             cases=[ToolCase(args=["Hello World"], expected="hello_world"),
                    ToolCase(args=["MakeItSo"], expected="make_it_so")]),
    ToolSpec(name="is_palindrome", capability="is a string a palindrome ignoring case and spaces",
             signature_hint="is_palindrome(s: str) -> bool",
             cases=[ToolCase(args=["Race car"], expected=True), ToolCase(args=["hello"], expected=False)]),
    ToolSpec(name="word_count", capability="count whitespace-separated words in a string",
             signature_hint="word_count(text: str) -> int",
             cases=[ToolCase(args=["one two three"], expected=3), ToolCase(args=["  hi  "], expected=1)]),
    ToolSpec(name="initials", capability="initials of each word, uppercased, no separators",
             signature_hint="initials(name: str) -> str",
             cases=[ToolCase(args=["ada lovelace"], expected="AL"),
                    ToolCase(args=["grace brewster hopper"], expected="GBH")]),
]
TENANT_SPECIFIC = [
    ToolSpec(name="tax_total", capability="add 8 percent sales tax to a price, round to 2 decimals",
             signature_hint="tax_total(price: float) -> float",
             cases=[ToolCase(args=[100.0], expected=108.0), ToolCase(args=[50.0], expected=54.0)]),
    ToolSpec(name="price_label", capability="format a number as a USD price label like $1,234.50",
             signature_hint="price_label(x: float) -> str",
             cases=[ToolCase(args=[1234.5], expected="$1,234.50"), ToolCase(args=[9.0], expected="$9.00")]),
    ToolSpec(name="order_code", capability="order code: prefix 'A-' then the number zero-padded to 5 digits",
             signature_hint="order_code(n: int) -> str",
             cases=[ToolCase(args=[42], expected="A-00042"), ToolCase(args=[7], expected="A-00007")]),
]

# ---- target tenants: their OWN held-out cases. Universal cases match everywhere; tenant-specific
#      cases encode each tenant's distinct rule (tax rate, currency, code prefix). -------------
def _universal_cases() -> dict:
    return {
        "slugify": [ToolCase(args=["Big News Today"], expected="big-news-today")],
        "snake_case": [ToolCase(args=["Fast And Loud"], expected="fast_and_loud")],
        "is_palindrome": [ToolCase(args=["Was it a car or a cat I saw"], expected=True)],
        "word_count": [ToolCase(args=["a b c d"], expected=4)],
        "initials": [ToolCase(args=["john ronald tolkien"], expected="JRT")],
    }


TARGETS = {
    "B_us_8pct": {**_universal_cases(),
                  "tax_total": [ToolCase(args=[200.0], expected=216.0)],          # 8% — matches A
                  "price_label": [ToolCase(args=[5.0], expected="$5.00")],        # USD — matches A
                  "order_code": [ToolCase(args=[1], expected="A-00001")]},        # A- prefix — matches
    "C_us_10pct": {**_universal_cases(),
                   "tax_total": [ToolCase(args=[100.0], expected=110.0)],         # 10% — differs
                   "price_label": [ToolCase(args=[5.0], expected="$5.00")],       # USD — matches
                   "order_code": [ToolCase(args=[1], expected="A-00001")]},
    "D_eu_20pct": {**_universal_cases(),
                   "tax_total": [ToolCase(args=[100.0], expected=120.0)],         # 20% — differs
                   "price_label": [ToolCase(args=[5.0], expected="5,00 €")],      # EUR — differs
                   "order_code": [ToolCase(args=[1], expected="EU-0001")]},       # different scheme
}


def main() -> int:
    if not llm.have_key():
        print("SKIP: no LLM key (~/.config/ollama/key or OPENAI_API_KEY).")
        return 0
    provider = os.environ.get("VEREL_LLM_PROVIDER", "ollama")
    print(f"LLM provider: {provider}  model: {llm.default_model(provider)}\n")

    reg_a = ToolRegistry(LocalMemory(), scope="tenant:A")
    smith = ToolSmith(reg_a, sandbox=True)

    artifacts, build_rows = [], []
    print("── Tenant A builds + verifies skills ──")
    for spec in UNIVERSAL + TENANT_SPECIFIC:
        try:
            res = smith.build(spec)
        except Exception as e:  # noqa: BLE001 — a provider hiccup shouldn't abort the run
            print(f"  {spec.name}: BUILD ERROR ({type(e).__name__})")
            build_rows.append((spec.name, "error"))
            continue
        trust = res.trust.value if res.trust else "unbuilt"
        print(f"  {spec.name:14} {trust:10} ({res.reason})")
        build_rows.append((spec.name, trust))
        if res.tool and res.trust and res.trust.value == "verified":
            artifacts.append(export_skill(res.tool, origin="tenant:A"))

    print("\n── Measuring cross-tenant transfer (re-verify against each tenant's held-out cases) ──")
    report = measure_transfer(artifacts, TARGETS, sandbox=True, log=print)

    per = report.per_skill_rate()
    print(f"\n  transfer rate: {report.transferred}/{report.attempts} = {report.rate:.0%}")
    print(f"  MOAT DECISION: {report.decision}")

    _write_results(provider, build_rows, report, per)
    print("\nwrote docs/H2_RESULTS.md")
    return 0


def _write_results(provider, build_rows, report, per) -> None:
    lines = [
        "# H2 — corpus-transfer experiment results", "",
        "> Generated by `examples/run_h2.py`. The moat (a public verified-skill registry) is real "
        "only if verified skills RE-VERIFY across tenants. This measures it on a live-built corpus.",
        "", f"- **LLM provider:** `{provider}`",
        f"- **Skills built:** {sum(t == 'verified' for _, t in build_rows)}/{len(build_rows)} verified",
        f"- **Transfer attempts:** {report.attempts} (skill × tenant with held-out cases)",
        f"- **Transfer rate:** **{report.transferred}/{report.attempts} = {report.rate:.0%}**",
        f"- **KILL_LINE:** 20% — **decision: {report.decision}**", "",
        "## Per-skill transfer", "", "| Skill | Re-verify rate | Reading |", "|---|---|---|",
    ]
    for skill, r in sorted(per.items()):
        reading = "universal" if r == 1.0 else ("tenant-specific (lock-in)" if r < 0.5 else "partial")
        lines.append(f"| `{skill}` | {r:.0%} | {reading} |")
    lines += ["", "## Interpretation", "",
              "Skills that re-verify everywhere are fungible — a genuine cross-tenant network "
              "effect. Skills that re-verify only where a tenant's rules happen to match are "
              "lock-in, not a moat. §8.7 says measure THIS before building the public registry."]
    Path("docs/H2_RESULTS.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
