"""H2 model sweep (§8.7) — measure cross-tenant skill transfer across MODELS, on a broad corpus.

The single-model run (`run_h2.py`) answered "is the corpus fungible for this model?". A real moat
decision shouldn't hinge on one model, so this sweeps several (provider, model) configs over a
broader corpus (8 universal + 4 tenant-specific skills × 4 tenants) and tabulates the transfer
rate per model. Default sweep: Ollama `qwen3-coder:480b` and OpenAI `gpt-4o-mini` — each runs only
if its key is present. Writes a comparison to docs/H2_RESULTS.md.

Run:  python examples/run_h2_sweep.py     (uses whichever of ~/.config/{ollama,OpenAI}/key exist)
"""

from __future__ import annotations

import os
from pathlib import Path

from verel.agents import llm
from verel.memory import LocalMemory
from verel.registry import export_skill, measure_transfer
from verel.toolsmith import ToolCase, ToolRegistry, ToolSmith, ToolSpec

# ---- broadened source corpus (tenant A) ------------------------------------------------------
UNIVERSAL = [
    ToolSpec(name="slugify", capability="convert a title to a url slug",
             signature_hint="slugify(text)-> lowercase; non-alphanumerics to single '-'; trim '-'",
             cases=[ToolCase(args=["Hello World"], expected="hello-world"),
                    ToolCase(args=["  Verel Rocks! "], expected="verel-rocks")]),
    ToolSpec(name="snake_case", capability="convert a phrase with spaces to snake_case",
             signature_hint="snake_case(text)-> lowercase words joined by single underscores",
             cases=[ToolCase(args=["Hello World"], expected="hello_world"),
                    ToolCase(args=["Fast And Loud"], expected="fast_and_loud")]),
    ToolSpec(name="is_palindrome", capability="is a string a palindrome ignoring case and spaces",
             signature_hint="is_palindrome(s)->bool",
             cases=[ToolCase(args=["Race car"], expected=True), ToolCase(args=["hello"], expected=False)]),
    ToolSpec(name="word_count", capability="count whitespace-separated words",
             signature_hint="word_count(text)->int",
             cases=[ToolCase(args=["one two three"], expected=3), ToolCase(args=["  hi  "], expected=1)]),
    ToolSpec(name="initials", capability="uppercased initials of each word, no separators",
             signature_hint="initials(name)->str",
             cases=[ToolCase(args=["ada lovelace"], expected="AL"),
                    ToolCase(args=["grace brewster hopper"], expected="GBH")]),
    ToolSpec(name="count_vowels", capability="count vowels (aeiou) in a string, case-insensitive",
             signature_hint="count_vowels(s)->int",
             cases=[ToolCase(args=["Hello"], expected=2), ToolCase(args=["SKY"], expected=0)]),
    ToolSpec(name="gcd", capability="greatest common divisor of two positive ints",
             signature_hint="gcd(a,b)->int",
             cases=[ToolCase(args=[12, 18], expected=6), ToolCase(args=[7, 5], expected=1)]),
    ToolSpec(name="reverse_words", capability="reverse the order of words in a sentence",
             signature_hint="reverse_words(text)->str",
             cases=[ToolCase(args=["a b c"], expected="c b a"),
                    ToolCase(args=["hello world"], expected="world hello")]),
]
TENANT_SPECIFIC = [
    ToolSpec(name="tax_total", capability="add 8 percent sales tax to a price, round to 2 decimals",
             signature_hint="tax_total(price)->float",
             cases=[ToolCase(args=[100.0], expected=108.0), ToolCase(args=[50.0], expected=54.0)]),
    ToolSpec(name="price_label", capability="format a number as a USD price like $1,234.50",
             signature_hint="price_label(x)->str",
             cases=[ToolCase(args=[1234.5], expected="$1,234.50"), ToolCase(args=[9.0], expected="$9.00")]),
    ToolSpec(name="order_code", capability="order code: prefix 'A-' then the number padded to 5 digits",
             signature_hint="order_code(n)->str",
             cases=[ToolCase(args=[42], expected="A-00042"), ToolCase(args=[7], expected="A-00007")]),
    ToolSpec(name="fiscal_quarter", capability="fiscal quarter where the year starts in February (Q1=Feb-Apr)",
             signature_hint="fiscal_quarter(month)->str like 'Q1'",
             cases=[ToolCase(args=[2], expected="Q1"), ToolCase(args=[1], expected="Q4")]),
]


def _universal_targets() -> dict:
    return {
        "slugify": [ToolCase(args=["Big News Today"], expected="big-news-today")],
        "snake_case": [ToolCase(args=["Make It So"], expected="make_it_so")],
        "is_palindrome": [ToolCase(args=["Was it a car or a cat I saw"], expected=True)],
        "word_count": [ToolCase(args=["a b c d"], expected=4)],
        "initials": [ToolCase(args=["john ronald tolkien"], expected="JRT")],
        "count_vowels": [ToolCase(args=["Education"], expected=5)],
        "gcd": [ToolCase(args=[24, 36], expected=12)],
        "reverse_words": [ToolCase(args=["one two three"], expected="three two one")],
    }


TARGETS = {
    "B_us_8pct_febFY": {**_universal_targets(),
                        "tax_total": [ToolCase(args=[200.0], expected=216.0)],     # 8% matches
                        "price_label": [ToolCase(args=[5.0], expected="$5.00")],
                        "order_code": [ToolCase(args=[1], expected="A-00001")],
                        "fiscal_quarter": [ToolCase(args=[5], expected="Q2")]},    # Feb-start matches
    "C_us_10pct_febFY": {**_universal_targets(),
                         "tax_total": [ToolCase(args=[100.0], expected=110.0)],    # 10% differs
                         "price_label": [ToolCase(args=[5.0], expected="$5.00")],
                         "order_code": [ToolCase(args=[1], expected="A-00001")],
                         "fiscal_quarter": [ToolCase(args=[5], expected="Q2")]},
    "D_eu_20pct_janFY": {**_universal_targets(),
                         "tax_total": [ToolCase(args=[100.0], expected=120.0)],    # 20% differs
                         "price_label": [ToolCase(args=[5.0], expected="5,00 €")],  # EUR differs
                         "order_code": [ToolCase(args=[1], expected="EU-0001")],    # scheme differs
                         "fiscal_quarter": [ToolCase(args=[2], expected="Q1")]},    # Jan-start differs
}

SWEEP = [("ollama", "qwen3-coder:480b"), ("openai", "gpt-4o-mini")]


def _has_key(provider: str) -> bool:
    _, env_key, key_file, _ = llm.PROVIDERS[provider]
    return bool(os.environ.get(env_key)) or (Path.home() / ".config" / key_file).exists()


def _run_one(provider: str, model: str) -> dict:
    def chat(messages, p=provider, m=model):
        return llm.chat(messages, provider=p, model=m).content

    reg = ToolRegistry(LocalMemory(), scope=f"tenant:A:{model}")
    smith = ToolSmith(reg, chat=chat, sandbox=True)
    artifacts, built = [], 0
    for spec in UNIVERSAL + TENANT_SPECIFIC:
        try:
            res = smith.build(spec)
        except Exception as e:  # noqa: BLE001
            print(f"    {spec.name}: build error ({type(e).__name__})")
            continue
        if res.tool and res.trust and res.trust.value == "verified":
            built += 1
            artifacts.append(export_skill(res.tool, origin=f"tenant:A:{model}"))
        print(f"    {spec.name:14} {(res.trust.value if res.trust else 'unbuilt'):10} ({res.reason})")
    report = measure_transfer(artifacts, TARGETS, sandbox=True)
    return {"provider": provider, "model": model, "built": built,
            "total": len(UNIVERSAL + TENANT_SPECIFIC), "report": report,
            "per": report.per_skill_rate()}


def main() -> int:
    runs = []
    for provider, model in SWEEP:
        if not _has_key(provider):
            print(f"── skip {provider}/{model}: no key ──")
            continue
        print(f"── sweep {provider}/{model} ──")
        runs.append(_run_one(provider, model))
        r = runs[-1]["report"]
        print(f"  -> {r.transferred}/{r.attempts} = {r.rate:.0%}  ({r.decision})\n")
    if not runs:
        print("no models available (need an Ollama or OpenAI key).")
        return 0
    _write(runs)
    print("wrote docs/H2_RESULTS.md")
    return 0


def _write(runs: list[dict]) -> None:
    lines = ["# H2 — corpus-transfer experiment, model sweep", "",
             "> Generated by `examples/run_h2_sweep.py`. Cross-tenant re-verification rate of a "
             "live-built skill corpus, swept across models. The moat is real only where skills "
             "transfer; a one-model result isn't enough to bet on.", "",
             "## Sweep", "", "| Provider | Model | Built | Transfer rate | Decision |",
             "|---|---|---|---|---|"]
    for r in runs:
        rep = r["report"]
        decided = "BUILD" if rep.rate >= 0.20 else "DON'T BUILD"
        lines.append(f"| `{r['provider']}` | `{r['model']}` | {r['built']}/{r['total']} | "
                     f"**{rep.transferred}/{rep.attempts} = {rep.rate:.0%}** | {decided} |")
    skills = sorted({s for r in runs for s in r["per"]})
    lines += ["", "## Per-skill transfer (by model)", "",
              "| Skill | " + " | ".join(f"`{r['model']}`" for r in runs) + " |",
              "|---|" + "---|" * len(runs)]
    for sk in skills:
        cells = " | ".join(f"{r['per'].get(sk, 0.0):.0%}" if sk in r["per"] else "—" for r in runs)
        lines.append(f"| `{sk}` | {cells} |")
    lines += ["", "## Interpretation", "",
              "Universal pure functions transfer ~100% across models; tenant-specific skills "
              "transfer only where a tenant's rule matches the one the skill encoded. A model that "
              "builds fewer skills, or whose skills overfit, shifts the rate — which is exactly why "
              "the decision is swept, not taken from a single run."]
    Path("docs/H2_RESULTS.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
