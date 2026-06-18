"""Tool-smith demo — agents building their own tools (design §7.6).

A capability is requested that no tool covers yet. The tool-smith asks Ollama Cloud to
scaffold a function, TESTS it against held-out cases, and registers it to procedural memory
ONLY on a passing, attested eval (verified + signed). A second request for the same
capability REUSES the registered tool instead of rebuilding. A destructive tool is withheld
pending a human-review verdict.

Run:  python examples/demo_toolsmith.py     (needs ~/.config/ollama/key)
"""

from __future__ import annotations

from verel.agents.llm import have_key
from verel.memory import LocalMemory
from verel.toolsmith import SideEffect, ToolCase, ToolRegistry, ToolSmith, ToolSpec, load_callable

SPEC = ToolSpec(
    name="wcag_contrast_ratio",
    capability="compute the WCAG contrast ratio between two sRGB hex colors",
    signature_hint="wcag_contrast_ratio(hex1: str, hex2: str) -> float  # rounded to 2 dp",
    side_effect=SideEffect.READ_ONLY,
    cases=[  # held-out, agent-inaccessible truth (the smith sees only pass/fail)
        ToolCase(args=["#000000", "#ffffff"], expected=21.0),
        ToolCase(args=["#ffffff", "#ffffff"], expected=1.0),
        ToolCase(args=["#777777", "#ffffff"], expected=4.48),
    ],
)


def main() -> int:
    if not have_key():
        print("SKIP: no Ollama Cloud key (~/.config/ollama/key).")
        return 0

    reg = ToolRegistry(LocalMemory(), scope="global")
    smith = ToolSmith(reg)

    print(f"── detect → scaffold → test → register: {SPEC.name} ──")
    res = smith.build(SPEC)
    print(f"  reused={res.reused}  passed={res.passed}  score={res.score:.2f}  "
          f"trust={res.trust.value if res.trust else None}  ({res.reason})")

    if res.registered and res.trust and res.trust.value == "verified":
        fn = load_callable(reg.find("contrast ratio between colors")[0])
        print(f"  the agent-built tool runs: wcag_contrast_ratio('#000','#fff') = "
              f"{fn('#000000', '#ffffff')}")

    print("\n── reuse (same capability → no rebuild) ──")
    res2 = smith.build(SPEC)
    print(f"  reused={res2.reused}")

    print("\n── a destructive tool is withheld pending human review ──")
    destructive = ToolSpec(
        name="purge_cache_key", capability="delete a cache entry by key (destructive)",
        signature_hint="purge_cache_key(key: str) -> str  # returns the key it would delete",
        side_effect=SideEffect.DESTRUCTIVE,
        cases=[ToolCase(args=["abc"], expected="abc")],
    )
    res3 = smith.build(destructive, human_review=None)
    print(f"  passed={res3.passed}  trust={res3.trust.value if res3.trust else None}  ({res3.reason})")

    ok = (res.trust and res.trust.value == "verified") and res2.reused and \
         (res3.trust and res3.trust.value == "candidate")
    print("\nResult:", "PASS — agent built + verified a tool, reused it, and gated the "
          "destructive one behind human review" if ok else "NOT MET")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
