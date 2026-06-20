"""Hosted skill registry (§2.2) — the public registry behind an HTTP API, trust-does-not-travel.

The H2 sweep measured ~88-89% cross-tenant transfer, so the registry is justified. This shows the
distribution flywheel over real HTTP: tenant A publishes a verified skill; tenant B (another
machine) fetches it and RE-VERIFIES it against its own held-out cases — a fetched skill is only a
candidate until B's eval passes. Offline, no LLM, no key.

Run:  python examples/demo_hosted_registry.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from verel.memory import LocalMemory
from verel.registry import RegistryServer, RemoteRegistry, export_skill, import_skill
from verel.toolsmith import SideEffect, ToolCase, ToolRecord, ToolRegistry

SLUG = ("def slugify(t):\n    import re\n"
        "    return re.sub(r'[^a-z0-9]+','-',t.lower()).strip('-')\n")
# a skill that encodes tenant A's 8% tax rule — should NOT transfer to a 10% tenant
TAX = "def tax_total(p):\n    return round(p * 1.08, 2)\n"


def _publish(client, name, capability, code):
    tool = ToolRecord(name=name, capability=capability, code=code,
                      side_effect=SideEffect.READ_ONLY, eval_score=1.0).sign()
    art = client.publish(export_skill(tool, origin="tenant:A"))
    print(f"  A published {name}  ({art.content_hash[:12]})")
    return art


def main() -> None:
    with tempfile.TemporaryDirectory() as d:
        srv = RegistryServer(Path(d) / "registry", auth_token="demo-key").start()
        print(f"hosted registry at {srv.url}")
        try:
            A = RemoteRegistry(srv.url, auth_token="demo-key")
            _publish(A, "slugify", "convert a title to a url slug", SLUG)
            _publish(A, "tax_total", "add 8 percent sales tax to a price", TAX)

            # tenant B, a different machine, fetches and re-verifies against ITS held-out cases.
            B = RemoteRegistry(srv.url, auth_token="demo-key")
            print("\nB fetches the catalog and re-verifies (trust does not travel):")
            regB = ToolRegistry(LocalMemory(), scope="tenant:B")
            cases = {
                "slugify": [ToolCase(args=["Big News"], expected="big-news")],   # universal
                "tax_total": [ToolCase(args=[100.0], expected=110.0)],           # B uses 10%!
            }
            for art in B.all():
                res = import_skill(art, regB, target_cases=cases[art.name])
                verdict = "VERIFIED (transferred)" if res.reverified else "candidate (did NOT transfer)"
                print(f"  {art.name:10} -> {verdict}")
            print("\nslugify transfers (universal); tax_total doesn't (B's rule differs) — exactly "
                  "what makes the registry a measured moat, not a trust hole.")
        finally:
            srv.stop()


if __name__ == "__main__":
    main()
