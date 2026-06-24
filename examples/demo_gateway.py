"""Gate the boundary — the agent calls its normal tools; Verel decides what actually happens (G).

The gateway sits in front of the agent's tools and gates the consequential ones: a verdict decides
whether a write forwards, and an irreversible action is dry-run by default and needs human approval.
The agent needn't know it's there. This is enforcement that will later be the `immel`/`actel` organs;
it's built here behind a clean seam, fail-closed from day one.

Run:  python examples/demo_gateway.py
"""

from __future__ import annotations

from verel.gateway import Gateway, Policy

# The real tools (stubbed here): each just records that it ran.
performed: list[str] = []


def invoke(tool: str, args: dict):
    performed.append(tool)
    return f"performed {tool}"


# A gate stub: pretend the repo currently FAILS CI (so consequential writes must be refused).
def failing_gate(tool, args):
    return {"verdict": "fail", "issues": [{"message": "2 tests failing"}]}


gw = Gateway(invoke, policy=Policy(dry_run=True), gate=failing_gate, approve=lambda t, a: False)

for tool in ["read_file", "write_config", "deploy_to_prod"]:
    r = gw.handle(tool, {})
    print(f"{tool:18} → {r.decision.value:14} [{r.action_class.value}]  {r.reason}")

print(f"\nactually performed: {performed}")
print("→ read_file forwarded (safe); write_config BLOCKED (the gate failed); "
      "deploy_to_prod DRY-RUN (irreversible, no human approval). Nothing dangerous happened.")
