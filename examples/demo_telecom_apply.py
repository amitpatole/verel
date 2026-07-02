"""Telecom NETCONF actuator — act-then-verify with guardrails, fully offline (fake NETCONF session).

Shows the "hands" of the telecom track: apply a config change, then the graders CONFIRM it. No device,
no ncclient — a fake session stands in so you can see every guardrail:
  1. dry-run plan: classify the change + grade the desired config (nothing touched);
  2. IRREVERSIBLE change refused without human approval;
  3. approved + the running config VERIFIES → confirmed;
  4. approved but the applied edit-config produces a BAD running state → auto-rolled-back, never confirmed.

    python examples/demo_telecom_apply.py       # needs verel[telecom]; no network
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from verel.ci.telecom_actuator import TelecomActuator

# cell broadcasts TAC {tac}; AMF serves TAC {atac}. Consistent iff tac == atac (else tac-plmn FAILs).
_CFG = """<data><ManagedElement><id>m</id><GNBDUFunction><id>1</id>
<NRCellDU><id>1</id><attributes><nRPCI>1</nRPCI><nRTAC>{tac}</nRTAC><cellLocalId>1</cellLocalId>
<pLMNInfoList><pLMNInfo><plmnId><mcc>001</mcc><mnc>01</mnc></plmnId></pLMNInfo></pLMNInfoList></attributes>
</NRCellDU></GNBDUFunction><AMFFunction><id>a</id><attributes><taiList><tai>
<plmnId><mcc>001</mcc><mnc>01</mnc></plmnId><tac>{atac}</tac></tai></taiList></attributes></AMFFunction>
</ManagedElement></data>"""


class FakeSession:
    """Stands in for a real NETCONF-over-SSH session; `running` is what get-config returns post-apply."""

    def __init__(self, running: str):
        self.running, self.calls = running, []

    def lock(self, d): self.calls.append("lock")
    def edit_config(self, t, c): self.calls.append("edit")
    def commit(self, *, confirmed=False, timeout=0): self.calls.append(f"commit(confirmed={confirmed})")
    def discard_changes(self): self.calls.append("discard")
    def get_config(self, s): return self.running
    def unlock(self, d): self.calls.append("unlock")
    def close(self): ...


def main() -> None:
    print("Telecom actuator — act-then-verify with guardrails (offline, fake NETCONF session)\n")
    with tempfile.TemporaryDirectory() as repo:
        # the change: retune the cell's TAC 7001→7002 AND update the AMF to serve it (a consistent change)
        Path(repo, "current.xml").write_text(_CFG.format(tac=7001, atac=7001))
        Path(repo, "desired.xml").write_text(_CFG.format(tac=7002, atac=7002))
        act = TelecomActuator(repo)
        plan = act.plan(current="current.xml", desired="desired.xml",
                        edit_config="<config>operator's NETCONF edit-config payload</config>")

        print(f"1) dry-run plan → action={plan.action.value}, desired grades {plan.report.verdict.value}")
        for r in plan.reasons:
            print(f"     change: {r}")

        r = act.act(plan, session=FakeSession(_CFG.format(tac=7002, atac=7002)), approved=False)
        print(f"\n2) apply without approval → {'OK' if r.ok else 'REFUSED'}: {r.detail}")

        s = FakeSession(_CFG.format(tac=7002, atac=7002))  # running is consistent → verify PASS
        r = act.act(plan, session=s, approved=True)
        print(f"\n3) apply WITH approval, running verifies → {'OK' if r.ok else 'FAIL'}: {r.detail}")
        print(f"     session calls: {s.calls}")

        bad = FakeSession(_CFG.format(tac=7002, atac=7001))  # cell 7002 but AMF still serves 7001 → FAIL
        r = act.act(plan, session=bad, approved=True)
        print(f"\n4) apply WITH approval, but running is INCONSISTENT → "
              f"{'OK' if r.ok else 'ROLLED BACK'}: {r.detail}")
        print(f"     session calls: {bad.calls}  (discarded, never confirmed)")
        print("\n  the senses confirm the world changed correctly BEFORE the change is made permanent.")


if __name__ == "__main__":
    main()
