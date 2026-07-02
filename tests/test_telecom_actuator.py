"""Phase 5 item 4 — NETCONF actuator (act-then-verify, guardrail-gated). No ncclient / no network: the
NetconfSession is faked. Focus: dry-run default, IRREVERSIBLE approval, confirmed-commit rollback,
plan-binding, and the verify-fail → rollback path."""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("yaml", reason="telecom tests need verel[telecom]")
pytest.importorskip("defusedxml")

from verel.ci.telecom_actuator import TelecomActuator, _classify
from verel.ci.telecom_cfg import _model_from_artifact
from verel.gateway import ActionClass
from verel.verdict.models import Verdict

_BASE = """<data><ManagedElement><id>m</id><GNBDUFunction><id>1</id>
<NRCellDU><id>1</id><attributes><nRPCI>1</nRPCI><nRTAC>{tac}</nRTAC><cellLocalId>1</cellLocalId>
<pLMNInfoList><pLMNInfo><plmnId><mcc>001</mcc><mnc>01</mnc></plmnId></pLMNInfo></pLMNInfoList></attributes>
</NRCellDU></GNBDUFunction><AMFFunction><id>a</id><attributes><taiList><tai>
<plmnId><mcc>001</mcc><mnc>01</mnc></plmnId><tac>{atac}</tac></tai></taiList></attributes></AMFFunction>
</ManagedElement></data>"""


def _cfg(tac, atac):
    return _BASE.format(tac=tac, atac=atac)


class FakeSession:
    def __init__(self, running):
        self.running = running
        self.calls: list = []

    def lock(self, d):
        self.calls.append(("lock", d))

    def edit_config(self, t, c):
        self.calls.append(("edit", t))

    def commit(self, *, confirmed=False, timeout=0):
        self.calls.append(("commit", confirmed, timeout))

    def discard_changes(self):
        self.calls.append(("discard",))

    def get_config(self, s):
        return self.running

    def unlock(self, d):
        self.calls.append(("unlock", d))

    def close(self):
        pass


def _plan(repo, *, current, desired, edit="<config>x</config>"):
    Path(repo, "cur.xml").write_text(current)
    Path(repo, "des.xml").write_text(desired)
    return TelecomActuator(repo).plan(current="cur.xml", desired="des.xml", edit_config=edit)


# --------------------------------------------------------------------------- classification
def test_classify_tac_change_is_irreversible():
    cur = _model_from_artifact(_cfg(7001, 7001))
    des = _model_from_artifact(_cfg(7002, 7002))
    action, reasons = _classify(cur, des)
    assert action == ActionClass.IRREVERSIBLE and any("TAC" in r for r in reasons)


def test_classify_identical_is_consequential():
    m = _model_from_artifact(_cfg(7001, 7001))
    action, reasons = _classify(m, m)
    assert action == ActionClass.CONSEQUENTIAL and reasons == []


def test_classify_cell_removal_irreversible():
    cur = _model_from_artifact(_cfg(7001, 7001))
    des = _model_from_artifact("<data><ManagedElement><id>m</id></ManagedElement></data>")
    action, reasons = _classify(cur, des)
    assert action == ActionClass.IRREVERSIBLE and any("removes" in r for r in reasons)


def test_classify_nf_snssai_change_irreversible():
    # red-team F1: an NF (not just a cell) S-NSSAI / PLMN change must be IRREVERSIBLE
    from verel.ci.telecom_model import NF, TelecomConfigModel
    cur = TelecomConfigModel(nfs=[NF(kind="NSSF", name="n1", plmns=["001-01"], snssais=["1"])])
    des = TelecomConfigModel(nfs=[NF(kind="NSSF", name="n1", plmns=["001-01"], snssais=["2"])])
    action, reasons = _classify(cur, des)
    assert action == ActionClass.IRREVERSIBLE and any("S-NSSAI" in r for r in reasons)


def test_classify_amf_served_tai_change_irreversible():
    # red-team F1 residual: an AMF served-TAI change (PLMN/TAC it serves) is service-defining
    cur = _model_from_artifact(_cfg(7002, 7002))
    des = _model_from_artifact(_cfg(7002, 7003))  # AMF served-TAC 7002 → 7003
    action, reasons = _classify(cur, des)
    assert action == ActionClass.IRREVERSIBLE and any("served-TAI" in r for r in reasons)


def test_r2_untracked_attrs_are_now_critical():
    # red-team R2: PCI / replicas / max-Tx-power / NF-attrs (SUCI etc.) changes must be IRREVERSIBLE
    from verel.ci.telecom_model import NF, Cell, TelecomConfigModel
    cases = [
        (TelecomConfigModel(cells=[Cell(name="x", pci=1)]), TelecomConfigModel(cells=[Cell(name="x", pci=500)])),
        (TelecomConfigModel(cells=[Cell(name="x", max_tx_power_dbm=20)]),
         TelecomConfigModel(cells=[Cell(name="x", max_tx_power_dbm=46)])),
        (TelecomConfigModel(nfs=[NF(kind="AMF", name="a", replicas=2)]),
         TelecomConfigModel(nfs=[NF(kind="AMF", name="a", replicas=1)])),
        (TelecomConfigModel(nfs=[NF(kind="AMF", name="a", attrs={"suci": "null"})]),
         TelecomConfigModel(nfs=[NF(kind="AMF", name="a", attrs={"suci": "ecc"})])),
    ]
    for cur, des in cases:
        assert _classify(cur, des)[0] == ActionClass.IRREVERSIBLE


def test_r2_untracked_divergence_rolls_back(tmp_path):
    # a CONSEQUENTIAL plan (identical current/desired) whose edit-config diverges on an UNTRACKED-before
    # attribute (here max-Tx-power) must now be caught by _matches_desired → rolled back
    same = _cfg(7001, 7001)
    plan = _plan(str(tmp_path), current=same, desired=same, edit="<config>bump power</config>")
    assert plan.action == ActionClass.CONSEQUENTIAL
    # running has the same cells/NFs but a jacked-up transmit power → must NOT be confirmed
    running = same.replace("<nRPCI>1</nRPCI>", "<nRPCI>1</nRPCI><configuredMaxTxPower>46</configuredMaxTxPower>")
    s = FakeSession(running)
    r = TelecomActuator(str(tmp_path)).act(plan, session=s, approved=False)
    assert not r.ok and r.rolled_back and ("commit", False, 0) not in s.calls


def test_r3_neighbor_order_does_not_false_mismatch():
    # red-team R3 Item 2: a correct apply whose device get-config REORDERS a set-like list (neighbors,
    # both legal per TS 28.541 DU/CU-nesting) must NOT be treated as a change → no false rollback.
    from verel.ci.telecom_actuator import _matches_desired
    from verel.ci.telecom_model import Cell, TelecomConfigModel
    des = TelecomConfigModel(cells=[Cell(name="c", neighbors=[{"target": "A"}, {"target": "B"}])])
    run = TelecomConfigModel(cells=[Cell(name="c", neighbors=[{"target": "B"}, {"target": "A"}])])
    assert _matches_desired(run, des) == []  # order-insensitive → equal


def test_r3_gnb_reparent_is_irreversible():
    # red-team R3 Item 1: gnb (co-siting key) change must be caught by classification + verification
    from verel.ci.telecom_model import Cell, TelecomConfigModel
    cur = TelecomConfigModel(cells=[Cell(name="c", gnb="gnb-1")])
    des = TelecomConfigModel(cells=[Cell(name="c", gnb="gnb-2")])
    assert _classify(cur, des)[0] == ActionClass.IRREVERSIBLE


def test_r3_cyclic_attrs_plan_fails_closed():
    # red-team R3/R4: a cyclic/pathological structure must RAISE (→ caught → fail-closed to IRREVERSIBLE
    # / rollback), never truncate to a false-equal or RecursionError
    import pytest as _pytest

    from verel.ci.telecom_actuator import _canon
    cyc: dict = {"k": None}
    cyc["k"] = cyc  # self-reference
    with _pytest.raises(ValueError, match="depth"):
        _canon(cyc)


def test_r4_security_order_reorder_is_irreversible():
    # red-team R4: ciphering_order / integrity_order are POSITION-significant (index 0 = top priority) —
    # a reorder (crypto downgrade) must NOT be flattened by the set-sort; it stays IRREVERSIBLE.
    from verel.ci.telecom_actuator import _matches_desired
    from verel.ci.telecom_model import NF, TelecomConfigModel
    cur = TelecomConfigModel(nfs=[NF(kind="AMF", name="a", attrs={"ciphering_order": ["NEA2", "NEA1", "NEA0"]})])
    des = TelecomConfigModel(nfs=[NF(kind="AMF", name="a", attrs={"ciphering_order": ["NEA1", "NEA2", "NEA0"]})])
    assert _classify(cur, des)[0] == ActionClass.IRREVERSIBLE
    assert _matches_desired(cur, des)  # bound in verification too (non-empty = mismatch)
    # a set-like list (neighbors) still order-insensitive (no false mismatch)
    from verel.ci.telecom_model import Cell
    a = TelecomConfigModel(cells=[Cell(name="c", neighbors=[{"target": "A"}, {"target": "B"}])])
    b = TelecomConfigModel(cells=[Cell(name="c", neighbors=[{"target": "B"}, {"target": "A"}])])
    assert _matches_desired(a, b) == []


def test_f2_destructive_editconfig_rolled_back(tmp_path):
    # red-team F2: a benign desired==current (CONSEQUENTIAL, no approval) shipped with an edit-config that
    # produces a DIFFERENT running state must be rolled back — applied result is bound to graded intent.
    plan = _plan(str(tmp_path), current=_cfg(7001, 7001), desired=_cfg(7001, 7001),
                 edit="<config>destructive delete-all</config>")
    assert plan.action == ActionClass.CONSEQUENTIAL  # benign classification
    s = FakeSession("<data></data>")  # the edit-config wiped the config → running projects to empty
    r = TelecomActuator(str(tmp_path)).act(plan, session=s, approved=False)
    assert not r.ok and r.rolled_back and ("commit", False, 0) not in s.calls  # never confirmed


def test_f3_malformed_running_fails_closed(tmp_path):
    # red-team F3: a device returning malformed XML must FAIL CLOSED (rollback), not crash or confirm
    plan = _plan(str(tmp_path), current=_cfg(7001, 7001), desired=_cfg(7002, 7002))

    class BadRun(FakeSession):
        def get_config(self, s):
            return "<data><ManagedElement>"  # truncated / malformed
    s = BadRun(_cfg(7002, 7002))
    r = TelecomActuator(str(tmp_path)).act(plan, session=s, approved=True)
    assert not r.ok and r.rolled_back and ("discard",) in s.calls


# --------------------------------------------------------------------------- guardrails
def test_plan_is_offline_dry_run(tmp_path):
    plan = _plan(str(tmp_path), current=_cfg(7001, 7001), desired=_cfg(7002, 7002))
    assert plan.action == ActionClass.IRREVERSIBLE
    assert plan.report.verdict != Verdict.FAIL  # desired is consistent (cell 7002, AMF serves 7002)


def test_irreversible_refused_without_approval(tmp_path):
    plan = _plan(str(tmp_path), current=_cfg(7001, 7001), desired=_cfg(7002, 7002))
    r = TelecomActuator(str(tmp_path)).act(plan, session=FakeSession(_cfg(7002, 7002)), approved=False)
    assert not r.ok and "approval" in r.detail


def test_approved_verify_pass_confirms(tmp_path):
    plan = _plan(str(tmp_path), current=_cfg(7001, 7001), desired=_cfg(7002, 7002))
    s = FakeSession(_cfg(7002, 7002))  # running verifies PASS
    r = TelecomActuator(str(tmp_path)).act(plan, session=s, approved=True)
    assert r.ok and ("commit", False, 0) in s.calls  # the confirming (non-confirmed) commit fired
    assert ("commit", True, 120) in s.calls           # preceded by the confirmed-commit


def test_verify_fail_rolls_back(tmp_path):
    plan = _plan(str(tmp_path), current=_cfg(7001, 7001), desired=_cfg(7002, 7002))
    # running has cell TAC 7002 but AMF still serves 7001 → tac-plmn FAIL → rollback
    s = FakeSession(_cfg(7002, 7001))
    r = TelecomActuator(str(tmp_path)).act(plan, session=s, approved=True)
    assert not r.ok and r.rolled_back and ("discard",) in s.calls
    assert ("commit", False, 0) not in s.calls  # never confirmed


def test_plan_binding_swap_refused(tmp_path):
    plan = _plan(str(tmp_path), current=_cfg(7001, 7001), desired=_cfg(7002, 7002))
    plan.edit_config = "<config>SWAPPED</config>"  # tamper after plan bound the digest
    r = TelecomActuator(str(tmp_path)).act(plan, session=FakeSession(_cfg(7002, 7002)), approved=True)
    assert not r.ok and "plan-binding" in r.detail


def test_plan_only_no_edit_config_refused(tmp_path):
    plan = _plan(str(tmp_path), current=_cfg(7001, 7001), desired=_cfg(7002, 7002), edit="")
    r = TelecomActuator(str(tmp_path)).act(plan, session=FakeSession(_cfg(7002, 7002)), approved=True)
    assert not r.ok and "plan-only" in r.detail


def test_desired_fails_grader_refused(tmp_path):
    # desired is INCONSISTENT (cell 7002, AMF serves 7001) → grader FAIL → act refuses even if approved
    plan = _plan(str(tmp_path), current=_cfg(7001, 7001), desired=_cfg(7002, 7001))
    assert plan.report.verdict == Verdict.FAIL
    r = TelecomActuator(str(tmp_path)).act(plan, session=FakeSession(_cfg(7002, 7001)), approved=True)
    assert not r.ok and "FAILS the grader" in r.detail


def test_edit_or_commit_error_discards(tmp_path):
    plan = _plan(str(tmp_path), current=_cfg(7001, 7001), desired=_cfg(7002, 7002))

    class Boom(FakeSession):
        def edit_config(self, t, c):
            raise RuntimeError("device rejected edit")
    s = Boom(_cfg(7002, 7002))
    r = TelecomActuator(str(tmp_path)).act(plan, session=s, approved=True)
    assert not r.ok and r.rolled_back and ("discard",) in s.calls


def test_ncclient_absent_gives_clear_hint():
    # the live-session factory must fail with an install hint, not an opaque ImportError
    import sys

    from verel.ci.telecom_actuator import ncclient_session
    if "ncclient" in sys.modules:  # environment has it; skip (we assert the absent-path message shape)
        pytest.skip("ncclient installed")
    with pytest.raises(RuntimeError, match="telecom-actuator"):
        ncclient_session("h", username="u")
