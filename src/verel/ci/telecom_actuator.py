"""Telecom NETCONF actuator (Phase 5 item 4) — act-then-verify for a 5G config change, guardrail-gated.

The "hands" of the telecom track: apply a config change, then the graders CONFIRM the change actually
landed and is still valid. Guardrails (per the actel/immel non-negotiables) are NOT optional:

- **Dry-run by default.** `plan()` is OFFLINE and mutates nothing: it grades the DESIRED config (the
  verify done pre-flight), classifies the change, and binds the edit-config payload's digest. A live
  apply happens ONLY via `act()` with an explicit session.
- **Human approval for irreversible.** Removing an MO, or changing a service-defining attribute
  (PLMN / TAC / S-NSSAI / an NF's endpoints), is IRREVERSIBLE → `act()` refuses unless `approved=True`.
  Pure additions / non-critical edits are CONSEQUENTIAL (verdict-gated).
- **Confirmed-commit rollback.** The live apply uses NETCONF `<commit confirmed>` with a timeout, so the
  change AUTO-REVERTS unless it is explicitly confirmed AFTER a post-apply re-grade passes. A crash
  between commit and confirm rolls back on its own.
- **Plan-binding.** `act()` sends EXACTLY the edit-config whose digest `plan()` bound; a swap between
  approval and apply is refused (TOCTOU defense), mirroring the Terraform actuator.
- **Secrets external.** NETCONF-over-SSH credentials come from the caller/env, never a repo, never logged.

The live NETCONF session (ncclient) is an OPTIONAL, lazily-imported backend; the offline planner needs no
dependency and works everywhere. We do NOT synthesize the edit-config from the slim model (that would be a
half-right guess) — the operator supplies the NETCONF payload; we grade the target, classify the risk, and
run the apply through the confirmed-commit + post-verify + auto-rollback sequence.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..gateway import ActionClass
from ..verdict.models import Report, Verdict
from .telecom_cfg import _model_from_artifact, grade_cfg
from .telecom_model import NF, Cell, TelecomConfigModel


class NetconfSession(Protocol):
    """The minimal session the actuator drives. The real ncclient backend implements it; tests inject a
    fake. Every method must raise on failure (the actuator treats a raise as fail-closed)."""

    def lock(self, datastore: str) -> None: ...
    def edit_config(self, target: str, config: str) -> None: ...
    def commit(self, *, confirmed: bool = False, timeout: int = 0) -> None: ...
    def discard_changes(self) -> None: ...
    def get_config(self, source: str) -> str: ...
    def unlock(self, datastore: str) -> None: ...
    def close(self) -> None: ...


@dataclass
class TelecomPlan:
    action: ActionClass
    reasons: list[str]
    report: Report                 # grade of the DESIRED config (pre-flight verify)
    edit_config_digest: str        # bound digest of the edit-config payload (empty if plan-only)
    confirm_timeout: int
    edit_config: str = field(default="", repr=False)  # the payload act() will send (not logged)
    desired_model: TelecomConfigModel | None = field(default=None, repr=False)  # bind applied result to it


@dataclass
class ActResult:
    ok: bool
    detail: str
    rolled_back: bool = False


# Lists whose ORDER carries meaning and must NOT be sorted away: 5G security-algorithm PREFERENCE lists
# (position 0 = top priority; the grader reads `ciphering_order[0]`). Sorting them would hide a crypto
# downgrade (e.g. AES-first → SNOW3G-first) from the approval gate (red-team R4).
_ORDER_SIGNIFICANT = frozenset({"ciphering_order", "integrity_order"})


def _norm(o: Any, depth: int = 0, *, ordered: bool = False) -> Any:
    """Provenance-free normalization for comparing two config artifacts on SEMANTICS: drop `loc` markers,
    and sort SET-LIKE list fields (neighbors/BWPs/PLMNs — a device get-config or DU-vs-CU nesting reorders
    them, so an order-sensitive compare would false-rollback a CORRECT apply, red-team R3) WHILE preserving
    the order of `*_order` preference lists (red-team R4). Depth-bounded — a cyclic/pathologically-nested
    structure raises so it fails CLOSED (to IRREVERSIBLE / rollback), never truncates to a false-equal."""
    if depth > 64:
        raise ValueError("config nesting exceeds the comparison depth bound")
    if isinstance(o, dict):
        return {k: _norm(v, depth + 1, ordered=(k in _ORDER_SIGNIFICANT or str(k).endswith("_order")))
                for k, v in o.items() if k != "loc"}
    if isinstance(o, list):
        items = [_norm(x, depth + 1) for x in o]
        return items if ordered else sorted(items, key=lambda x: json.dumps(x, sort_keys=True, default=str))
    return o


def _canon(o: Any) -> str:
    return json.dumps(_norm(o), sort_keys=True, default=str)


# EVERY service-defining attribute is compared — the actuator's approval gate AND its applied-vs-desired
# verification both flow through these, so an omission here is BOTH un-approved AND un-verified
# (red-team R2). Cell identity/RF (PCI, ARFCN, SSB, BW, power, PRACH, neighbors) and NF posture
# (replicas, endpoints, the whole attrs bag: MTU/SUCI/SBI/…) are all in scope.
def _cell_critical(a: Cell, b: Cell) -> list[str]:
    out = []
    fields = [("PLMN", _canon(a.plmns), _canon(b.plmns)), ("TAC", a.tac, b.tac),
              ("S-NSSAI", _canon(a.snssais), _canon(b.snssais)),
              ("PCI", a.pci, b.pci), ("gNB", a.gnb, b.gnb),  # gnb is the co-siting key (red-team R3 Item 1)
              ("DL-ARFCN", a.arfcn_dl, b.arfcn_dl), ("SSB-freq", a.ssb_frequency, b.ssb_frequency),
              ("channel-BW", a.channel_bw_mhz, b.channel_bw_mhz),
              ("max-Tx-power", a.max_tx_power_dbm, b.max_tx_power_dbm),
              ("PRACH", _canon(a.prach), _canon(b.prach)),
              ("neighbors", _canon(a.neighbors), _canon(b.neighbors)),
              ("cell-attrs", _canon(a.attrs), _canon(b.attrs))]
    for label, x, y in fields:
        if x != y:
            out.append(f"cell {a.name}: {label} changed")
    return out


def _served_tais(nf: NF) -> list:
    tais = nf.attrs.get("served_tais")  # AMF: the (PLMN, TAC) it serves — service-defining, read by tac-plmn
    return sorted((str(t.get("plmn")), t.get("tac")) for t in tais) if isinstance(tais, list) else []


def _nf_critical(a: NF, b: NF) -> list[str]:
    out = []
    fields = [("PLMN", sorted(a.plmns), sorted(b.plmns)),
              ("S-NSSAI", sorted(a.snssais), sorted(b.snssais)),
              ("served-TAI", _served_tais(a), _served_tais(b)),
              ("endpoints", _nf_endpoints(a), _nf_endpoints(b)),
              ("replicas", a.replicas, b.replicas),
              # the attrs bag carries MTU / SUCI-scheme / SBI-TLS / … — all service-defining posture
              ("nf-attrs", _canon({k: v for k, v in a.attrs.items() if k != "served_tais"}),
                           _canon({k: v for k, v in b.attrs.items() if k != "served_tais"}))]
    for label, x, y in fields:
        if x != y:
            out.append(f"NF {a.kind}={a.name}: {label} changed")
    return out


def _classify(current: TelecomConfigModel, desired: TelecomConfigModel) -> tuple[ActionClass, list[str]]:
    """IRREVERSIBLE (dry-run + human approval) if the change removes an MO or alters a service-defining
    attribute (PLMN/TAC/S-NSSAI/NF endpoints, on a cell OR an NF); else CONSEQUENTIAL (verdict-gated)."""
    reasons: list[str] = []
    cur_cells = {c.name: c for c in current.cells}
    des_cells = {c.name: c for c in desired.cells}
    for name in cur_cells.keys() - des_cells.keys():
        reasons.append(f"removes cell {name}")
    for name in cur_cells.keys() & des_cells.keys():
        reasons += _cell_critical(cur_cells[name], des_cells[name])
    cur_nf = {(n.kind, n.name): n for n in current.nfs}
    des_nf = {(n.kind, n.name): n for n in desired.nfs}
    for key in cur_nf.keys() - des_nf.keys():
        reasons.append(f"removes NF {key[0]}={key[1]}")
    for key in cur_nf.keys() & des_nf.keys():
        reasons += _nf_critical(cur_nf[key], des_nf[key])
    return (ActionClass.IRREVERSIBLE if reasons else ActionClass.CONSEQUENTIAL), reasons


def _nf_endpoints(nf: NF) -> list:
    return sorted((e.iface, e.subnet) for e in nf.endpoints)


def _matches_desired(running: TelecomConfigModel, desired: TelecomConfigModel) -> list[str]:
    """The applied result must equal the graded/classified DESIRED — otherwise the operator's edit-config
    did something other than produce `desired`, and neither the grade nor the approval covered it
    (red-team F2). Symmetric: any add/remove/critical-change in EITHER direction is a mismatch. Also
    fail-closed on a degenerate running config (0 cells+NFs when desired was non-empty)."""
    if not (running.cells or running.nfs) and (desired.cells or desired.nfs):
        return ["running config is empty/degenerate — apply did not take"]
    _, a = _classify(running, desired)
    _, b = _classify(desired, running)
    return a + b


def _digest(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class TelecomActuator:
    """plan (offline, dry-run) → act (guarded live apply) for a 5G config change."""

    def __init__(self, repo: str, *, rules: str | dict | None = None):
        self.repo = repo
        self.rules = rules

    def plan(self, *, current: str, desired: str, edit_config: str = "",
             confirm_timeout: int = 120, attest: str = "hmac") -> TelecomPlan:
        """OFFLINE. Grade the desired config (pre-flight verify), classify current→desired, and bind the
        edit-config digest. Mutates nothing. `current`/`desired` are repo-relative config artifacts."""
        from .k8s import _read_in_repo  # path-traversal-safe reader

        report = grade_cfg(self.repo, values=desired, rules=self.rules, attest=attest)
        des_model: TelecomConfigModel | None = None
        try:
            cur_model = _model_from_artifact(_read_in_repo(self.repo, current))
            des_model = _model_from_artifact(_read_in_repo(self.repo, desired))
            action, reasons = _classify(cur_model, des_model)
        except Exception as e:  # noqa: BLE001 — ANY read/parse/normalize/recurse failure (incl. a cyclic
            # attrs passthrough → RecursionError, red-team R3 Item 3) fails closed to IRREVERSIBLE.
            action, reasons = ActionClass.IRREVERSIBLE, [f"cannot classify change (fail closed): {e}"]
        dig = _digest(edit_config) if edit_config else ""
        return TelecomPlan(action=action, reasons=reasons, report=report, edit_config_digest=dig,
                           confirm_timeout=confirm_timeout, edit_config=edit_config, desired_model=des_model)

    def act(self, plan: TelecomPlan, *, session: NetconfSession, approved: bool = False) -> ActResult:
        """Guarded LIVE apply of the bound edit-config, act-then-verify with confirmed-commit rollback.

        Refuses (fail closed) unless: an edit-config was bound; its digest still matches (plan-binding);
        and — if the change is IRREVERSIBLE — the caller passed approved=True (human approval). After the
        confirmed-commit, the RUNNING config must both grade non-FAIL AND equal the graded `desired`
        (the applied result is bound to the graded intent) before the change is confirmed permanent."""
        if not plan.edit_config:
            return ActResult(False, "no edit-config bound — plan-only; refused (fail closed)")
        if _digest(plan.edit_config) != plan.edit_config_digest:
            return ActResult(False, "plan-binding mismatch — edit-config changed since plan; refused")
        if plan.desired_model is None:
            return ActResult(False, "desired model unavailable (plan could not classify) — refused")
        if plan.action == ActionClass.IRREVERSIBLE and not approved:
            return ActResult(False, f"IRREVERSIBLE change needs human approval — refused: {plan.reasons}")
        if plan.report.verdict == Verdict.FAIL:
            return ActResult(False, "desired config FAILS the grader — refused (fail closed)")

        try:
            session.lock("candidate")
        except Exception as e:  # noqa: BLE001 — any lock failure is fail-closed, no mutation happened
            return ActResult(False, f"could not lock candidate: {type(e).__name__}: {e}")
        try:
            session.edit_config("candidate", plan.edit_config)
            # confirmed-commit: auto-reverts after confirm_timeout unless we explicitly confirm below
            session.commit(confirmed=True, timeout=plan.confirm_timeout)
            # act-then-verify: the running state must grade non-FAIL AND equal the graded desired; any
            # raise here is caught → treated as a verify failure (fail-closed, red-team F3).
            ok, why = self._verify_running(session, plan.desired_model)
        except Exception as e:  # noqa: BLE001
            _safe(session.discard_changes)
            _safe(session.unlock, "candidate")
            return ActResult(False, f"edit/commit/verify failed, discarded: {type(e).__name__}: {e}",
                             rolled_back=True)
        if not ok:
            _safe(session.discard_changes)  # belt: also let the confirm-timeout auto-revert
            _safe(session.unlock, "candidate")
            return ActResult(False, f"post-apply verify FAILED — rolling back: {why}", rolled_back=True)
        try:
            session.commit(confirmed=False)  # confirm the pending confirmed-commit → make it permanent
            _safe(session.unlock, "candidate")
        except Exception as e:  # noqa: BLE001 — confirm failed → the confirmed-commit auto-reverts
            return ActResult(False, f"confirm failed — will auto-rollback: {type(e).__name__}: {e}",
                             rolled_back=True)
        return ActResult(True, "applied and confirmed (grader-verified, matches desired)")

    def _verify_running(self, session: NetconfSession, desired: TelecomConfigModel) -> tuple[bool, str]:
        import tempfile
        from pathlib import Path
        running = session.get_config("running")  # a raise propagates to act()'s guard → fail-closed
        try:
            run_model = _model_from_artifact(running)  # malformed device output → fail closed
        except (ValueError, FileNotFoundError) as e:
            return False, f"running config unparseable: {type(e).__name__}: {e}"
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "running.xml").write_text(running)
            try:
                rep = grade_cfg(tmp, values="running.xml", rules=self.rules)
            except (ValueError, FileNotFoundError) as e:
                return False, f"could not grade running config: {type(e).__name__}: {e}"
        if rep.verdict == Verdict.FAIL:
            return False, f"running config grades {rep.verdict.value}"
        mismatch = _matches_desired(run_model, desired)
        if mismatch:
            return False, f"running config does not match the graded desired: {mismatch[:3]}"
        return True, "running verified + matches desired"


def _safe(fn, *a) -> None:
    try:
        fn(*a)
    except Exception:  # noqa: BLE001 — best-effort cleanup; never mask the original error
        pass


def ncclient_session(host: str, *, port: int = 830, username: str, key_filename: str | None = None,
                     password: str | None = None, timeout: int = 30) -> NetconfSession:
    """Open a real NETCONF-over-SSH session (lazy ncclient — `pip install verel[telecom-actuator]`).
    Credentials come from the CALLER (env/config), never a repo. Raises Fetchless ImportError guidance if
    ncclient is absent."""
    try:
        from ncclient import manager  # type: ignore[import-untyped]
    except ModuleNotFoundError as e:
        raise RuntimeError("live NETCONF apply needs ncclient: pip install 'verel[telecom-actuator]'") from e
    mgr = manager.connect(host=host, port=port, username=username, key_filename=key_filename,
                          password=password, timeout=timeout, hostkey_verify=True)
    return _NcclientAdapter(mgr)


class _NcclientAdapter:
    """Adapts ncclient's manager to the NetconfSession protocol."""

    def __init__(self, mgr):
        self._m = mgr

    def lock(self, datastore: str) -> None:
        self._m.lock(target=datastore)

    def edit_config(self, target: str, config: str) -> None:
        self._m.edit_config(target=target, config=config)

    def commit(self, *, confirmed: bool = False, timeout: int = 0) -> None:
        if confirmed:
            self._m.commit(confirmed=True, timeout=str(timeout))
        else:
            self._m.commit()

    def discard_changes(self) -> None:
        self._m.discard_changes()

    def get_config(self, source: str) -> str:
        return str(self._m.get_config(source=source))

    def unlock(self, datastore: str) -> None:
        self._m.unlock(target=datastore)

    def close(self) -> None:
        self._m.close_session()
