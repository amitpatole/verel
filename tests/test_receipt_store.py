"""Tests for DC-01 + DC-02: ReceiptStore — crash-atomic WAL + hash-chained receipt store."""

import json

from verel.verdict import GateReceipt, ReceiptStore, Verdict
from verel.verdict.attest import build_gate_receipt


def _receipt(verdict: Verdict = Verdict.PASS) -> GateReceipt:
    return build_gate_receipt(verdict, [])


def test_wal_written_before_commit(tmp_path):
    store = ReceiptStore(tmp_path)
    store.begin("act-001")
    wal = list(tmp_path.glob("pending-*.wal"))
    assert len(wal) == 1
    data = json.loads(wal[0].read_text())
    assert data["action_id"] == "act-001"
    assert data["status"] == "pending"


def test_wal_cleared_after_commit(tmp_path):
    store = ReceiptStore(tmp_path)
    store.begin("act-002")
    store.commit(_receipt(), "act-002")
    assert store.check_pending() is None
    assert not list(tmp_path.glob("pending-*.wal"))


def test_commit_returns_hex_hash(tmp_path):
    store = ReceiptStore(tmp_path)
    h = store.commit(_receipt(), "act-003")
    assert isinstance(h, str) and len(h) == 64  # sha256 hex


def test_receipt_file_written_atomically(tmp_path):
    store = ReceiptStore(tmp_path)
    h = store.commit(_receipt(), "act-004")
    files = list(tmp_path.glob("**/*.json"))
    assert len(files) == 1
    env = json.loads(files[0].read_text())
    assert env["receipt_hash"] == h
    assert env["action_id"] == "act-004"


def test_head_advances_after_each_commit(tmp_path):
    store = ReceiptStore(tmp_path)
    h1 = store.commit(_receipt(), "act-005a")
    h2 = store.commit(_receipt(), "act-005b")
    assert h1 != h2
    head = (tmp_path / "HEAD").read_text().strip()
    assert head == h2


def test_hash_chain_prev_hash_links(tmp_path):
    store = ReceiptStore(tmp_path)
    store.commit(_receipt(), "act-006a")
    store.commit(_receipt(), "act-006b")

    files = sorted(tmp_path.glob("**/*.json"), key=lambda p: p.stat().st_mtime)
    env0 = json.loads(files[0].read_text())
    env1 = json.loads(files[1].read_text())

    assert env0["prev_hash"] == "genesis"
    assert env1["prev_hash"] == env0["receipt_hash"]


def test_verify_chain_clean(tmp_path):
    store = ReceiptStore(tmp_path)
    store.commit(_receipt(), "act-007a")
    store.commit(_receipt(), "act-007b")
    ok, reason = store.verify_chain()
    assert ok, reason


def test_verify_chain_empty_store(tmp_path):
    store = ReceiptStore(tmp_path)
    ok, reason = store.verify_chain()
    assert ok and reason == "ok"


def test_verify_chain_detects_prev_hash_tamper(tmp_path):
    store = ReceiptStore(tmp_path)
    store.commit(_receipt(), "act-008a")
    store.commit(_receipt(), "act-008b")

    files = sorted(tmp_path.glob("**/*.json"), key=lambda p: p.stat().st_mtime)
    # Tamper with the second receipt's prev_hash
    env = json.loads(files[1].read_text())
    env["prev_hash"] = "deadbeef" * 8
    files[1].write_text(json.dumps(env))

    ok, reason = store.verify_chain()
    assert not ok
    assert "chain break" in reason


def test_check_pending_returns_none_without_wal(tmp_path):
    store = ReceiptStore(tmp_path)
    assert store.check_pending() is None


def test_check_pending_returns_action_id(tmp_path):
    store = ReceiptStore(tmp_path)
    store.begin("unfinished-action")
    assert store.check_pending() == "unfinished-action"


def test_iter_receipts(tmp_path):
    store = ReceiptStore(tmp_path)
    store.commit(_receipt(), "act-010a")
    store.commit(_receipt(Verdict.FAIL), "act-010b")
    envelopes = list(store.iter_receipts())
    assert len(envelopes) == 2
    action_ids = {e["action_id"] for e in envelopes}
    assert action_ids == {"act-010a", "act-010b"}


def test_env_var_override(tmp_path, monkeypatch):
    monkeypatch.setenv("QUINE_RECEIPT_STORE", str(tmp_path))
    import importlib

    from verel.verdict import store as store_mod
    importlib.reload(store_mod)
    # After reload, _DEFAULT_ROOT should pick up the env var
    assert str(store_mod._DEFAULT_ROOT) == str(tmp_path)
    importlib.reload(store_mod)  # cleanup — restore module state for other tests


def test_action_id_sanitized_in_path(tmp_path):
    store = ReceiptStore(tmp_path)
    store.commit(_receipt(), "act/../../../etc/passwd")
    files = list(tmp_path.glob("**/*.json"))
    assert len(files) == 1
    # The path must stay inside tmp_path — no directory traversal
    assert files[0].is_relative_to(tmp_path)


def test_receipt_kind_committed_in_committed_receipt(tmp_path):
    """DC-04 smoke: a receipt committed to the store has COMMITTED kind by default."""
    from verel.verdict.models import ReceiptKind
    store = ReceiptStore(tmp_path)
    r = _receipt()
    assert r.receipt_kind == ReceiptKind.COMMITTED
    store.commit(r, "act-kind-001")
    files = list(tmp_path.glob("**/*.json"))
    env = json.loads(files[0].read_text())
    assert env["receipt"]["receipt_kind"] == "committed"
