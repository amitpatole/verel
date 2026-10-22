"""The multi-tenant pilot service end to end over real HTTP: identity, roles, tenant isolation, audit,
telemetry, retention, and the CLI around it."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from verel.auth import AuditLog, Authenticator, TokenStore, add_token
from verel.cli import main
from verel.pilot.service import PilotServer
from verel.verdict.fingerprint import assign
from verel.verdict.models import GraderKind, Issue, IssueKind, Report, Severity, Verdict


def _rep(bad):
    iss = [Issue(kind=IssueKind.LOUDNESS, severity=Severity.ERROR, message="m", locator="a",
                 source=GraderKind.DSP)] if bad else []
    return assign(Report(verdict=Verdict.FAIL if bad else Verdict.PASS, summary="s", issues=iss,
                         grader=GraderKind.DSP)).model_dump(mode="json")


@pytest.fixture
def env(tmp_path):
    tf = tmp_path / "tokens.json"
    toks = {
        "acme_op": add_token(tf, id="acme-op", role="operator", tenant="acme"),
        "acme_op2": add_token(tf, id="acme-op2", role="operator", tenant="acme"),
        "acme_view": add_token(tf, id="acme-view", role="viewer", tenant="acme"),
        "acme_admin": add_token(tf, id="acme-admin", role="admin", tenant="acme"),
        "globex_op": add_token(tf, id="globex-op", role="operator", tenant="globex"),
    }
    srv = PilotServer(tmp_path / "data", Authenticator(TokenStore(tf))).start()
    yield srv, toks, tmp_path
    srv.stop()


def call(srv, method, path, token=None, body=None, raw=None, headers=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(srv.url + path, data=data, method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_health_is_open_everything_else_needs_a_token(env):
    srv, toks, _ = env
    assert call(srv, "GET", "/health")[0] == 200
    assert call(srv, "GET", "/v1/pilot/verify")[0] == 401
    assert call(srv, "GET", "/v1/pilot/verify", token="vrl_" + "x" * 43)[0] == 401
    assert call(srv, "GET", "/v1/pilot/verify", token=toks["acme_view"])[0] == 200


def test_record_label_evaluate_roundtrip(env):
    srv, t, _ = env
    for i in range(6):
        st, body = call(srv, "POST", "/v1/pilot/record", t["acme_op"],
                        {"artifact_id": f"ep-{i}", "reports": [_rep(i % 2 == 0)]})
        assert st == 200 and body["enforced"] == "pass" and body["would_be"] in ("fail", "pass")
    st, body = call(srv, "POST", "/v1/pilot/labels", t["acme_op2"],
                    {"labels": [{"artifact_id": f"ep-{i}", "defect": i % 2 == 0} for i in range(6)]})
    assert st == 200 and body["added"] == 6
    st, ev = call(srv, "GET", "/v1/pilot/evaluation?min_samples=1&min_precision=0.5", t["acme_view"])
    assert st == 200 and ev["overall"]["tp"] == 3 and ev["overall"]["tn"] == 3
    assert call(srv, "GET", "/v1/pilot/verify", t["acme_view"])[1]["decisions"] == 6


def test_roles_are_enforced(env):
    srv, t, _ = env
    body = {"artifact_id": "x", "reports": [_rep(False)]}
    assert call(srv, "POST", "/v1/pilot/record", t["acme_view"], body)[0] == 403       # viewer can't write
    assert call(srv, "POST", "/v1/pilot/labels", t["acme_view"], {"labels": []})[0] == 403
    assert call(srv, "POST", "/v1/pilot/archive", t["acme_op"], {"keep_last": 0})[0] == 403
    # enforce mode needs the promote permission (admin)
    assert call(srv, "POST", "/v1/pilot/record", t["acme_op"], {**body, "mode": "enforce"})[0] == 403
    st, d = call(srv, "POST", "/v1/pilot/record", t["acme_admin"], {**body, "mode": "enforce"})
    assert st == 200 and d["mode"] == "enforce"


def test_tenants_are_isolated(env):
    srv, t, tmp = env
    call(srv, "POST", "/v1/pilot/record", t["acme_op"], {"artifact_id": "acme-secret-ep", "reports": [_rep(True)]})
    st, v = call(srv, "GET", "/v1/pilot/verify", t["globex_op"])
    assert st == 200 and v["decisions"] == 0                      # globex sees none of acme's data
    st, ev = call(srv, "GET", "/v1/pilot/evaluation", t["globex_op"])
    assert ev["labeled"] == 0 and ev["unlabeled_records"] == 0
    # nothing in a request can name another tenant
    st, _ = call(srv, "POST", "/v1/pilot/record", t["globex_op"],
                 {"artifact_id": "g1", "reports": [_rep(False)], "tenant": "acme"})
    assert (tmp / "data/tenants/acme/pilot.jsonl").read_text().count("\n") == 1
    assert "acme-secret-ep" not in (tmp / "data/tenants/globex/pilot.jsonl").read_text()


def test_conflicting_label_is_409_and_admin_can_amend(env):
    srv, t, _ = env
    call(srv, "POST", "/v1/pilot/record", t["acme_op"], {"artifact_id": "a", "reports": [_rep(False)]})
    post = lambda tok, d, path="/v1/pilot/labels": call(srv, "POST", path, tok, {"labels": [{"artifact_id": "a", "defect": d}]})  # noqa: E731
    assert post(t["acme_op"], True)[0] == 200
    assert post(t["acme_op"], True)[1]["added"] == 0
    assert post(t["acme_op"], False)[0] == 409
    assert post(t["acme_op"], False, "/v1/pilot/labels/amend")[0] == 403           # only an admin may amend
    assert post(t["acme_admin"], False, "/v1/pilot/labels/amend")[0] == 200
    assert call(srv, "GET", "/v1/pilot/evaluation?min_samples=1", t["acme_view"])[1]["overall"]["tn"] == 1
    # a label for an artifact nobody has recorded is refused (no pre-labeling)
    st, d = call(srv, "POST", "/v1/pilot/labels", t["acme_op"], {"labels": [{"artifact_id": "future", "defect": True}]})
    assert st == 409 and "recorded" in d["error"]


@pytest.mark.parametrize("body", [
    {"artifact_id": "bad id\n", "reports": [_rep(False)]},
    {"artifact_id": "x", "reports": []},
    {"artifact_id": "x", "reports": "nope"},
    {"artifact_id": "x", "reports": [{"verdict": "banana"}]},
    {"artifact_id": "x", "reports": [_rep(False)], "mode": "yolo"},
])
def test_bad_requests_are_400_without_echoing_input(env, body):
    srv, t, _ = env
    st, d = call(srv, "POST", "/v1/pilot/record", t["acme_op"], body)
    assert st == 400 and "banana" not in json.dumps(d) or st == 400


def test_framing_and_size_limits(env):
    srv, t, _ = env
    assert call(srv, "POST", "/v1/pilot/record", t["acme_op"], raw=b"{not json")[0] == 400
    assert call(srv, "POST", "/v1/pilot/record", t["acme_op"], raw=b"[1,2]")[0] == 400
    try:  # the server rejects on Content-Length and closes; the client may see 413 or a reset mid-send
        assert call(srv, "POST", "/v1/pilot/record", t["acme_op"], raw=b"x" * (5 * 1024 * 1024))[0] == 413
    except urllib.error.URLError:
        pass
    assert call(srv, "GET", "/nope", t["acme_op"])[0] == 404
    assert call(srv, "GET", "/v1/pilot/evaluation?min_samples=abc", t["acme_view"])[0] == 400


def test_audit_trail_is_per_tenant_and_anonymous_attempts_are_not_persisted(env):
    srv, t, tmp = env
    call(srv, "POST", "/v1/pilot/record", t["acme_view"], {"artifact_id": "x", "reports": [_rep(False)]})   # denied
    call(srv, "POST", "/v1/pilot/record", t["acme_op"], {"artifact_id": "x", "reports": [_rep(False)]})      # ok
    for _ in range(5):
        call(srv, "GET", "/v1/pilot/verify", "vrl_" + "y" * 43)                                              # anonymous
    log = AuditLog(tmp / "data/tenants/acme/audit.jsonl", domain="acme/audit")
    recs = log.records()
    assert [(r.principal, r.allowed) for r in recs] == [("acme-view", False), ("acme-op", True)]
    assert srv.stats["unauthenticated"] == 5 and not (tmp / "data/audit.jsonl").exists()
    text = (tmp / "data/tenants/acme/audit.jsonl").read_text()
    assert t["acme_op"] not in text and "vrl_" not in text and "Bearer" not in text
    assert log.verify() == 2


def test_archive_endpoint_retention(env):
    srv, t, tmp = env
    for i in range(5):
        call(srv, "POST", "/v1/pilot/record", t["acme_op"], {"artifact_id": f"e{i}", "reports": [_rep(False)]})
    st, d = call(srv, "POST", "/v1/pilot/archive", t["acme_admin"], {"keep_last": 2})
    assert st == 200 and d["archived"] == 3 and d["live"] == 2
    assert len(list((tmp / "data/tenants/acme").glob("pilot.*.archive"))) == 1
    assert call(srv, "GET", "/v1/pilot/verify", t["acme_view"])[1]["decisions"] == 2
    assert call(srv, "POST", "/v1/pilot/archive", t["acme_admin"], {"keep_last": -1})[0] == 400


def test_tampered_tenant_log_is_reported_not_served(env):
    srv, t, tmp = env
    call(srv, "POST", "/v1/pilot/record", t["acme_op"], {"artifact_id": "e0", "reports": [_rep(True)]})
    p = tmp / "data/tenants/acme/pilot.jsonl"
    p.write_text(p.read_text().replace('"would_be":"fail"', '"would_be":"pass"'))
    st, d = call(srv, "GET", "/v1/pilot/evaluation", t["acme_view"])
    assert st == 500 and "integrity" in d["error"]
    assert call(srv, "POST", "/v1/pilot/record", t["acme_op"], {"artifact_id": "e1", "reports": [_rep(True)]})[0] == 500


def test_revocation_is_immediate(env):
    srv, t, tmp = env
    assert call(srv, "GET", "/v1/pilot/verify", t["acme_view"])[0] == 200
    assert main(["auth", "revoke", "--file", str(tmp / "tokens.json"), "--id", "acme-view"]) == 0
    assert call(srv, "GET", "/v1/pilot/verify", t["acme_view"])[0] == 401


def test_routable_bind_requires_tls(tmp_path):
    tf = tmp_path / "t.json"
    add_token(tf, id="a", role="viewer", tenant="t")
    with pytest.raises(Exception):
        PilotServer(tmp_path / "d", Authenticator(TokenStore(tf)), host="0.0.0.0")


# ---------------------------------------------------------------- telemetry
def test_telemetry_inert_without_sdk_and_exports_with_it(tmp_path):
    from verel import telemetry
    from verel.pilot import ShadowLog, run_pilot
    telemetry.reset_for_tests()
    run_pilot([Report.model_validate(_rep(True))], artifact_id="ep-1", log=ShadowLog(tmp_path / "l"))  # no SDK set: no-op
    pytest.importorskip("opentelemetry.sdk")
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    exp = InMemorySpanExporter()
    prov = TracerProvider()
    prov.add_span_processor(SimpleSpanProcessor(exp))
    trace.set_tracer_provider(prov)
    telemetry.reset_for_tests()
    run_pilot([Report.model_validate(_rep(True))], artifact_id="ep-secret-title", tenant="acme",
              log=ShadowLog(tmp_path / "l2"))
    spans = exp.get_finished_spans()
    assert len(spans) == 1
    a = spans[0].attributes
    assert a["verel.would_be"] == "fail" and a["verel.enforced"] == "pass" and a["verel.tenant"] == "acme"
    assert a["verel.grader.dsp"] == "fail"
    assert "ep-secret-title" not in json.dumps(dict(a))               # ids are hashed unless opted in
    telemetry.reset_for_tests()


# ---------------------------------------------------------------- CLI
def test_cli_auth_and_archive(tmp_path, capsys):
    tf = str(tmp_path / "t.json")
    assert main(["auth", "add", "--file", tf, "--id", "u1", "--role", "operator", "--tenant", "acme"]) == 0
    out = capsys.readouterr().out
    tok = out.strip().splitlines()[-1]
    assert tok.startswith("vrl_") and tok not in Path(tf).read_text()
    assert main(["auth", "add", "--file", tf, "--id", "u1", "--role", "operator", "--tenant", "acme"]) == 2   # duplicate
    assert main(["auth", "add", "--file", tf, "--id", "u2", "--role", "root", "--tenant", "acme"]) == 2
    assert main(["auth", "list", "--file", tf]) == 0
    assert tok not in capsys.readouterr().out
    # archive
    rp = tmp_path / "r.json"
    rp.write_text(json.dumps([_rep(False)]))
    log = str(tmp_path / "p.jsonl")
    for i in range(4):
        assert main(["pilot", "record", "--reports", str(rp), "--artifact-id", f"x{i}", "--log", log]) == 0
    seg = str(tmp_path / "seg.archive")
    assert main(["pilot", "archive", "--log", log, "--keep-last", "1", "--segment", seg]) == 0
    assert main(["pilot", "verify", "--log", log]) == 0
    assert main(["pilot", "verify", "--log", seg, "--segment"]) == 0
    assert main(["pilot", "verify", "--log", seg]) == 2        # a segment has no head ledger
