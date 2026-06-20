"""Hosted skill registry (§2.2) — publish/search/fetch over HTTP, with trust-does-not-travel
preserved end-to-end. Real in-process HTTP server."""

import pytest

from verel.memory import LocalMemory
from verel.registry import (
    RegistryServer,
    RemoteRegistry,
    SkillArtifact,
    export_skill,
    import_skill,
)
from verel.toolsmith import SideEffect, ToolCase, ToolRecord, ToolRegistry

SLUG_CODE = ("def slugify(t):\n    import re\n"
             "    return re.sub(r'[^a-z0-9]+','-',t.lower()).strip('-')\n")


def _artifact():
    tool = ToolRecord(name="slugify", capability="convert a title to a url slug",
                      code=SLUG_CODE, side_effect=SideEffect.READ_ONLY, eval_score=1.0).sign()
    return export_skill(tool, origin="tenant:A")


def _server(tmp_path, token=None):
    return RegistryServer(tmp_path / "registry", auth_token=token).start()


def test_publish_search_fetch_over_http(tmp_path):
    srv = _server(tmp_path)
    try:
        art = _artifact()
        RemoteRegistry(srv.url).publish(art)
        client = RemoteRegistry(srv.url)
        hits = client.search("url slug")
        assert [h.name for h in hits] == ["slugify"]
        fetched = client.get(art.content_hash)
        assert fetched is not None and fetched.verify()  # integrity preserved across the wire
        assert {a.content_hash for a in client.all()} == {art.content_hash}
    finally:
        srv.stop()


def test_trust_does_not_travel_import_reverifies(tmp_path):
    srv = _server(tmp_path)
    try:
        RemoteRegistry(srv.url).publish(_artifact())
        fetched = RemoteRegistry(srv.url).all()[0]
        # matching held-out cases -> re-verified (verified locally)
        good = import_skill(fetched, ToolRegistry(LocalMemory(), scope="B"),
                            target_cases=[ToolCase(args=["Hello World"], expected="hello-world")])
        assert good.reverified
        # failing held-out cases -> installed only as a candidate (did NOT transfer)
        bad = import_skill(fetched, ToolRegistry(LocalMemory(), scope="C"),
                           target_cases=[ToolCase(args=["Hello World"], expected="NOPE")])
        assert not bad.reverified
    finally:
        srv.stop()


def test_server_refuses_a_tampered_artifact(tmp_path):
    srv = _server(tmp_path)
    try:
        art = _artifact()
        tampered = SkillArtifact(**art.model_dump())
        tampered.code = "def slugify(t):\n    return 'pwned'\n"  # content no longer matches signature
        with pytest.raises(ValueError):
            RemoteRegistry(srv.url)._req("POST", "/publish", {"artifact": tampered.model_dump()})
    finally:
        srv.stop()


def test_fetch_unknown_returns_none(tmp_path):
    srv = _server(tmp_path)
    try:
        assert RemoteRegistry(srv.url).get("deadbeef" * 8) is None
    finally:
        srv.stop()


def test_auth_token_gates_access(tmp_path):
    srv = _server(tmp_path, token="secret")
    try:
        RemoteRegistry(srv.url, auth_token="secret").publish(_artifact())  # ok
        with pytest.raises(Exception):
            RemoteRegistry(srv.url, auth_token="wrong").all()
    finally:
        srv.stop()
