"""Phase 5 item 3 — live acquisition helper (Prometheus scrape / PromQL query). Network fully mocked;
the grader itself never touches the network. Focus: SSRF/scheme/size guards + the PromQL→JSON mapping."""
from __future__ import annotations

import json
import socket

import pytest

from verel.ci import telecom_fetch as tf


def _addrinfo(ip):
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443))]


# --------------------------------------------------------------------------- SSRF / scheme guard
def test_guard_rejects_nonhttp_scheme():
    with pytest.raises(tf.FetchError, match="scheme"):
        tf._guard_url("ftp://host/x", allow_link_local=False)
    with pytest.raises(tf.FetchError, match="scheme"):
        tf._guard_url("file:///etc/passwd", allow_link_local=False)


def test_guard_blocks_cloud_metadata_link_local(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo("169.254.169.254"))
    with pytest.raises(tf.FetchError, match="metadata|link-local"):
        tf._guard_url("http://metadata/latest", allow_link_local=False)
    # 169.254.169.254 is the metadata IP → denylisted regardless of allow_link_local
    with pytest.raises(tf.FetchError, match="metadata"):
        tf._guard_url("http://metadata/latest", allow_link_local=True)
    # a generic (non-metadata) link-local IS permitted with the override
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo("169.254.5.5"))
    tf._guard_url("http://ll/latest", allow_link_local=True)


def test_guard_allows_private_and_public(monkeypatch):
    for ip in ("10.0.0.5", "192.168.1.9", "8.8.8.8", "127.0.0.1"):  # operator Prometheus is often private/loopback
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, ip=ip, **k: _addrinfo(ip))
        tf._guard_url(f"http://{ip}:9090/metrics", allow_link_local=False)  # no raise


def test_guard_blocks_ipv6_and_mapped_metadata(monkeypatch):
    # red-team F1: AWS IMDSv2 over IPv6 (ULA, not link-local) + NAT64-embedded metadata
    for ip in ("fd00:ec2::254", "64:ff9b::a9fe:a9fe"):
        monkeypatch.setattr(socket, "getaddrinfo",
                            lambda *a, ip=ip, **k: [(socket.AF_INET6, socket.SOCK_STREAM,
                                                     socket.IPPROTO_TCP, "", (ip, 443, 0, 0))])
        with pytest.raises(tf.FetchError, match="metadata|link-local"):
            tf._guard_url(f"http://[{ip}]/latest", allow_link_local=False)
    # red-team F2: IPv4-mapped IPv6 of the metadata IP must be normalized + blocked (bypass on <3.12.4)
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
                                          ("::ffff:169.254.169.254", 443, 0, 0))])
    with pytest.raises(tf.FetchError, match="metadata|link-local"):
        tf._guard_url("http://[::ffff:169.254.169.254]/", allow_link_local=False)


def test_guard_blocks_6to4_teredo_and_oracle(monkeypatch):
    # red-team R2: 6to4 (2002:a9fe:a9fe:: embeds 169.254.169.254) and Oracle OCI 192.0.0.192
    for ip in ("2002:a9fe:a9fe::", "192.0.0.192"):
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        addr = (ip, 443, 0, 0) if ":" in ip else (ip, 443)
        monkeypatch.setattr(socket, "getaddrinfo",
                            lambda *a, fam=fam, addr=addr, **k: [(fam, socket.SOCK_STREAM,
                                                                  socket.IPPROTO_TCP, "", addr)])
        host = f"[{ip}]" if ":" in ip else ip
        with pytest.raises(tf.FetchError, match="metadata|link-local"):
            tf._guard_url(f"http://{host}/latest", allow_link_local=False)


def test_guard_no_false_block_on_legit_targets():
    # the embedding accessors must NOT false-block a legitimate public/private IPv6 or v4
    import ipaddress
    for ip in ("8.8.8.8", "10.0.0.5", "192.168.1.1", "2606:4700::6810:85e5", "2002:0808:0808::"):
        assert tf._blocked_reason(ipaddress.ip_address(ip), False) is None, ip


def test_query_prometheus_drops_non_finite(monkeypatch):
    # red-team F3: NaN/Inf must be dropped, not written as RFC-8259-invalid JSON tokens
    prom = {"status": "success", "data": {"result": [
        {"metric": {"__name__": "ok"}, "value": [1, "5"]},
        {"metric": {"__name__": "nan"}, "value": [1, "NaN"]},
        {"metric": {"__name__": "inf"}, "value": [1, "Infinity"]},
    ]}}
    monkeypatch.setattr(tf, "_get", lambda *a, **k: json.dumps(prom).encode())
    out = tf.query_prometheus("https://prom", "up")
    assert "NaN" not in out and "Infinity" not in out
    doc = json.loads(out)  # strict parse succeeds
    assert {s["kpi"] for s in doc["samples"]} == {"ok"}


def test_guard_unresolvable_host(monkeypatch):
    def boom(*a, **k):
        raise socket.gaierror("nope")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    with pytest.raises(tf.FetchError, match="resolve"):
        tf._guard_url("http://nonexistent.invalid/metrics", allow_link_local=False)


# --------------------------------------------------------------------------- scrape / size cap
def test_scrape_returns_text(monkeypatch):
    monkeypatch.setattr(tf, "_get", lambda *a, **k: b"metric_a 1\nmetric_b 2\n")
    assert tf.scrape("https://prom/metrics") == "metric_a 1\nmetric_b 2\n"


def test_get_enforces_size_cap(monkeypatch):
    # simulate the opener returning more than max_bytes → FetchError, never buffered whole
    class _Resp:
        status = 200
        def read(self, n):
            return b"x" * n  # always returns the full requested count → looks oversized
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    class _Opener:
        def open(self, req, timeout):
            return _Resp()
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo("8.8.8.8"))
    monkeypatch.setattr(tf.urllib.request, "build_opener", lambda *a, **k: _Opener())
    with pytest.raises(tf.FetchError, match="max_bytes"):
        tf._get("https://prom/metrics", timeout=1, max_bytes=1024, verify_tls=True, allow_link_local=False)


def test_get_rejects_redirect(monkeypatch):
    class _Resp:
        status = 302
        def read(self, n):
            return b""
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    class _Opener:
        def open(self, req, timeout):
            return _Resp()
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _addrinfo("8.8.8.8"))
    monkeypatch.setattr(tf.urllib.request, "build_opener", lambda *a, **k: _Opener())
    with pytest.raises(tf.FetchError, match="redirects are disabled|HTTP 30"):
        tf._get("https://prom/metrics", timeout=1, max_bytes=1024, verify_tls=True, allow_link_local=False)


# --------------------------------------------------------------------------- PromQL → JSON mapping
def test_query_prometheus_maps_to_grader_json(monkeypatch):
    prom = {"status": "success", "data": {"resultType": "vector", "result": [
        {"metric": {"__name__": "fivegs_amffunction_rm_reginitsucc", "nf": "amf-1"}, "value": [1.0, "410"]},
        {"metric": {"__name__": "fivegs_amffunction_rm_reginitreq", "nf": "amf-1"}, "value": [1.0, "1000"]},
        {"metric": {"__name__": "bad"}, "value": ["only-one"]},  # malformed → dropped
    ]}}
    monkeypatch.setattr(tf, "_get", lambda *a, **k: json.dumps(prom).encode())
    out = tf.query_prometheus("https://prom", "up")
    doc = json.loads(out)
    samples = {s["kpi"]: s for s in doc["samples"]}
    assert set(samples) == {"fivegs_amffunction_rm_reginitsucc", "fivegs_amffunction_rm_reginitreq"}
    assert samples["fivegs_amffunction_rm_reginitsucc"]["value"] == 410.0
    assert samples["fivegs_amffunction_rm_reginitsucc"]["dims"] == {"nf": "amf-1"}


def test_query_prometheus_rejects_error_status(monkeypatch):
    monkeypatch.setattr(tf, "_get", lambda *a, **k: b'{"status":"error","error":"bad query"}')
    with pytest.raises(tf.FetchError, match="not successful"):
        tf.query_prometheus("https://prom", "))(")


def test_end_to_end_query_output_grades(monkeypatch, tmp_path):
    # the fetched JSON, mapped via open5gs, grades through the OFFLINE grader (proving the seam)
    from verel.ci.telecom_kpi import grade_kpi
    pytest.importorskip("yaml")
    prom = {"status": "success", "data": {"result": [
        {"metric": {"__name__": "fivegs_amffunction_rm_reginitsucc", "nf": "a"}, "value": [1, "410"]},
        {"metric": {"__name__": "fivegs_amffunction_rm_reginitreq", "nf": "a"}, "value": [1, "1000"]},
    ]}}
    monkeypatch.setattr(tf, "_get", lambda *a, **k: json.dumps(prom).encode())
    (tmp_path / "m.json").write_text(tf.query_prometheus("https://prom", "up"))
    rep = grade_kpi(str(tmp_path), metrics="m.json", fmt="json", mapping="open5gs",
                    thresholds={"RM.RegInitSuccRate": {"min": 0.99, "min_samples": 1}})
    assert any(i.kind.value == "threshold_breach" and "RegInitSucc" in i.message for i in rep.issues)
