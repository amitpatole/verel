"""Live metrics acquisition (Phase 5 item 3) — scrape a Prometheus/OpenMetrics endpoint or run a PromQL
query, and WRITE a metrics file the OFFLINE KPI grader then reads. Acquisition is deliberately SEPARATE
from grading: the grader stays pure/deterministic/offline (it never touches the network); this helper is
the only network-facing piece, and its output is a plain file you can commit, inspect, and re-grade.

Security posture (this DOES talk to the network — the grader does not):
- scheme allowlist (http/https only); redirects DISABLED (a 3xx is an error) so a redirect can't bounce
  the request to an internal target after the pre-check;
- SSRF guard: the host is resolved and every address REJECTED if it is link-local (169.254/fe80) unless
  `allow_link_local=True`, OR a known cloud-metadata address (incl. AWS IMDSv2-over-IPv6 `fd00:ec2::254`
  and NAT64-embedded), with IPv4-mapped-IPv6 normalized so the classification can't be dodged;
- bounded read (`max_bytes`, streamed — never allocate an unbounded response), connect+read `timeout`,
  TLS verification on by default (`verify_tls=False` only with an explicit opt-out).
Residual (honest): DNS-rebinding TOCTOU between the resolve-check and the socket connect is not fully
closed — do NOT point this at an untrusted/attacker-supplied URL; it is an operator tool for your own
Prometheus. The GRADER remains offline regardless.
"""

from __future__ import annotations

import ipaddress
import json
import math
import socket
import ssl
import urllib.request
from collections.abc import Iterator
from ipaddress import IPv4Address, IPv6Address
from urllib.parse import urlparse

_MAX_BYTES = 32 * 1024 * 1024  # 32 MiB response cap (a metrics scrape is small; larger is pathological)
_TIMEOUT = 15.0


class FetchError(RuntimeError):
    """Any acquisition failure — surfaced as a clean CLI error, never a raw traceback."""


# Known cloud instance-metadata addresses that are NOT caught by is_link_local (red-team F1): AWS IMDSv2
# over IPv6 is a unique-local (ULA) address; Alibaba uses a public-looking IP. Denylisted explicitly so we
# don't have to block all of ULA/private (operator Prometheus legitimately lives there).
# AWS/GCP/Azure 169.254.169.254 · AWS IMDSv2-over-IPv6 fd00:ec2::254 (ULA) · Alibaba 100.100.100.200 ·
# Oracle OCI legacy 192.0.0.192 (routable, not link-local). The denylist can't enumerate every cloud's
# metadata IP — the honesty header's "operator tool, not for untrusted URLs" covers the unknown-cloud tail.
_METADATA = {ipaddress.ip_address(x) for x in
             ("169.254.169.254", "fd00:ec2::254", "100.100.100.200", "192.0.0.192")}
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _embedded_v4(ip: IPv4Address | IPv6Address) -> Iterator[IPv4Address]:
    """Any IPv4 an IPv6 address embeds — so a metadata/link-local target can't hide inside a v6 wrapper
    (IPv4-mapped ::ffff: / 6to4 2002:: / Teredo 2001:: / NAT64 64:ff9b::). Accessors return None for
    non-matching prefixes, so a legitimate GUA yields nothing (no false-positive). Red-team F2/R2."""
    if not isinstance(ip, IPv6Address):
        return
    for got in (ip.ipv4_mapped, ip.sixtofour):
        if got:
            yield got
    if ip.teredo:
        yield from ip.teredo
    if ip in _NAT64:
        yield IPv4Address(int(ip) & 0xFFFFFFFF)  # low 32 bits are the embedded IPv4


def _blocked_reason(ip: IPv4Address | IPv6Address, allow_link_local: bool) -> str | None:
    cands = [ip, *_embedded_v4(ip)]
    if any(c in _METADATA for c in cands):
        return f"cloud-metadata address {ip}"
    if not allow_link_local and any(c.is_link_local for c in cands):  # 169.254.0.0/16 / fe80::/10
        return f"link-local {ip}"
    return None


def _guard_url(url: str, *, allow_link_local: bool) -> None:
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise FetchError(f"unsupported scheme {p.scheme!r} (http/https only)")
    host = p.hostname
    if not host:
        raise FetchError("URL has no host")
    port = p.port or (443 if p.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise FetchError(f"cannot resolve host {host!r}: {e}") from e
    for info in infos:  # check EVERY resolved address (a host can return public + metadata)
        reason = _blocked_reason(ipaddress.ip_address(info[4][0]), allow_link_local)
        if reason:
            raise FetchError(f"refusing {reason} (cloud-metadata/SSRF guard; "
                             "pass allow_link_local to override link-local)")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # a metrics endpoint must not redirect; a 3xx is an error
        return None


def _get(url: str, *, timeout: float, max_bytes: int, verify_tls: bool, allow_link_local: bool) -> bytes:
    _guard_url(url, allow_link_local=allow_link_local)
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, headers={"User-Agent": "verel-telecom-fetch", "Accept": "*/*"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            if resp.status and resp.status >= 300:
                raise FetchError(f"HTTP {resp.status} (redirects are disabled)")
            buf = resp.read(max_bytes + 1)
    except FetchError:
        raise
    except Exception as e:  # URLError, HTTPError, socket.timeout, ssl.SSLError, …
        raise FetchError(f"fetch failed: {type(e).__name__}: {e}") from e
    if len(buf) > max_bytes:
        raise FetchError(f"response exceeds max_bytes ({max_bytes}); refusing to buffer")
    return buf


def scrape(url: str, *, timeout: float = _TIMEOUT, max_bytes: int = _MAX_BYTES,
           verify_tls: bool = True, allow_link_local: bool = False) -> str:
    """GET a raw Prometheus/OpenMetrics exposition endpoint → its text (grade with `--fmt openmetrics`)."""
    return _get(url, timeout=timeout, max_bytes=max_bytes, verify_tls=verify_tls,
                allow_link_local=allow_link_local).decode("utf-8", "replace")


def query_prometheus(base_url: str, query: str, *, timeout: float = _TIMEOUT, max_bytes: int = _MAX_BYTES,
                     verify_tls: bool = True, allow_link_local: bool = False) -> str:
    """Run a PromQL instant query against a Prometheus server's HTTP API and return a JSON metrics file
    (`{"samples":[{kpi,value,dims}]}`) the KPI grader reads with `--fmt json`. The `kpi` is the PromQL
    result's `__name__` (map vendor names via `--mapping`); other labels become dims."""
    from urllib.parse import quote
    u = base_url.rstrip("/") + "/api/v1/query?query=" + quote(query)
    raw = _get(u, timeout=timeout, max_bytes=max_bytes, verify_tls=verify_tls,
               allow_link_local=allow_link_local)
    try:
        doc = json.loads(raw)
    except (json.JSONDecodeError, RecursionError) as e:
        raise FetchError(f"invalid Prometheus JSON: {type(e).__name__}") from e
    if not (isinstance(doc, dict) and doc.get("status") == "success"):
        raise FetchError(f"Prometheus query not successful: {(doc or {}).get('error', 'unknown')}")
    result = (doc.get("data") or {}).get("result") or []
    samples = []
    for r in result if isinstance(result, list) else []:
        metric = r.get("metric") if isinstance(r, dict) else None
        value = r.get("value") if isinstance(r, dict) else None  # [ts, "val"] instant vector
        if not isinstance(metric, dict) or not isinstance(value, list) or len(value) != 2:
            continue
        name = str(metric.get("__name__", "")).strip()
        try:
            val = float(value[1])
        except (TypeError, ValueError):
            continue
        if not name or not math.isfinite(val):  # drop NaN/±Inf (Prometheus staleness) — non-finite would
            continue                             # write RFC-8259-invalid JSON and never breach a threshold
        dims = {str(k): str(v) for k, v in metric.items() if k != "__name__"}
        samples.append({"kpi": name, "value": val, "dims": dims})
    return json.dumps({"samples": samples}, sort_keys=True, allow_nan=False)
