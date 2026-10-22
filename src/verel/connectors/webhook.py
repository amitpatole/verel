"""Signed outbound webhooks.

Destinations are OPERATOR configuration (never taken from a request or a job payload): a job can only name
a sink id that the operator defined for that tenant. Deliveries are HMAC-signed with a timestamp so
receivers can reject forgeries and replays, redirects are refused, the cloud-metadata / link-local SSRF guard
applies, and the response body is size-capped.

Receiver check (pseudo): `v1=hex(hmac_sha256(secret, f"{timestamp}.{raw_body}"))` must equal the
`X-Verel-Signature` value, and `timestamp` must be within a few minutes of now (`verify_signature`).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import ssl
import time
import urllib.request
import uuid
from dataclasses import dataclass

MAX_BODY = 256 * 1024
MAX_RESPONSE = 64 * 1024


class DeliveryError(RuntimeError):
    def __init__(self, msg: str, *, permanent: bool = False):
        super().__init__(msg)
        self.permanent = permanent


@dataclass(frozen=True)
class Sink:
    url: str
    secret: str
    timeout_s: float = 10.0
    allow_http: bool = False  # plain http only for an internal receiver you explicitly accept


def sign(secret: str, timestamp: str, body: bytes) -> str:
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return f"v1={mac}"


def verify_signature(
    secret: str,
    timestamp: str,
    body: bytes,
    signature: str,
    *,
    tolerance_s: int = 300,
    now: float | None = None,
) -> bool:
    """For receivers: constant-time signature check plus a replay window."""
    try:
        age = abs((time.time() if now is None else now) - int(timestamp))
    except (TypeError, ValueError):
        return False
    mine = sign(secret, timestamp, body).encode()
    return age <= tolerance_s and hmac.compare_digest(mine, (signature or "").encode("utf-8", "replace"))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def deliver(sink: Sink, event: dict) -> int:
    """POST one event. Returns the HTTP status on 2xx; raises `DeliveryError` otherwise
    (`permanent=True` for caller errors that retrying cannot fix)."""
    from ..ci.telecom_fetch import FetchError, _guard_url

    if not sink.secret:
        raise DeliveryError("sink has no secret; refusing to send unsigned webhooks", permanent=True)
    if not (sink.url.startswith("https://") or (sink.allow_http and sink.url.startswith("http://"))):
        raise DeliveryError("sink url must be https (or http with allow_http)", permanent=True)
    try:
        _guard_url(sink.url, allow_link_local=False)
    except FetchError as e:
        raise DeliveryError(str(e), permanent=True) from None
    # the event id lives INSIDE the signed body, so the header copy cannot be forged independently
    event = {**event, "event_id": str(event.get("event_id") or uuid.uuid4().hex)}
    body = json.dumps(event, separators=(",", ":"), sort_keys=True).encode()
    if len(body) > MAX_BODY:
        raise DeliveryError("event too large", permanent=True)
    ts = str(int(time.time()))
    req = urllib.request.Request(
        sink.url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "verel-webhook",
            "X-Verel-Timestamp": ts,
            "X-Verel-Signature": sign(sink.secret, ts, body),
            "X-Verel-Event-Id": event["event_id"],
        },
    )
    opener = urllib.request.build_opener(
        _NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
    )
    try:
        with opener.open(req, timeout=sink.timeout_s) as r:
            r.read(MAX_RESPONSE)
            return int(r.status)
    except urllib.error.HTTPError as e:
        # 4xx (except timeouts / rate limits) will not get better by retrying
        raise DeliveryError(
            f"receiver returned HTTP {e.code}",
            permanent=400 <= e.code < 500 and e.code not in (408, 425, 429),
        ) from None
    except Exception as e:  # noqa: BLE001 - network errors are retryable
        raise DeliveryError(f"delivery failed: {type(e).__name__}") from None
