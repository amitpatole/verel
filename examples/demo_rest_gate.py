"""Gate over HTTP — any CI, script, or PR webhook can verify, no MCP host (Reach track, R1).

Starts the REST gate server over a tiny repo and shows: a `POST /gate` returns the verdict, and the
GitHub webhook endpoint rejects an unsigned event but accepts an HMAC-signed one. All local, no key.

Run:  python examples/demo_rest_gate.py
"""

from __future__ import annotations

import hashlib
import hmac
import json
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from verel.integrations.rest import GateServer

with tempfile.TemporaryDirectory() as d:
    repo = Path(d)
    (repo / "m.py").write_text("def add(a, b):\n    return a + b\n")
    (repo / "test_m.py").write_text("from m import add\n\ndef test_add():\n    assert add(2, 3) == 5\n")

    secret = "webhook-secret"
    srv = GateServer(str(repo), webhook_secret=secret, lint=False).start()
    try:
        print(f"gate server on {srv.url}  (repo it gates is fixed at startup)\n")

        # 1) language-agnostic gate: POST /gate → verdict
        with urllib.request.urlopen(srv.url + "/gate", data=b"", timeout=20) as r:
            print("POST /gate        →", json.loads(r.read()))

        # 2) GitHub webhook: an UNSIGNED event is refused before any gate runs
        payload = json.dumps({"action": "opened", "number": 1,
                              "repository": {"full_name": "you/app"},
                              "pull_request": {"head": {"sha": "abc1234"}}}).encode()

        def post_github(headers):
            req = urllib.request.Request(srv.url + "/github", data=payload, method="POST",
                                         headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=20) as r:
                    return r.status, json.loads(r.read())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read())

        print("POST /github (forged sig) →", post_github({"X-Hub-Signature-256": "sha256=00"}))

        # 3) a correctly HMAC-signed event → gate runs, verdict returned
        sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        code, body = post_github({"X-Hub-Signature-256": sig})
        print("POST /github (signed)     →", code, "verdict:", body["gate"]["verdict"],
              "sha:", body["event"]["sha"])
    finally:
        srv.stop()

print("\nResult: the gate is reachable over HTTP for any stack; the webhook runs ONLY on a verified "
      "GitHub signature — forged events never trigger CI.")
