#!/usr/bin/env python3
"""Back-compat shim — the metrics dashboard now ships in the package as `verel.dashboard`
(run it via the `verel-dashboard` console script). This keeps an existing `python
tools/metrics_dashboard.py` / systemd invocation working.

NOTE: the bind is now fail-closed — it defaults to loopback (127.0.0.1). To serve on the LAN set
VEREL_DASHBOARD_HOST + VEREL_DASHBOARD_TOKEN + VEREL_DASHBOARD_CERT/KEY (a routable bind requires auth
AND TLS). See verel/dashboard.py.
"""
from verel.dashboard import main

if __name__ == "__main__":
    raise SystemExit(main())
