#!/usr/bin/env bash
# Local mirror of .github/workflows/policy.yml — render every Verel workload and audit it on Polaris,
# kube-linter, and kube-score. Needs: helm, kube-linter, kube-score, polaris, and verel[operator] +
# pyyaml on PATH/in the venv. Exits non-zero on any Danger / finding / CRITICAL.
set -euo pipefail
cd "$(dirname "$0")/../.."

PY="${PY:-.venv/bin/python}"
CHART_IGNORE="container-image-pull-policy"
OP_IGNORE="container-image-pull-policy,deployment-has-poddisruptionbudget"

R="$(mktemp -d)"; trap 'rm -rf "$R"' EXIT
helm template v deploy/chart --set tls.secretName=verel-tls --set auth.token=t --set replicaCount=2 > "$R/chart-tls.yaml"
helm template v deploy/chart --set tls.insecure=true     --set auth.token=t --set replicaCount=2 > "$R/chart-insecure.yaml"
"$PY" - "$R" <<'PY'
import sys, yaml
from verel.operator.jobs import build_gaterun_job, build_gaterun_netpol
from verel.operator.deployments import (build_gateway_deployment, build_service,
                                        build_fleet_deployment, build_workload_netpol)
o = {"apiVersion":"verel.dev/v1alpha1","kind":"GateRun","name":"gr1","uid":"u","controller":True}
docs = [build_gaterun_job("gr1","verel",{"repo":"https://github.com/o/r"},owner=o),
        build_gaterun_netpol("gr1","verel",owner=o),
        build_gateway_deployment("gw","verel",{},owner=o), build_service("gw","verel",owner=o),
        build_workload_netpol("gw","verel",owner=o),
        build_fleet_deployment("fl","verel",{"brain":"main"},owner=o),
        build_workload_netpol("fl","verel",owner=o,same_namespace_only=True)]
open(f"{sys.argv[1]}/operator-workloads.yaml","w").write(yaml.safe_dump_all(docs))
PY
{ cat deploy/operator/operator.yaml; echo '---'; cat deploy/operator/rbac.yaml; } > "$R/operator-all.yaml"

echo "== kube-linter =="
for f in "$R"/*.yaml; do kube-linter lint "$f"; done
echo "== polaris (fail on Danger) =="
for f in "$R"/*.yaml; do
  polaris audit --config deploy/policy/polaris.yaml --audit-path "$f" \
    --format pretty --only-show-failed-tests --set-exit-code-on-danger
done
echo "== kube-score (documented ignores) =="
for f in "$R"/chart-tls.yaml "$R"/chart-insecure.yaml; do kube-score score "$f" --ignore-test "$CHART_IGNORE"; done
for f in "$R"/operator-workloads.yaml "$R"/operator-all.yaml; do kube-score score "$f" --ignore-test "$OP_IGNORE"; done
echo "ALL GREEN"
