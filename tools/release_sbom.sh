#!/usr/bin/env bash
# Build a CycloneDX SBOM of exactly what `pip install verel==X.Y.Z` resolves, from the built wheel.
# usage: tools/release_sbom.sh dist/verel-X.Y.Z-py3-none-any.whl [extras]   (e.g. "sso,otel,media")
set -euo pipefail
WHEEL="${1:?wheel path}"; EXTRAS="${2:-}"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
python3 -m venv "$T/v"
SPEC="$WHEEL"; [ -n "$EXTRAS" ] && SPEC="${WHEEL}[${EXTRAS}]"
"$T/v/bin/pip" -q install "$SPEC" cyclonedx-bom
OUT="${WHEEL%.whl}.cdx.json"
"$T/v/bin/cyclonedx-py" environment --of JSON -o "$OUT" "$T/v"
sha256sum "$WHEEL" "$OUT"
echo "SBOM: $OUT"
