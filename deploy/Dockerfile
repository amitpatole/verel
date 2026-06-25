# syntax=docker/dockerfile:1
# Verel — hardened container image on a Chainguard Wolfi base (the same low-/zero-CVE base as the
# apko path in deploy/apko.yaml; this Dockerfile is the buildable-anywhere variant). The final stage
# is distroless + nonroot (UID 65532) + no shell/package-manager — minimal attack surface.
#
# Build: docker build -f deploy/Dockerfile -t verel:dev .
# Run:   docker run --rm -p 8000:8000 -v "$PWD:/workspace:ro" verel:dev serve --host 0.0.0.0 --repo /workspace

# ---- builder: Wolfi python WITH build tooling (shell, pip) ----
FROM cgr.dev/chainguard/python:latest-dev AS builder
USER root
WORKDIR /build
ENV PATH="/opt/venv/bin:$PATH" PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
# Copy only what the build needs (see .dockerignore) and install verel + the production extras.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install ".[postgres,redis,lancedb,operator,attest]"

# ---- final: distroless Wolfi python, nonroot, no shell/pip ----
FROM cgr.dev/chainguard/python:latest
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
# Chainguard images already run as nonroot (UID 65532); declare it explicitly + a read-only-friendly
# workdir. The gate server binds 0.0.0.0:8000 in-cluster (TLS/auth enforced by GateServer for routable
# binds; the chart fronts it with TLS + NetworkPolicy).
USER 65532:65532
EXPOSE 8000
ENTRYPOINT ["verel"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000", "--repo", "/workspace", "--no-lint"]
