"""Pytest setup — pin fixed signing secrets so the suite is hermetic and deterministic.

Production resolves signing keys via `verel._secrets.load_secret` (env var, else a persisted
per-installation random key). For tests we set the env vars to fixed values BEFORE any verel module
is imported, so sign→verify is reproducible and nothing is written under the user's config dir.
"""

import os

os.environ.setdefault("VEREL_RUNNER_SECRET", "test-runner-secret")
os.environ.setdefault("VEREL_TOOL_SECRET", "test-tool-secret")
os.environ.setdefault("VEREL_REGISTRY_SECRET", "test-registry-secret")
# Fixed ed25519 seed (§11) so the runner's keypair is deterministic and nothing is written under the
# user's config dir. 64 hex chars = 32 bytes.
os.environ.setdefault("VEREL_RUNNER_ED25519_SEED", "11" * 32)
os.environ.setdefault("VEREL_LOG_KEY", "test-log-key")
os.environ.setdefault("VEREL_LOG_FSYNC", "none")  # tests: speed; durability modes are covered by test_log_fsync_modes
os.environ.setdefault("VEREL_EVIDENCE_ALLOW_SELF_REPORTED", "1")  # most tests record over HTTP; r7 covers the default
