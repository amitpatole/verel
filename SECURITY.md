# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories
(**Security → Report a vulnerability**) on this repository, or by email to the maintainer.
Do not open a public issue for an unfixed vulnerability.

## Posture

- **No secrets in CI.** The CI workflow uses no repository secrets, and the `GITHUB_TOKEN`
  is read-only (`permissions: contents: read`).
- **Fork pull requests** run with a read-only token, no secrets, and **require maintainer
  approval** before any workflow runs.
- **Allowed Actions** are restricted to GitHub-owned + verified-creator actions.
- **`main` is protected**: reviewed PRs + passing CI required to merge; force-pushes and
  deletions are blocked; linear history and conversation resolution are required.
- Untrusted, agent-authored tool code is executed under OS-level isolation
  (`toolsmith.container`, a `bwrap` namespace sandbox with no network and a read-only fs);
  this is documented honestly as a strong middle tier, not a full production sandbox.

## Supported versions

The latest released `0.x` line on PyPI receives fixes. Pre-1.0: APIs may change between
minor versions.
