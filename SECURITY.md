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

## Rendering untrusted content (the eyes)

With `verel[sight]`, the **eyes** ([AgentVision](https://github.com/amitpatole/agent-vision))
render untrusted HTML/URLs in headless Chromium. AgentVision is hardened against SSRF
(including DNS-rebinding, via a vetting egress proxy), runs Chromium sandboxed by default, and
caps image/PDF/OCR work. For a networked deployment add a network-level backstop: **restrict
the renderer's egress** (deny outbound to `169.254.0.0/16` metadata, RFC-1918, and CGNAT) and
**containerize** so the Chromium sandbox is available. See AgentVision's
[SECURITY.md](https://github.com/amitpatole/agent-vision/blob/main/SECURITY.md).

## Supported versions

The latest released `0.x` line on PyPI receives fixes. Pre-1.0: APIs may change between
minor versions.
