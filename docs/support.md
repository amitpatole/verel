# Support and compatibility policy

Verel is an open-source project maintained by one person. This page states what you can rely on and what you
cannot, so you can decide whether it fits your risk model.

## What this is not

There is **no SLA, no guaranteed response time and no commercial support** offered with this project. If your
organization needs those, plan for your own team to be able to maintain a fork, or arrange a support agreement
separately. Nothing here is a warranty.

## Versioning

Verel follows semantic versioning for its public surface:

- **Public**: the documented CLI commands and flags, the REST endpoints in these docs, the Python API named in
  [API](api.md), the JSON shapes of `Report`, receipts and `MediaFacts v1`, and the on-disk formats of the
  pilot logs and token files.
- **Not public**: anything underscore-prefixed, internal module layout, and log message text.

A breaking change to the public surface only happens in a major version, and is called out at the top of the
[changelog](https://github.com/amitpatole/verel/blob/main/CHANGELOG.md).

## Deprecation

A deprecated command, flag or endpoint keeps working for at least **two minor releases** after the release that
announces it, and warns when used. Security fixes can shorten this when keeping the old behavior would be unsafe;
that is stated plainly in the changelog.

## On-disk formats and upgrades

- Evidence logs, ledgers and policy histories are versioned by their record schema. A release that changes one
  ships a migration or refuses to open the old file with a clear message. It never silently reinterprets it.
- Keep a copy of your `VEREL_LOG_KEY` (or its key file). Without it, existing evidence cannot be verified.
- Upgrade one minor version at a time in production, and read the changelog between them.

## Security fixes

Report vulnerabilities privately per `SECURITY.md`. Fixes are made on the current minor release. Older minors are
not patched; the supported path is to upgrade. Each security fix is pinned by a regression test and described in the
changelog once the gap is closed. Open, unfixed issues are not published.

## Compatibility with the other organs

Verel depends on the shared `agentsensory` contract. The `sight`, `hearing` and related extras pin minimum
versions of AgentVision and Audel; a Verel release notes any change to those pins. Reports from the senses are
accepted as long as they validate against the contract version Verel was built against.

## Python and platform

The package declares Python 3.10 or newer, but CI exercises Python 3.11 on Linux only; other versions are best effort. The evidence-log locking uses POSIX `flock`; Windows is not
supported for the pilot service or workers.
