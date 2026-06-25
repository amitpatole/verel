# Python API

The verdict bus, senses, and CI stages are all importable. Example — gate any repo:

```python
from verel.ci import inner_loop_stage, run_stage
result = run_stage(inner_loop_stage(".", with_lint=True))
print(result.verdict)          # pass / warn / fail
```

## The verdict contract

::: verel.verdict.models

## The gate

::: verel.verdict.gate

## Senses (the eyes)

::: verel.senses.sight

## CI stages & self-healing

::: verel.ci.pipeline
::: verel.ci.heal

## Verified-Review graders

Test-effectiveness (mutation), spec/intent conformance, business-rule invariants, over-engineering
smell, and the action gateway — all importable, all on the verdict bus.

### Test-effectiveness (mutation)

::: verel.ci.mutation

### Spec / intent conformance

::: verel.ci.spec

### Business-rule / invariant

::: verel.ci.invariants

### Over-engineering smell

::: verel.smell

### Action gateway

::: verel.gateway

## Receipts & attestation

Sign and verify run-receipts; the two-tier (`hmac-sha256` / `ed25519`) signing and the trusted-key
resolution that makes a verdict publicly re-checkable.

::: verel.verdict.attest

::: verel.verdict.keys

## Memory

::: verel.memory.view
