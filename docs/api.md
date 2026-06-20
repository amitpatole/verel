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

## Memory

::: verel.memory.view
