"""Run the shared MemoryView contract (tests/memory_contract.py) over the in-tree backends.

LocalMemory (sqlite `:memory:`) and the mem0 adapter (against the offline FakeMem0) must BOTH
satisfy every invariant — the same harness each external backend (Postgres/LanceDB/Redis) reuses.
"""

import pytest
from memory_contract import CONTRACT_CHECKS
from test_mem0_backend import FakeMem0

from verel.memory.local import LocalMemory
from verel.memory.mem0_backend import Mem0Memory

BACKENDS = {
    "local": lambda: LocalMemory(":memory:"),
    "fakemem0": lambda: Mem0Memory(FakeMem0(), user_id="contract"),
}


@pytest.mark.parametrize("backend", BACKENDS.values(), ids=list(BACKENDS))
@pytest.mark.parametrize("check", CONTRACT_CHECKS, ids=lambda c: c.__name__)
def test_contract(check, backend):
    check(backend())
