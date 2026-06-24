"""Semantic recall via embeddings (§5.6) + the subprocess sandbox (§7.7) — offline."""

import math

import pytest

from verel.memory import HashEmbedder, LocalMemory, MemoryKind, MemoryRecord, cosine
from verel.toolsmith import SandboxError, SideEffect, ToolRecord, run_sandboxed


# ---- embeddings ----
def test_cosine_basics():
    assert cosine([1, 0], [1, 0]) == pytest.approx(1.0)
    assert cosine([1, 0], [0, 1]) == pytest.approx(0.0)
    assert cosine([], [1]) == 0.0


def test_openai_embedder_dim_matches_model():
    # Red-team HIGH: .dim MUST reflect the model's real output width (a fixed-dim vector store creates a
    # wrong-width column and crashes on write if .dim lies). Not a blanket 1536.
    from verel.memory.embed import OpenAIEmbedder

    assert OpenAIEmbedder("text-embedding-3-small").dim == 1536
    assert OpenAIEmbedder("text-embedding-3-large").dim == 3072   # was wrongly 1536 before the fix
    assert OpenAIEmbedder("some-future-model", dim=42).dim == 42  # explicit override (VEREL_EMBED_DIM)


def test_hash_embedder_is_deterministic_and_normalized():
    e = HashEmbedder(dim=64)
    a = e.embed(["overflow on narrow screens"])[0]
    b = e.embed(["overflow on narrow screens"])[0]
    assert a == b
    assert math.isclose(math.sqrt(sum(x * x for x in a)), 1.0, rel_tol=1e-6)


def _fact(text, subject, scope="repo:x"):
    return MemoryRecord(kind=MemoryKind.FACT, subject=subject, predicate="p", text=text, scope=scope)


def test_recall_uses_embeddings_when_present():
    mem = LocalMemory(embedder=HashEmbedder(dim=128))
    mem.write(_fact("fixed width container overflows the viewport", "overflow-rule"))
    mem.write(_fact("button colors and palette tokens", "color-rule"))
    hits = mem.recall("element overflows the viewport on small screens", scope="repo:x", k=1)
    assert hits and hits[0].subject == "overflow-rule"  # ranked by vector similarity


def test_vector_survives_reinforcement():
    mem = LocalMemory(embedder=HashEmbedder(dim=64))
    r = mem.write(_fact("overflow rule", "o"))
    v1 = mem._get_vector(r.id)
    assert v1 is not None
    mem.corroborate(r.id)  # an upsert that must NOT wipe the vector
    assert mem._get_vector(r.id) == v1


def test_lexical_fallback_without_embedder():
    mem = LocalMemory()  # no embedder
    mem.write(_fact("overflow viewport", "o"))
    assert mem.recall("overflow", scope="repo:x")  # still works lexically


# ---- subprocess sandbox ----
def _tool(code, name="f"):
    return ToolRecord(name=name, code=code, side_effect=SideEffect.READ_ONLY).sign()


def test_sandbox_runs_pure_function():
    t = _tool("def f(a, b):\n    return a + b\n")
    assert run_sandboxed(t, [2, 3]) == 5


def test_sandbox_kills_infinite_loop():
    t = _tool("def f():\n    while True:\n        pass\n")
    with pytest.raises(SandboxError):
        run_sandboxed(t, timeout_s=1.0)


def test_sandbox_blocks_persisting_file_content():
    # RLIMIT_FSIZE=0: the moment real bytes are flushed to disk, SIGXFSZ kills the child.
    t = _tool("def f():\n    fh=open('/tmp/verel_sbx_x','w'); fh.write('x'*100); fh.flush()\n    return 'wrote'\n")
    with pytest.raises(SandboxError):
        run_sandboxed(t)


def test_sandbox_rejects_tampered_signature():
    t = _tool("def f():\n    return 1\n")
    t.code = "def f():\n    return 999\n"  # tamper after signing
    with pytest.raises(SandboxError):
        run_sandboxed(t)


def test_sandbox_isolated_no_ambient_imports():
    # -I -S means the tool can still `import` stdlib explicitly, but inherits no site customizations
    t = _tool("def f():\n    import math\n    return int(math.sqrt(16))\n")
    assert run_sandboxed(t) == 4
