"""ed25519 keys for publicly-verifiable receipts (substrate §11).

Two-tier signing: HMAC-SHA256 stays the default *within* a trust domain (see `gate.sign_receipt`);
ed25519 adds public verifiability *across* domains — a second party verifies a receipt offline with
only the producer's PUBLIC key, no shared secret.

**Trust is pinning, never TOFU.** A valid ed25519 signature is necessary but NOT sufficient: the
receipt's `key_id` MUST resolve in the verifier's trusted set — the runner's own key (zero-config
local roundtrip) or a published key under `~/.config/verel/trusted_keys/<key_id>.pub`. An
attacker-minted receipt is cryptographically self-consistent but rejected because its key is untrusted.

PyNaCl is an OPTIONAL dependency (`pip install verel[attest]`). With it absent, ed25519 verification
fails CLOSED (the gate FAILs; the `verify` verb surfaces an install hint) — never silent green.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import string

from .._secrets import _config_dir, load_or_create_keyfile

try:  # optional dependency — HMAC works without it
    from nacl.exceptions import BadSignatureError
    from nacl.signing import SigningKey, VerifyKey

    _NACL = True
except ImportError:  # pragma: no cover - exercised via monkeypatch in tests
    SigningKey = VerifyKey = None  # type: ignore[assignment,misc]
    BadSignatureError = Exception  # type: ignore[assignment,misc]
    _NACL = False

ED25519 = "ed25519"
_IDENT_PREFIX = "ed25519:"
# key_id is a 16-char slice of urlsafe-b64 — strictly ASCII [A-Za-z0-9_-]. Use an explicit ASCII set
# (not str.isalnum(), which is Unicode-aware) so the fs-path guard can't be widened by exotic glyphs.
_KEYID_ALPHABET = frozenset(string.ascii_letters + string.digits + "-_")


class MissingAttestationDep(RuntimeError):
    """Raised when an ed25519 operation is attempted without PyNaCl installed."""


def available() -> bool:
    """True iff ed25519 (PyNaCl) is installed — i.e. receipts can be minted publicly verifiable."""
    return _NACL


def _require_nacl() -> None:
    if not _NACL:
        raise MissingAttestationDep(
            "ed25519 receipts require PyNaCl — install it with `pip install verel[attest]`"
        )


# --- base64 (urlsafe, padding-tolerant) -------------------------------------
def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode()


def _b64d(s: str) -> bytes:
    # tolerate missing padding, but REJECT any non-alphabet byte (validate=True) so a malformed
    # signature/pubkey raises cleanly instead of silently discarding stray chars and decoding to
    # garbage. urlsafe alphabet via altchars="-_". Raises binascii.Error / ValueError on bad input.
    pad = "=" * (-len(s) % 4)
    return base64.b64decode(s + pad, altchars=b"-_", validate=True)


def key_id_for(public_key: bytes) -> str:
    """Stable short identity of a public key: first 16 chars of urlsafe-b64(sha256(pubkey))."""
    return _b64e(hashlib.sha256(public_key).digest())[:16]


# --- the local runner's own keypair -----------------------------------------
def _seed() -> bytes:
    """32-byte ed25519 seed: env `VEREL_RUNNER_ED25519_SEED` (64 hex chars) > persisted per-install
    key (hardened, reusing the HMAC keyfile path) > ephemeral (verify then fails closed)."""
    env = os.environ.get("VEREL_RUNNER_ED25519_SEED")
    if env:
        try:
            raw = bytes.fromhex(env.strip())
        except ValueError as e:
            raise MissingAttestationDep(f"VEREL_RUNNER_ED25519_SEED must be 64 hex chars: {e}") from e
        if len(raw) != 32:
            raise MissingAttestationDep("VEREL_RUNNER_ED25519_SEED must decode to exactly 32 bytes")
        return raw
    return load_or_create_keyfile("ed25519_seed", 32)


def signing_key() -> SigningKey:
    _require_nacl()
    return SigningKey(_seed())


def own_verify_key() -> VerifyKey:
    return signing_key().verify_key


def own_public_key_b64() -> str:
    return _b64e(bytes(own_verify_key()))


def self_runner_identity() -> str:
    return _IDENT_PREFIX + key_id_for(bytes(own_verify_key()))


# --- trusted-key resolution (pinning) ---------------------------------------
def _trusted_dir() -> str:
    return os.environ.get("VEREL_TRUSTED_KEYS") or str(_config_dir() / "trusted_keys")


def resolve_trusted_key(key_id: str) -> VerifyKey | None:
    """Return the VerifyKey for `key_id` IFF it is trusted: the runner's own key, or a published
    `<key_id>.pub` in the trusted dir. Returns None for any untrusted/unknown key — the gate then
    fails closed. The stored pubkey must itself hash back to `key_id`, so a mis-named file cannot
    grant trust for a different key."""
    _require_nacl()
    own = own_verify_key()
    if key_id == key_id_for(bytes(own)):
        return own
    # a key_id is a 16-char slice of urlsafe-b64 — reject anything else before touching the fs
    # (path-traversal / odd filenames). Strict ASCII alphabet, never Unicode-aware isalnum().
    if len(key_id) != 16 or not all(c in _KEYID_ALPHABET for c in key_id):
        return None
    path = os.path.join(_trusted_dir(), f"{key_id}.pub")
    try:
        # A 32-byte ed25519 pubkey is ~44 b64 chars; cap the read so a symlinked/oversized .pub
        # (e.g. /dev/zero) can't hang or balloon the verifier. Anything longer is not a valid key.
        with open(path, encoding="ascii") as fh:
            raw = _b64d(fh.read(128).strip())
    except (OSError, ValueError, binascii.Error):
        return None
    if len(raw) != 32 or key_id_for(raw) != key_id:
        return None  # the file's pubkey does not match its claimed id → not trusted
    return VerifyKey(raw)


# --- sign / verify ----------------------------------------------------------
def ed25519_sign(payload: str) -> str:
    _require_nacl()
    return _b64e(signing_key().sign(payload.encode()).signature)


def ed25519_verify(receipt) -> bool:  # noqa: ANN001 - RunReceipt (avoid import cycle)
    """Verify an ed25519 receipt under the pinning trust model. False on ANY failure (fail closed).
    Raises MissingAttestationDep only when PyNaCl is absent — the caller decides how to surface that."""
    _require_nacl()
    ident = receipt.runner_identity or ""
    if not ident.startswith(_IDENT_PREFIX):
        return False
    key_id = ident[len(_IDENT_PREFIX):]
    vk = resolve_trusted_key(key_id)
    if vk is None:
        return False  # untrusted key_id — the TOFU trap; a self-certified receipt dies here
    # inline pubkey is PINNED: if present it must hash to key_id AND equal the authoritative key.
    # It never grants trust — it can only be cross-checked against the key we already trust.
    if receipt.public_key:
        try:
            inline = _b64d(receipt.public_key)
        except (ValueError, binascii.Error):
            return False
        if len(inline) != 32 or key_id_for(inline) != key_id or inline != bytes(vk):
            return False
    try:
        sig = _b64d(receipt.signature)
    except (ValueError, binascii.Error):
        return False
    try:
        vk.verify(receipt.signing_payload().encode(), sig)
        return True
    except BadSignatureError:
        return False
    except Exception:  # malformed signature length etc. → fail closed
        return False


def attest_self(receipt) -> None:  # noqa: ANN001 - RunReceipt
    """Stamp `receipt` with the local runner's ed25519 identity + inline pubkey, then sign it.
    Mutates in place: sets `alg`, `runner_identity`, `public_key`, `signature`."""
    receipt.alg = ED25519
    receipt.runner_identity = self_runner_identity()
    receipt.public_key = own_public_key_b64()
    receipt.signature = ed25519_sign(receipt.signing_payload())
