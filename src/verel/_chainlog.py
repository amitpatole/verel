"""One keyed, hash-chained, append-only, file-locked JSONL log, shared by the pilot decision log, the
label ledger, the policy history and the authorization audit log.

What it protects, and what it does not:
- Every record carries a MAC (HMAC-SHA256 under a per-installation secret, `VEREL_LOG_KEY` or the
  persisted key file, domain-separated per log). Someone who can only WRITE the file cannot recompute a
  valid chain: edits, deletions, reordering, insertion, forged records and rebuilt chains are detected.
- A keyed head ledger (`<log>.head`) pins the latest head, total count and archive segments, so tail
  truncation and deleting the log are detected too. If the key cannot be persisted the process uses an
  ephemeral key and cross-process verification then fails CLOSED.
- NOT protected: an attacker who holds the key (same-user compromise); who deletes the log AND its
  ledger together; or who restores an OLDER consistent log+ledger pair (rollback). Keep an external copy
  of `head()` (or ship the log to WORM storage) for those.
- Retention (`archive_first`) is an AUTHORIZED deletion: the oldest records move to a verifiable
  archive segment and the live log starts with a keyed anchor line. Segments are listed in the ledger, so
  `missing_segments()` can tell you when one has gone, but deleting one is not an integrity failure.
- Appends are O(1): under an exclusive lock they check the log's LAST record against the keyed ledger.
  Full-chain verification (`records()`, `verify()`) walks every record and runs on every read.
- File handling: no symlink following on the log, lock or temp files; temp files are exclusive and unique.
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import hmac
import io
import json
import os
import secrets
import stat
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar, Generic, TypeVar

from pydantic import BaseModel, ConfigDict

from ._secrets import load_secret

GENESIS = "0" * 64
MAX_RECORDS = 1_000_000
MAX_LINE = 1_048_576
MAX_RECORD_JSON = MAX_LINE // 4  # a single record may not be big enough to brick later reads
MAX_FILE = 512 * 1024 * 1024
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


Pending = tuple[str, int, tuple[str, ...]]  # (head, total, hashes of the announced batch)


class LogCorrupt(Exception):
    """The log failed integrity verification (edit, deletion, reorder, insertion, forgery, truncation)."""


class LogBusy(RuntimeError):
    """Another writer held this log's lock past the timeout (callers should retry later, not block)."""


LOCK_TIMEOUT_S = 10.0
LEDGER_MAX = 4 * 1024 * 1024
MAX_SEGMENT_ENTRIES = (
    200  # older archive entries are folded into one, so the ledger cannot grow without bound
)
MAX_BATCH = 512  # most records a single append_batch may write (so a crash can be recovered)
MAX_TAIL_SCAN = 8 * 1024 * 1024
CACHE_SETTLE_NS = 100_000_000  # 100 ms
_VERIFIED: dict[tuple, tuple[tuple, list]] = {}  # (path, domain) -> (file fingerprint, verified records)
_VERIFIED_MAX = 32
_IDS_CACHE: dict[str, tuple] = {}
_CACHE_LOCK = threading.Lock()  # guards both module-level caches (eviction is a read-modify-write)


def _mac(text: str, domain: str = "") -> str:
    key = load_secret("VEREL_LOG_KEY", "log")
    return hmac.new(key, f"{domain}|{text}".encode(), hashlib.sha256).hexdigest()


def _eq(a: str, b: str) -> bool:
    """Constant-time compare that cannot raise on non-ASCII input."""
    return hmac.compare_digest(str(a).encode("utf-8", "replace"), str(b).encode("utf-8", "replace"))


class ChainRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")  # an unhashed extra field must not ride along unnoticed
    prev_hash: str = GENESIS
    hash: str = ""
    mac: str = ""

    def compute_hash(self) -> str:
        body = self.model_dump(mode="json", exclude={"hash", "mac"})
        return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


R = TypeVar("R", bound=ChainRecord)


def _fsync_mode() -> str:
    """`VEREL_LOG_FSYNC`: `all` (default: sync the record AND the head ledger), `record` (sync only the
    record; after a power loss the ledger may lag and verification then reports corruption, fail-closed),
    or `none` (tests and throwaway pilots; a power loss can lose recent records)."""
    v = os.environ.get("VEREL_LOG_FSYNC", "all").strip().lower()
    return v if v in ("all", "record", "none") else "all"


def _write_atomic(path: Path, text: str, *, sync: bool = True) -> None:
    """Write via a unique, exclusively-created temp file (O_EXCL|O_NOFOLLOW): a symlink planted at a
    predictable temp name cannot redirect the write onto another file."""
    tmp = Path(f"{path}.{os.getpid()}.{secrets.token_hex(6)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            if sync:
                os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


class ChainLog(Generic[R]):
    MODEL_NAME: ClassVar[str] = "record"

    def __init__(
        self, path: str | os.PathLike[str], model: type[R], *, domain: str = "", id_field: str | None = None
    ):
        """`domain` is mixed into every MAC, so evidence cannot be copied between logs given different
        domains (e.g. one per tenant and kind). Standalone CLI logs use the empty domain."""
        self.path = Path(path)
        self._model = model
        self._domain = domain
        self._id_field = id_field
        self._ledger = Path(str(path) + ".head")
        self._ids = Path(str(path) + ".ids")
        self._tl = threading.local()

    def _m(self, text: str) -> str:
        return _mac(text, self._domain)

    # -- ids that have left the live log ------------------------------------------------------------
    @staticmethod
    def _id_digest(value: str) -> bytes:
        return hashlib.sha256(value.encode()).hexdigest()[:16].encode()

    def _id_lines(self, values: list[str], prev_mac: str) -> tuple[bytes, str]:
        """Index lines, each keyed AND chained to the one before it (the MAC covers the previous line's MAC),
        so a line cannot be deleted, duplicated or reordered without breaking every line after it."""
        out = []
        for v in values:
            d = self._id_digest(v).decode()
            prev_mac = self._m(f"ids:{prev_mac}:{d}")[:16]
            out.append(f"{d} {prev_mac}\n".encode())
        return b"".join(out), prev_mac

    def _ids_state(self, limit: int) -> tuple[frozenset, int, str, int]:
        """(digests, line count, last chain MAC, byte offset after the last counted line). Only the first
        `limit` lines count: that is how many the anchor commits to. Lines after them are an orphan tail from
        an archive that never completed: they must still chain (a forged line is reported) but they retire
        nothing. An unterminated final write (a torn tail) is ignored. Fewer than `limit` lines, or any line
        that does not chain, is corruption."""
        fd = os.open(self._ids, os.O_RDONLY | _NOFOLLOW)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE:
                raise LogCorrupt("archived-id index is not a regular file")
            with os.fdopen(fd, "rb", closefd=False) as fh:
                raw = fh.read()
        finally:
            os.close(fd)
        good: set[bytes] = set()
        prev = counted = "0" * 16
        count = off = 0
        for ln in raw.split(b"\n")[:-1]:  # the last piece is "" or an unfinished write
            if not ln:
                off += 1 if count < limit else 0
                continue
            parts = ln.split(b" ")
            if len(parts) != 2:
                raise LogCorrupt("archived-id index was tampered with")
            d = parts[0].decode("ascii", "replace")
            want = self._m(f"ids:{prev}:{d}")[:16]
            if not _eq(want, parts[1].decode("ascii", "replace")):
                raise LogCorrupt("archived-id index was tampered with")
            if count < limit:
                good.add(parts[0])
                count, off, counted = count + 1, off + len(ln) + 1, want
            prev = want
        if count < limit:
            raise LogCorrupt("archived-id index is missing entries (deleted or truncated)")
        return frozenset(good), count, counted, off

    def _check_ids_bound(self, counted_mac: str, count: int) -> None:
        """The index must be THIS log's. Its chain MAC after `count` lines is recorded in the keyed ledger
        when the lines are archived; otherwise another log's index (same MAC domain) could be copied over
        this one and every id archived out of this log would read as never decided."""
        if not count:
            return
        led = self._read_ledger()
        cum, want = 0, None
        for e in led[2] if led else []:
            cum += int(e["count"])
            if cum == count:
                want = e.get("ids")
                break
        if want is None or not _eq(str(want), counted_mac):
            raise LogCorrupt("archived-id index does not belong to this log (replaced or edited)")

    def archived_has(self, value: str) -> bool:
        """Was `value` (the id field of some record) archived out of the live log? Retention must not let a
        decided id be decided again, so archived ids are remembered as short digests: keyed, chained line to
        line, and counted against the archived total in the anchor, so a forged, deleted, duplicated or
        truncated index is reported rather than trusted or silently read as "nothing was archived"."""
        archived_total = 0
        if self.path.exists():
            try:
                first = json.loads(self._first_line())
                if isinstance(first, dict) and "_anchor" in first:
                    archived_total = self._anchor_of(first)[1]
            except (ValueError, OSError):
                archived_total = 0
        if not self._ids.exists():
            if archived_total:
                raise LogCorrupt("archived-id index is missing (records were archived)")
            return False
        try:
            st = self._ids.stat()
        except OSError:
            raise LogCorrupt("archived-id index unreadable") from None
        key = (str(self._ids), st.st_mtime_ns, st.st_size, st.st_ino, self._m("ids"), archived_total)
        with _CACHE_LOCK:
            hit = _IDS_CACHE.get(str(self._ids))
        if hit is None or hit[0] != key:
            try:
                digests, lines, last, _end = self._ids_state(archived_total)
            except OSError:
                raise LogCorrupt("archived-id index unreadable") from None
            hit = (key, digests, lines, last)
            with _CACHE_LOCK:
                if len(_IDS_CACHE) >= _VERIFIED_MAX * 8:
                    _IDS_CACHE.pop(next(iter(_IDS_CACHE)), None)
                _IDS_CACHE[str(self._ids)] = hit
        self._check_ids_bound(hit[3], hit[2])
        return self._id_digest(value) in hit[1]

    def _open_lines(self):
        snap = getattr(self._tl, "snap", None)
        if snap is not None:
            return io.StringIO(snap[0])
        fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | _NOFOLLOW)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            os.close(fd)
            raise LogCorrupt("log is not a regular file")
        if st.st_size > MAX_FILE:
            os.close(fd)
            raise LogCorrupt("log file too large")
        return os.fdopen(fd, "r", encoding="utf-8")

    def _anchor_of(self, obj: object) -> tuple[str, int]:
        try:
            a = obj["_anchor"]  # type: ignore[index]
            head, count = str(a["head"]), int(a["count"])
            if len(head) != 64 or count < 0 or not _eq(self._m(f"anchor:{head}:{count}"), str(a["mac"])):
                raise ValueError
            return head, count
        except Exception:  # noqa: BLE001
            raise LogCorrupt("anchor failed verification (forged or wrong key)") from None

    def _parse(self) -> tuple[str, int, list[R]]:
        """(anchor head, anchored count, records), anchor MAC verified, chain NOT yet verified."""
        if getattr(self._tl, "snap", None) is None and not self.path.exists():
            return GENESIS, 0, []
        head, count, recs = GENESIS, 0, []
        with self._open_lines() as fh:
            n = 0
            while True:
                line = fh.readline(MAX_LINE + 1)
                if not line:
                    break
                if len(line) > MAX_LINE and not line.endswith("\n"):
                    raise LogCorrupt("record too long")  # the read hit the cap mid-line
                if not line.endswith("\n"):  # a torn final write never reached the ledger: not a record
                    break
                n += 1
                if len(line) > MAX_LINE + 1 or n > MAX_RECORDS + 1:
                    raise LogCorrupt("record too long or too many records")
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except Exception:  # noqa: BLE001
                    raise LogCorrupt(f"line {n}: unparseable record") from None
                if n == 1 and isinstance(obj, dict) and "_anchor" in obj:
                    head, count = self._anchor_of(obj)
                    continue
                try:
                    recs.append(self._model.model_validate(obj))
                except Exception as e:  # noqa: BLE001
                    raise LogCorrupt(f"line {n}: invalid record ({type(e).__name__})") from None
        return head, count, recs

    def _read_ledger(self) -> tuple[str, int, list[dict], Pending | None] | None:
        snap = getattr(self._tl, "snap", None)
        if snap is not None:
            if snap[1] is None:
                return None
        elif not self._ledger.exists():
            return None
        try:
            if snap is not None:
                d = json.loads(snap[1])
            else:
                fd = os.open(self._ledger, os.O_RDONLY | _NOFOLLOW)
                with os.fdopen(fd, "r", encoding="utf-8") as fh:
                    d = json.loads(fh.read(LEDGER_MAX))
            head, total = str(d["head"]), int(d["total"])
            segs = d.get("segments", [])
            if not isinstance(segs, list):
                raise ValueError
            pend = d.get("pending")
            pending: Pending | None = (
                (str(pend["head"]), int(pend["total"]), tuple(str(h) for h in pend["hashes"]))
                if pend
                else None
            )
            ok = _eq(self._m(self._ledger_text(head, total, segs, pending)), str(d["mac"]))
        except Exception:  # noqa: BLE001
            raise LogCorrupt("head ledger unreadable") from None
        if not ok:
            raise LogCorrupt("head ledger failed verification (forged or wrong key)")
        return head, total, segs, pending

    @staticmethod
    def _ledger_text(head: str, total: int, segs: list[dict], pending: Pending | None) -> str:
        canon = json.dumps(segs, sort_keys=True, separators=(",", ":"))
        pend = (
            f"{pending[0]}:{pending[1]}:{hashlib.sha256(chr(10).join(pending[2]).encode()).hexdigest()}"
            if pending
            else "-"
        )
        return f"ledger:{head}:{total}:{canon}:{pend}"

    def _write_ledger(
        self, head: str, total: int, segments: list[dict], pending: Pending | None = None
    ) -> None:
        """`pending` announces a write that is about to happen (keyed, so it cannot be forged). It is what
        makes a crash between "records written" and "ledger updated" recoverable WITHOUT letting the ledger
        lag arbitrarily behind the log, which would let a stale ledger copy hide truncated records."""
        body = {
            "head": head,
            "total": total,
            "segments": segments,
            "mac": self._m(self._ledger_text(head, total, segments, pending)),
        }
        if pending:
            body["pending"] = {"head": pending[0], "total": pending[1], "hashes": list(pending[2])}
        _write_atomic(self._ledger, json.dumps(body), sync=_fsync_mode() == "all")

    def _fingerprint(self) -> tuple:
        """Identity of the log+ledger files as the filesystem sees them. ctime cannot be reset by a writer
        (unlike mtime), so a same-size edit with a restored mtime still changes the fingerprint."""
        out: list = [self._m("fp")]  # also changes whenever the signing key does
        for f in (self.path, self._ledger):
            try:
                st = f.stat()
                out += [st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns]
            except OSError:
                out.append(None)
        return tuple(out)

    def records(self, *, check_ledger: bool = True) -> list[R]:
        if not check_ledger:
            return self._records_uncached(check_ledger=False)
        key = (str(self.path), self._domain)
        fp = self._fingerprint()
        with _CACHE_LOCK:
            hit = _VERIFIED.get(key)
        if hit is not None and hit[0] == fp:
            return list(hit[1])
        recs = self._records_uncached(check_ledger=True)
        # Cache only if nothing changed while we read AND the files are not "fresh": kernel timestamps are
        # coarse (milliseconds), so an edit within the same tick as the last write could keep an identical
        # fingerprint. Anything modified in the last CACHE_SETTLE_NS is simply re-verified next time.
        newest = max((x for x in fp[1:] if isinstance(x, int) and x > 10**15), default=0)
        settled = time.time_ns() - newest > CACHE_SETTLE_NS
        if settled and self._fingerprint() == fp:
            with _CACHE_LOCK:
                if len(_VERIFIED) >= _VERIFIED_MAX:
                    _VERIFIED.pop(next(iter(_VERIFIED)), None)
                _VERIFIED[key] = (fp, list(recs))
        return recs

    def _records_uncached(self, *, check_ledger: bool = True, held: bool = False) -> list[R]:
        """Read and verify. A reader takes the SHARED lock (a writer holds the exclusive one for its whole
        two-step write), so it never sees the log and ledger half-way between two states and misreports it
        as corruption. Callers that already hold the exclusive lock pass `held=True`."""
        if held or not check_ledger or not self.path.parent.exists():
            return self._verify_files(check_ledger)
        try:
            fd = self._lock(shared=True)
        except LogBusy:
            raise
        except OSError:
            # No write access to the directory (an auditor, a read-only mount, a WORM copy): read without the
            # lock. A write racing us can make the two files briefly disagree, so look once more before
            # calling it corruption.
            try:
                return self._verify_files(check_ledger)
            except LogCorrupt:
                time.sleep(0.05)
                return self._verify_files(check_ledger)
        try:  # hold the shared lock only long enough to COPY both files; verification happens outside it, so
            # a slow verify of a big log never blocks a writer
            log_text = self._read_text(self.path) if self.path.exists() else ""
            ledger_text = self._read_text(self._ledger) if self._ledger.exists() else None
        finally:
            os.close(fd)
        self._tl.snap = (log_text, ledger_text)
        try:
            return self._verify_files(check_ledger)
        finally:
            self._tl.snap = None

    @staticmethod
    def _read_text(path: Path) -> str:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | _NOFOLLOW)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise LogCorrupt("not a regular file")
            if st.st_size > MAX_FILE:
                raise LogCorrupt("file too large")
            with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as fh:
                return fh.read()
        finally:
            os.close(fd)

    def _verify_files(self, check_ledger: bool) -> list[R]:
        a_head, a_count, recs = self._parse()
        prev = a_head
        for i, r in enumerate(recs, 1):
            if r.prev_hash != prev:
                raise LogCorrupt(f"record {i}: chain broken (deleted, reordered or inserted record)")
            if r.hash != r.compute_hash():
                raise LogCorrupt(f"record {i}: hash mismatch (record was edited)")
            if not _eq(self._m(r.hash), r.mac):
                raise LogCorrupt(f"record {i}: MAC invalid (forged record or wrong key)")
            prev = r.hash
        if not check_ledger:  # an archive SEGMENT has no head ledger; its chain and MACs are still verified
            return recs
        led = self._read_ledger()
        total = a_count + len(recs)
        if led is None:
            if total:
                raise LogCorrupt("head ledger missing for a non-empty log (deleted or replaced)")
        else:
            l_head, l_total, _segs, pending = led
            seg_total = sum(int(x["count"]) for x in _segs)
            if a_count != seg_total or (a_count and a_head != _segs[-1]["head"]):
                # The live anchor must be exactly the end of the recorded archive segments: splicing one back
                # in front of the live records (or dropping the anchor) would resurrect retired evidence.
                raise LogCorrupt(
                    "live anchor does not match the ledger's archive segments "
                    "(an interrupted archive? run `verel pilot repair`)"
                )
            # Exactly the committed state, or exactly the announced pending state (a write that finished but
            # did not get to update the ledger). No other lag is tolerated: a stale ledger must not pass.
            if not ((l_head == prev and l_total == total) or (pending and pending[:2] == (prev, total))):
                hint = " (an interrupted batch? run `verel pilot repair`)" if pending else ""
                raise LogCorrupt("log does not match its head ledger (truncated, deleted or replaced)" + hint)
        return recs

    def head(self) -> str:
        recs = self.records()
        return recs[-1].hash if recs else self._parse()[0]

    def archived_count(self) -> int:
        return self._parse()[1]

    def segments(self) -> list[dict]:
        led = self._read_ledger()
        return list(led[2]) if led else []

    def missing_segments(self) -> list[str]:
        """Archive segments the ledger knows about that are no longer next to the log."""
        return [
            s["name"] for s in self.segments() if s["name"] and not (self.path.parent / s["name"]).exists()
        ]

    def verify(self, expect_head: str | None = None, *, segment: bool = False) -> int:
        """Verify chain, MACs and head ledger; with `expect_head` also pin an externally stored head.
        `segment=True` verifies an archive segment (chain + MACs, no ledger)."""
        recs = self.records(check_ledger=not segment)
        if expect_head is not None and (recs[-1].hash if recs else self._parse()[0]) != expect_head:
            raise LogCorrupt("head hash mismatch (log truncated, extended or replaced)")
        return len(recs)

    # -- writing ----------------------------------------------------------------------------------
    def _lock(self, *, shared: bool = False):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.path) + ".lock", os.O_RDWR | os.O_CREAT | _NOFOLLOW, 0o600)
        deadline = time.monotonic() + LOCK_TIMEOUT_S
        mode = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
        while True:  # bounded wait: a stuck writer must not park every other request thread forever
            try:
                fcntl.flock(fd, mode | fcntl.LOCK_NB)
                return fd
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise LogBusy("log is busy; try again") from None
                time.sleep(0.005)

    def _first_line(self) -> str:
        with self._open_lines() as fh:
            return fh.readline(MAX_LINE + 1)

    def _last_line(self) -> str:
        """The last non-empty line, read from the END of the file (bounded window)."""
        fd = os.open(self.path, os.O_RDONLY | _NOFOLLOW)
        try:
            size = os.fstat(fd).st_size
            window = min(size, 4096)
            while True:  # grow the window until it holds one COMPLETE last line (records are ~0.5 KB)
                os.lseek(fd, size - window, os.SEEK_SET)
                buf = os.read(fd, window)
                body = buf.rstrip(b"\n \t\r")
                if b"\n" in body or window >= size:
                    break
                if window >= MAX_LINE + 2:
                    raise LogCorrupt("last record too long")
                window = min(size, window * 4)
        finally:
            os.close(fd)
        return body.rsplit(b"\n", 1)[-1].decode("utf-8", "replace") if body else ""

    def _tail(self) -> tuple[str, int, list[dict]]:
        """(head to chain onto, total records so far, segments) verified against the keyed ledger,
        in O(1): the last record must be internally valid and agree with the ledger."""
        led = self._read_ledger()
        a_head, a_count = GENESIS, 0
        last_line = ""
        if self.path.exists() and self.path.stat().st_size > 0:
            first = self._first_line()
            try:
                obj = json.loads(first)
            except Exception:  # noqa: BLE001
                raise LogCorrupt("unparseable first line") from None
            if isinstance(obj, dict) and "_anchor" in obj:
                a_head, a_count = self._anchor_of(obj)
            last_line = self._last_line()
        last: R | None = None
        if last_line:
            try:
                obj = json.loads(last_line)
            except Exception:  # noqa: BLE001
                raise LogCorrupt("unparseable last record") from None
            if not (isinstance(obj, dict) and "_anchor" in obj):
                try:
                    last = self._model.model_validate(obj)
                except Exception:  # noqa: BLE001
                    raise LogCorrupt("invalid last record") from None
                if last.hash != last.compute_hash() or not _eq(self._m(last.hash), last.mac):
                    raise LogCorrupt("last record failed verification")
        if led is None:
            if last is not None or a_count:
                raise LogCorrupt("head ledger missing for a non-empty log (deleted or replaced)")
            return GENESIS, 0, []
        l_head, l_total, segs, pending = led
        if last is None:
            if l_head != a_head or l_total != a_count:
                raise LogCorrupt("log does not match its head ledger (truncated, deleted or replaced)")
            return a_head, a_count, segs
        if l_head == last.hash:
            return last.hash, l_total, segs
        if (
            pending and last.hash == pending[0]
        ):  # the announced write completed; only the ledger update was lost
            return last.hash, pending[1], segs
        hint = " (an interrupted batch? run `verel pilot repair`)" if pending else ""
        raise LogCorrupt("log does not match its head ledger (truncated, deleted or replaced)" + hint)

    def repair(self) -> int:
        """Resolve an interrupted multi-record write that a power loss left half-persisted: the unacknowledged
        records after the committed head are dropped and the pending marker cleared. Refuses anything that is
        not exactly that situation (a stale ledger on a log with MORE acknowledged records is corruption)."""
        fd = self._lock()
        try:
            self._repair_torn_tail()
            finished = self._finish_archive()
            led = self._read_ledger()
            if led is None or led[3] is None:
                if finished is not None:
                    return 0
                raise LogCorrupt("nothing to repair: the ledger has no interrupted write")
            l_head, l_total, segs, pend = led
            assert pend is not None
            p_head, p_total, p_hashes = pend
            a_head, _a_count, _ = self._parse()
            recs = self._parse()[2]
            tip = recs[-1].hash if recs else a_head
            if tip == p_head:
                self._write_ledger(p_head, p_total, segs)
                return 0
            after = self._records_after(l_head, a_head)
            k = len(after) if after is not None else -1
            # What survives after the committed head must be EXACTLY the first k records of the announced
            # batch (their hashes are committed in the keyed pending marker). Anything else is acknowledged
            # data that a stale ledger snapshot would have us destroy.
            if after is None or k >= p_total - l_total or [r.hash for r in after] != list(p_hashes[:k]):
                raise LogCorrupt("log does not match the announced write; refusing to repair")
            lines = [ln for ln in self.path.read_bytes().split(b"\n") if ln.strip()]
            _write_atomic(self.path, b"\n".join(lines[: len(lines) - k]).decode("utf-8") + "\n")
            self._write_ledger(l_head, l_total, segs)
            return k
        finally:
            os.close(fd)

    def _finish_archive(self) -> int | None:
        """Roll an interrupted archive FORWARD: the ledger already names the new segment but the live log was
        not yet replaced (a crash between the two writes, or a spliced-back segment). Only done when the
        segment verifies (chain, MACs), starts at the live anchor, and the live log's first records are
        exactly the segment's records. Returns the number of records moved, or None if nothing to finish."""
        led = self._read_ledger()
        if led is None or not led[2]:
            return None
        segs = led[2]
        last = segs[-1]
        n = int(last["count"])
        a_head, a_count, recs = self._parse()
        if not last["name"] or sum(int(x["count"]) for x in segs) != a_count + n:
            return None
        seg = copy.copy(self)
        seg.path = self.path.parent / last["name"]
        if not seg.path.exists():
            name = last["name"]
            raise LogCorrupt(f"interrupted archive: segment {name!r} is not beside the log; restore, repair")
        seg._ledger = Path(str(seg.path) + ".head")
        seg._tl = threading.local()
        try:
            srecs = seg.records(check_ledger=False)
            s_anchor = seg._parse()[:2]
        except (OSError, LogCorrupt):
            raise LogCorrupt("interrupted archive: segment missing or invalid; refusing to repair") from None
        if (
            len(srecs) != n
            or srecs[-1].hash != last["head"]
            or s_anchor != (a_head, a_count)
            or [r.hash for r in recs[:n]] != [r.hash for r in srecs]
        ):
            raise LogCorrupt("interrupted archive does not match its segment; refusing to repair")
        body = [
            json.dumps(
                {
                    "_anchor": {
                        "head": last["head"],
                        "count": a_count + n,
                        "mac": self._m(f"anchor:{last['head']}:{a_count + n}"),
                    }
                }
            )
        ] + [r.model_dump_json() for r in recs[n:]]
        _write_atomic(self.path, "\n".join(body) + "\n")
        return n

    def _records_after(self, ledger_head: str, anchor_head: str) -> list[R] | None:
        """The records that follow `ledger_head` at the end of the log (an interrupted BATCH), verifying each
        one's hash, MAC and chain link. None if the ledger head is not within the last MAX_BATCH records."""
        fd = os.open(self.path, os.O_RDONLY | _NOFOLLOW)
        try:
            size = os.fstat(fd).st_size
            window = min(size, MAX_TAIL_SCAN)
            os.lseek(fd, size - window, os.SEEK_SET)
            buf = os.read(fd, window)
        finally:
            os.close(fd)
        lines = buf.split(b"\n")
        if window < size:
            lines = lines[1:]
        recs: list[R] = []
        for ln in [x for x in lines if x.strip()][-(MAX_BATCH + 1) :]:
            try:
                obj = json.loads(ln)
                if isinstance(obj, dict) and "_anchor" in obj:
                    continue
                recs.append(self._model.model_validate(obj))
            except Exception:  # noqa: BLE001
                return None
        for r in recs:
            if r.hash != r.compute_hash() or not _eq(self._m(r.hash), r.mac):
                return None
        for a, b in zip(recs, recs[1:], strict=False):
            if b.prev_hash != a.hash:
                return None
        for i, r in enumerate(recs):
            before = recs[i - 1].hash if i else r.prev_hash
            if before == ledger_head or (i == 0 and r.prev_hash == anchor_head == ledger_head):
                return recs[i:]
        return None

    def _repair_torn_tail(self) -> None:
        """A crash or ENOSPC mid-write can leave a partial final line (no newline). It never reached the
        keyed ledger (the ledger is written AFTER the record), so dropping it is safe; anything that WAS
        committed ends with a newline and is untouched. Truncating committed data would break the ledger
        match and still be detected."""
        if not self.path.exists():
            return
        fd = os.open(self.path, os.O_RDWR | _NOFOLLOW)
        try:
            size = os.fstat(fd).st_size
            if size == 0:
                return
            os.lseek(fd, size - 1, os.SEEK_SET)
            if os.read(fd, 1) == b"\n":
                return
            window = min(size, MAX_LINE + 2)
            os.lseek(fd, size - window, os.SEEK_SET)
            buf = os.read(fd, window)
            cut = buf.rfind(b"\n")
            partial = buf[cut + 1 :] if cut >= 0 else buf
            if cut < 0 and window != size:
                return  # a last line longer than any record: leave it for the readers to flag
            if self._is_valid_line(partial):
                # a complete, MAC-valid record that only lacks its newline is COMMITTED data (or someone
                # stripped the newline): restore the newline, never delete it
                os.lseek(fd, 0, os.SEEK_END)
                os.write(fd, b"\n")
            elif cut >= 0:
                os.ftruncate(fd, size - window + cut + 1)
            else:
                os.ftruncate(fd, 0)  # the whole file is one torn line
        finally:
            os.close(fd)

    def _is_valid_line(self, raw: bytes) -> bool:
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict) and "_anchor" in obj:
                self._anchor_of(obj)
                return True
            r = self._model.model_validate(obj)
            return r.hash == r.compute_hash() and _eq(self._m(r.hash), r.mac)
        except Exception:  # noqa: BLE001
            return False

    def _write_records(self, recs: list[R], prev: str, total: int, segs: list[dict]) -> None:
        """Append `recs` in ONE write + ONE sync + ONE ledger update. On any failure the file is truncated
        back to where it started, so a full disk cannot leave a torn record behind."""
        if total + len(recs) > MAX_RECORDS:
            raise ValueError("log is full; archive old records first")
        if len(recs) > MAX_BATCH:
            raise ValueError(f"at most {MAX_BATCH} records per write")
        prev0 = prev
        lines = []
        hashes: list[str] = []
        for rec in recs:
            rec.prev_hash = prev
            rec.hash = rec.compute_hash()
            rec.mac = self._m(rec.hash)
            line = rec.model_dump_json()
            if len(line) > MAX_RECORD_JSON:
                raise ValueError("record too large")
            lines.append(line)
            hashes.append(rec.hash)
            prev = rec.hash
        if not lines:
            return
        new_total = total + len(recs)
        self._write_ledger(*self._committed(prev0, total, segs), pending=(prev, new_total, tuple(hashes)))
        wfd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | _NOFOLLOW, 0o600)
        start = os.fstat(wfd).st_size
        try:
            with os.fdopen(wfd, "a", encoding="utf-8", closefd=False) as fh:
                fh.write("\n".join(lines) + "\n")
                fh.flush()
                if _fsync_mode() != "none":
                    os.fsync(wfd)
            self._write_ledger(prev, new_total, segs)
        except BaseException:
            try:
                os.ftruncate(wfd, start)
                self._write_ledger(*self._committed(prev0, total, segs))
            except OSError:
                pass
            raise
        finally:
            os.close(wfd)

    @staticmethod
    def _committed(head: str, total: int, segs: list[dict]) -> tuple[str, int, list[dict]]:
        return head, total, segs

    def append(self, rec: R) -> R:
        """O(1) append under an exclusive lock. Refuses to extend a log whose tail is corrupt or
        disagrees with the keyed ledger (the full chain is verified by `records()` / `verify()`)."""
        fd = self._lock()
        try:
            self._repair_torn_tail()
            prev, total, segs = self._tail()
            self._write_records([rec], prev, total, segs)
            return rec
        finally:
            os.close(fd)

    def append_if_absent(
        self,
        rec: R,
        needle: bytes,
        confirm: Callable[[R], bool],
        duplicate: Callable[[R], Exception],
        extra_seen: Callable[[], bool] | None = None,
    ) -> R:
        """Append `rec` unless an existing record is a duplicate. `needle` is a byte string present in the
        serialized line of any duplicate (a cheap substring scan, no per-record verification: append safety
        comes from the keyed tail check, full verification from reads); `confirm` parses a candidate line
        to be sure. `extra_seen` lets a subclass also consult data no longer in the live log."""
        fd = self._lock()
        try:
            self._repair_torn_tail()
            prev, total, segs = self._tail()
            if self.path.exists():  # a LIVE record wins: the caller gets the real one back
                with open(self.path, "rb") as fh:
                    for line in fh:
                        if needle in line:
                            try:
                                existing = self._model.model_validate_json(line)
                            except Exception:  # noqa: BLE001
                                continue
                            if confirm(existing):
                                raise duplicate(existing)
            if extra_seen is not None and extra_seen():
                raise duplicate(rec)
            self._write_records([rec], prev, total, segs)
            return rec
        finally:
            os.close(fd)

    def append_batch(self, make: Callable[[list[R]], list[R]]) -> list[R]:
        """Under ONE lock: fully verify the log, let `make(existing)` decide which records to add (it may
        raise to reject the whole batch), then append them. Use for check-then-append invariants."""
        fd = self._lock()
        try:
            self._repair_torn_tail()
            existing = self._records_uncached(held=True)
            new = make(existing)
            prev, total, segs = self._tail()
            self._write_records(new, prev, total, segs)
            return new
        finally:
            os.close(fd)

    def archive_first(self, n: int, segment: str | os.PathLike[str]) -> int:
        """Move the oldest `n` live records into `segment` (a standalone verifiable chain) and re-anchor
        the live log at their head. Returns the number archived. The segment is durable before the live
        log is atomically replaced."""
        if n <= 0:
            return 0
        fd = self._lock()
        try:
            a_head, a_count, _ = self._parse()
            recs = self._records_uncached(held=True)
            n = min(n, len(recs))
            if n == 0:
                return 0
            seg = Path(segment)
            if seg.resolve().parent != self.path.resolve().parent:
                # The ledger records only the segment's NAME and `repair` looks next to the log: a segment
                # elsewhere could not be found to finish an interrupted archive. Move it afterwards.
                raise ValueError("the archive segment must be created next to the log (move it afterwards)")
            if seg.exists():
                raise ValueError(f"archive segment already exists: {seg}")
            seg.parent.mkdir(parents=True, exist_ok=True)
            lines = []
            if a_count:
                lines.append(
                    json.dumps(
                        {
                            "_anchor": {
                                "head": a_head,
                                "count": a_count,
                                "mac": self._m(f"anchor:{a_head}:{a_count}"),
                            }
                        }
                    )
                )
            lines += [r.model_dump_json() for r in recs[:n]]
            old_led = None
            ids_size = None
            ids_last: str | None = None
            seg_made = False
            new_count = a_count + n
            try:
                sfd = os.open(seg, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600)
                seg_made = True  # only a segment THIS call created may be removed by the rollback
                with os.fdopen(sfd, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(lines) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                if self._id_field:  # remember the ids about to leave the live log
                    try:
                        if self._ids.exists():
                            # Trust only the lines the anchor commits to; trim a torn or orphaned tail first.
                            _d, _c, prev_mac, end = self._ids_state(a_count)
                            self._check_ids_bound(prev_mac, a_count)
                        elif a_count:
                            raise LogCorrupt("archived-id index is missing (records were archived)")
                        else:
                            prev_mac, end = "0" * 16, 0
                        if self._ids.exists() and self._ids.stat().st_size != end:
                            os.truncate(self._ids, end)
                    except OSError:
                        raise LogCorrupt("archived-id index unreadable") from None
                    moving = [str(getattr(r, self._id_field)) for r in recs[:n]]
                    payload, ids_last = self._id_lines(moving, prev_mac)
                    ids_size = end
                    ifd = os.open(self._ids, os.O_WRONLY | os.O_APPEND | os.O_CREAT | _NOFOLLOW, 0o600)
                    try:
                        view = memoryview(payload)
                        while view:  # a short write must not leave a torn index line
                            view = view[os.write(ifd, view) :]
                        os.fsync(ifd)
                    finally:
                        os.close(ifd)
                old_led = self._read_ledger()
                new_head, new_count = recs[n - 1].hash, a_count + n
                body = [
                    json.dumps(
                        {
                            "_anchor": {
                                "head": new_head,
                                "count": new_count,
                                "mac": self._m(f"anchor:{new_head}:{new_count}"),
                            }
                        }
                    )
                ]
                body += [r.model_dump_json() for r in recs[n:]]
                entry: dict = {"name": seg.name, "head": new_head, "count": n}
                if ids_last is not None:
                    entry["ids"] = ids_last  # the index chain end after these lines: binds .ids to this log
                segs = (old_led[2] if old_led else []) + [entry]
                if len(segs) > MAX_SEGMENT_ENTRIES:  # fold the oldest entries: the ledger stays small
                    keep = MAX_SEGMENT_ENTRIES // 2
                    old, segs = segs[:-keep], segs[-keep:]
                    folded = {"name": "", "head": old[-1]["head"], "count": sum(int(x["count"]) for x in old)}
                    if "ids" in old[-1]:
                        folded["ids"] = old[-1]["ids"]
                    segs = [folded] + segs
                tip = recs[-1].hash
                # Ledger FIRST (head and total unchanged, so it stays valid for the old log), live log last:
                # the single remaining step is the atomic replace, so there is no window in which the archived
                # records exist nowhere. A crash between the two is finished by `repair()` (_finish_archive).
                self._write_ledger(tip, a_count + len(recs), segs)
                _write_atomic(self.path, "\n".join(body) + "\n")
            except BaseException:
                try:
                    replaced = self._parse()[1] == new_count
                except Exception:  # noqa: BLE001
                    replaced = False
                if not replaced:
                    # The live log still holds the records: put the ledger back and drop what we added. If the
                    # ledger cannot be restored, keep the segment and ids so `repair()` can finish it.
                    try:
                        if old_led is not None:
                            self._write_ledger(old_led[0], old_led[1], old_led[2], old_led[3])
                        restored = True
                    except BaseException:  # noqa: BLE001
                        restored = False
                    if restored:
                        if ids_size is not None:
                            try:
                                os.truncate(self._ids, ids_size)
                            except OSError:
                                pass
                        if seg_made:
                            try:
                                seg.unlink()
                            except OSError:
                                pass
                raise
            return n
        finally:
            os.close(fd)
