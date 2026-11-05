"""Tamper-evident audit log: a hash chain over JSON lines.

Every record mcp-leash writes ends with two fields that tie it to the one
before it:

    {..., "seq": 7, "prev": "sha256:<hash of record 6>", "hash": "sha256:<hex>"}

`hash` is the digest of the record's own bytes up to (not including) the
`, "hash": ...` suffix, closed with `}`. Because `prev` is inside those bytes,
each record commits to the whole history before it: editing, deleting,
inserting or reordering any record breaks every link after it, and
`mcp-leash verify-audit` reports the first line where that happens.

With MCP_LEASH_AUDIT_KEY set in mcp-leash's environment the digest is an
HMAC-SHA256 under that key (`"hmac-sha256:<hex>"`), so someone who can write
the file but does not have the key cannot forge a consistent chain. The key
is removed from the environment of the server mcp-leash starts.

What a chain cannot show by itself: records cut off the END of the file
(the remaining chain is still consistent), or, without a key, a whole file
rewritten from scratch. `verify-audit` prints the head (last seq and hash):
note it somewhere else and compare it later to catch either.

Zero dependencies: hashlib, hmac, and fcntl/msvcrt for the file lock that
keeps several mcp-leash processes (one per wrapped server) sharing one log
from forking the chain.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import threading

KEY_ENV = "MCP_LEASH_AUDIT_KEY"
_SUFFIX = re.compile(rb', "hash": "((?:sha256|hmac-sha256):[0-9a-f]{64})"\}\Z')
ALGS = ("sha256", "hmac-sha256")

# One id per mcp-leash process: tells the sessions apart in a shared log.
SESSION = secrets.token_hex(6)

_lock = threading.Lock()                 # threads of this process
# path -> ((size, (dev, inode)), head hash, seq) after our last append: when
# the file is still that size and that file, its tail need not be re-read
_cache: dict = {}
_TAIL_CHUNK = 64 * 1024
_TAIL_MAX = 16 * 1024 * 1024            # longest last line we will look for


def audit_key() -> "bytes | None":
    key = os.environ.get(KEY_ENV)
    return key.encode("utf-8") if key else None


def _alg(key) -> str:
    return "hmac-sha256" if key else "sha256"


def digest(data: bytes, alg: str, key) -> str:
    if alg == "hmac-sha256":
        return alg + ":" + hmac.new(key, data, hashlib.sha256).hexdigest()
    return alg + ":" + hashlib.sha256(data).hexdigest()


def genesis(alg: str) -> str:
    return alg + ":" + "0" * 64


def split_record(line: bytes) -> "tuple[bytes, str] | None":
    """(the bytes the hash covers, the hash) for a chained record, else
    None (a record written before the chain existed, or a damaged line)."""
    m = _SUFFIX.search(line)
    if m is None:
        return None
    return line[:m.start()] + b"}", m.group(1).decode("ascii")


# -- writing ----------------------------------------------------------------


def _lock_file(f):
    """Exclusive lock on the open log for the read-tail-then-append step.
    Returns an unlock function. Best effort: a file system without locks
    still gets the in-process lock."""
    try:
        import fcntl
    except ImportError:          # Windows
        try:
            import msvcrt
            fd = f.fileno()
            pos = f.tell()
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)   # retries for ~10 s

            def unlock():
                try:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
                os.lseek(fd, pos, os.SEEK_SET)
            return unlock
        except (ImportError, OSError):
            return lambda: None
    try:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
    except OSError:
        return lambda: None
    return lambda: fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def _last_line(f, size: int) -> bytes:
    """The last line of the file (without its newline), read backwards in
    chunks; b"" for an empty file."""
    end = size
    buf = b""
    # a file that does not end in a newline: its last line is incomplete,
    # and it is still the line the next record follows
    while end > 0 and len(buf) <= _TAIL_MAX:
        start = max(0, end - _TAIL_CHUNK)
        f.seek(start)
        buf = f.read(end - start) + buf
        end = start
        body = buf[:-1] if buf.endswith(b"\n") else buf
        nl = body.rfind(b"\n")
        if nl >= 0:
            return body[nl + 1:]
    return buf[:-1] if buf.endswith(b"\n") else buf


def _head(f, size: int, alg: str, key) -> tuple[str, int, bool]:
    """(prev for the next record, seq of the last record, needs newline)."""
    if size == 0:
        return genesis(alg), 0, False
    f.seek(size - 1)
    needs_nl = f.read(1) != b"\n"
    last = _last_line(f, size)
    parts = split_record(last)
    if parts is not None:
        try:
            seq = json.loads(parts[0]).get("seq")
        except (ValueError, AttributeError, RecursionError):
            seq = None
        if isinstance(seq, int) and not isinstance(seq, bool):
            return parts[1], seq, needs_nl
    # a record from before the chain, or a damaged line: link to its bytes
    # so that nothing can be slipped in between it and what follows
    return digest(last, alg, key), 0, needs_nl


def append(path: str, event: dict, opener) -> None:
    """Add `event` to the log at `path` as the next link of the chain.
    `opener(path)` returns a binary append handle (created 0600)."""
    key = audit_key()
    alg = _alg(key)
    with _lock:
        with opener(path) as f:
            unlock = _lock_file(f)
            try:
                st = os.fstat(f.fileno())
                size, ident = st.st_size, (st.st_dev, st.st_ino)
                cached = _cache.get(path)
                if cached is not None and cached[0] == (size, ident) and \
                        cached[1].startswith(alg + ":"):
                    prev, seq, needs_nl = cached[1], cached[2], False
                else:
                    with open(path, "rb") as r:
                        prev, seq, needs_nl = _head(r, size, alg, key)
                record = dict(event)
                record["seq"] = seq + 1
                record["prev"] = prev
                body = json.dumps(record, ensure_ascii=True).encode("ascii")
                h = digest(body, alg, key)
                line = body[:-1] + b', "hash": "' + h.encode("ascii") + b'"}\n'
                data = (b"\n" if needs_nl else b"") + line
                f.write(data)
                f.flush()
                _cache[path] = ((size + len(data), ident), h, seq + 1)
            finally:
                unlock()


# -- verifying --------------------------------------------------------------


class Report:
    def __init__(self):
        self.records = 0          # chained records checked
        self.legacy = 0           # unchained lines before the chain began
        self.head_seq = 0
        self.head_hash = ""
        self.algs: set = set()
        self.problem: "str | None" = None
        self.line_no: "int | None" = None

    @property
    def ok(self) -> bool:
        return self.problem is None


def verify(path: str, key=None, anchor: "str | None" = None) -> Report:
    """Walk the log and check every link. Stops at the first problem.
    `anchor`: a hash printed by an earlier verify (a head you kept); the
    chain must still contain it, or the log was rewritten or cut."""
    rep = Report()
    found = anchor is None
    prev_line: "bytes | None" = None
    prev_hash: "str | None" = None
    prev_seq = 0
    prev_alg: "str | None" = None
    chained = False
    with open(path, "rb") as f:
        for no, raw in enumerate(f, 1):
            if not raw.endswith(b"\n"):
                rep.problem, rep.line_no = (
                    "the last line is incomplete (no newline): written "
                    "partially, or cut", no)
                return rep
            line = raw[:-1]
            if line.endswith(b"\r"):
                rep.problem, rep.line_no = (
                    "line ends in CR LF: the file was rewritten (a text "
                    "editor or a line-ending conversion)", no)
                return rep
            parts = split_record(line)
            if parts is None:
                if chained:
                    rep.problem, rep.line_no = (
                        "a line without a hash inside the chain: inserted "
                        "or damaged", no)
                    return rep
                rep.legacy += 1
                prev_line = line
                continue
            body, h = parts
            alg = h.split(":", 1)[0]
            try:
                rec = json.loads(body)
            except (ValueError, RecursionError):
                rep.problem, rep.line_no = "not valid JSON", no
                return rep
            if not isinstance(rec, dict):
                rep.problem, rep.line_no = "not a JSON object", no
                return rep
            if prev_alg == "hmac-sha256" and alg != "hmac-sha256":
                rep.problem, rep.line_no = (
                    "the chain was keyed (hmac-sha256) and this record is "
                    "not: written without the key, or forged", no)
                return rep
            if alg == "hmac-sha256" and key is None:
                rep.problem, rep.line_no = (
                    f"keyed record (hmac-sha256): set {KEY_ENV} to the key "
                    f"to verify it", no)
                return rep
            if digest(body, alg, key) != h:
                rep.problem, rep.line_no = (
                    "the record does not match its hash: edited", no)
                return rep
            if prev_hash is not None:
                expect_prev, expect_seq = prev_hash, prev_seq + 1
            elif prev_line is not None:     # the first record after legacy
                expect_prev, expect_seq = digest(prev_line, alg, key), 1
            else:
                expect_prev, expect_seq = genesis(alg), 1
            if rec.get("prev") != expect_prev:
                rep.problem, rep.line_no = (
                    "the link to the previous record is broken: a record "
                    "before this one was edited, removed or reordered", no)
                return rep
            seq = rec.get("seq")
            if seq != expect_seq or isinstance(seq, bool):
                rep.problem, rep.line_no = (
                    f"seq is {seq!r}, expected {expect_seq}", no)
                return rep
            chained = True
            found = found or h == anchor
            rep.records += 1
            rep.algs.add(alg)
            prev_hash, prev_seq, prev_alg, prev_line = h, seq, alg, line
    rep.head_seq = prev_seq
    rep.head_hash = prev_hash or ""
    if not found:
        rep.problem = ("the anchor is not in the chain: the log was rewritten "
                       "or cut since that head was noted")
    return rep
