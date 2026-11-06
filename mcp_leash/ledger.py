"""Tamper-evident audit log: a hash chain over JSON lines.

Every record mcp-leash writes ends with fields that tie it to the one before:

    {..., "seq": 7, "prev": "sha256:<hash of record 6>", "hash": "sha256:<hex>"}

`hash` is the digest of the record's own bytes up to (not including) the
`, "hash": ...` suffix, closed with `}`. Because `prev` is inside those bytes,
each record commits to the whole history before it: editing, deleting,
inserting or reordering any record breaks every link after it, and
`mcp-leash verify-audit` reports the first line where that happens.

With a key (MCP_LEASH_AUDIT_KEY_FILE naming a private file, or
MCP_LEASH_AUDIT_KEY) the digest is an HMAC-SHA256 under that key
(`"hmac-sha256:<hex>"`), so someone who can write the file but does not have
the key cannot forge a consistent chain. Both variables are removed from the
environment of the server mcp-leash starts.

An interrupted write (power loss, a killed process) can leave an incomplete
last line. The next append, under the lock, ends that line and writes a
`"event": "recovered"` record that names it by hash; verify-audit counts it as
recovered, not as tampering.

What a chain cannot show by itself: records cut off the END of the file
(the remaining chain is still consistent), or, without a key, a whole file
rewritten from scratch. `verify-audit` prints the head (last seq and hash):
keep it somewhere else and pass it back with --anchor to catch either.

Zero dependencies: hashlib, hmac, and fcntl (POSIX) or msvcrt (Windows) for
the file lock that keeps several mcp-leash processes (one per wrapped server)
sharing one log from forking the chain. An append that cannot take the lock
fails (OSError) rather than writing unlocked.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import threading
import time

KEY_ENV = "MCP_LEASH_AUDIT_KEY"
KEY_FILE_ENV = "MCP_LEASH_AUDIT_KEY_FILE"
SECRET_ENVS = (KEY_ENV, KEY_FILE_ENV)   # never passed to the server
_SUFFIX = re.compile(rb', "hash": "((?:sha256|hmac-sha256):[0-9a-f]{64})"\}\Z')
ALGS = ("sha256", "hmac-sha256")
KEYED = "hmac-sha256"

# One id per mcp-leash process: tells the sessions apart in a shared log.
SESSION = secrets.token_hex(6)

_lock = threading.Lock()                 # threads of this process
# path -> ((size, (dev, inode)), head hash, seq) after our last append: when
# the file is still that size and that file, its tail need not be re-read
_cache: dict = {}
_warned: set = set()
_TAIL_CHUNK = 64 * 1024
_TAIL_MAX = 16 * 1024 * 1024            # longest last line we will look for
_LOCK_WAIT = 30.0                        # seconds to wait for the file lock


class KeyProblem(ValueError):
    """The audit key is configured but cannot be used."""


_key_cache: dict = {}


def audit_key() -> "bytes | None":
    """The audit key: the contents of the file MCP_LEASH_AUDIT_KEY_FILE
    names (preferred: the key itself is never in an environment, where on
    Linux a process of the same user can read it from /proc/<pid>/environ),
    or MCP_LEASH_AUDIT_KEY. None when neither is set. KeyProblem when one is
    set and unusable: both set, a file that is missing, empty, or readable
    by others (POSIX)."""
    path, inline = os.environ.get(KEY_FILE_ENV), os.environ.get(KEY_ENV)
    if path and inline:
        raise KeyProblem(f"both {KEY_FILE_ENV} and {KEY_ENV} are set; use one "
                         f"({KEY_FILE_ENV} is the safer)")
    if inline:
        return inline.encode("utf-8")
    if not path:
        return None
    path = os.path.expanduser(path)
    if path in _key_cache:
        return _key_cache[path]
    try:
        st = os.stat(path)
        if os.name != "nt" and stat.S_IMODE(st.st_mode) & 0o077:
            raise KeyProblem(f"{KEY_FILE_ENV} {path} can be read by other "
                             f"users (mode {oct(stat.S_IMODE(st.st_mode))}); "
                             f"chmod 600 it")
        with open(path, "rb") as f:
            key = f.read().strip()
    except OSError as e:
        raise KeyProblem(f"cannot read {KEY_FILE_ENV} {path}: "
                         f"{e.strerror or e}") from None
    if not key:
        raise KeyProblem(f"{KEY_FILE_ENV} {path} is empty")
    _key_cache[path] = key
    return key


def _alg(key) -> str:
    return KEYED if key else "sha256"


def digest(data: bytes, alg: str, key) -> str:
    if alg == KEYED:
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


def _seq_of(body: bytes):
    try:
        seq = json.loads(body).get("seq")
    except (ValueError, AttributeError, RecursionError):
        return None
    return seq if isinstance(seq, int) and not isinstance(seq, bool) else None


# -- the file lock ----------------------------------------------------------


class _FileLock:
    """Exclusive lock for the read-tail-then-append step. POSIX: flock on the
    log itself. Windows: msvcrt locks a byte range, and a locked range of the
    log could not be read by anyone meanwhile, so the lock is taken on a
    separate `<log>.lock` file. Either way a lock that cannot be had within
    _LOCK_WAIT seconds is an OSError: the record is not written unlocked."""

    def __init__(self, path: str, f):
        self.path, self.f = path, f
        self._release = None

    def __enter__(self):
        try:
            import fcntl
        except ImportError:
            self._release = self._windows()
            return self
        try:
            fcntl.flock(self.f.fileno(), fcntl.LOCK_EX)
        except OSError as e:
            raise OSError(e.errno, f"cannot lock the audit log: "
                                   f"{e.strerror or e}") from None
        self._release = lambda: fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
        return self

    def _windows(self):
        import msvcrt
        fd = os.open(self.path + ".lock",
                     os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600)
        deadline = time.monotonic() + _LOCK_WAIT
        while True:
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                break
            except OSError:
                if time.monotonic() > deadline:
                    os.close(fd)
                    raise OSError(f"cannot lock the audit log ({self.path}"
                                  f".lock held for over {_LOCK_WAIT:.0f}s)")
                time.sleep(0.01)

        def release():
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            finally:
                os.close(fd)
        return release

    def __exit__(self, *exc):
        if self._release is not None:
            self._release()
        return False


# -- writing ----------------------------------------------------------------


def _tail(r, size: int) -> tuple:
    """(last complete line or None, incomplete last line or None), read
    backwards in chunks; newlines not included."""
    end, buf = size, b""
    while end > 0 and len(buf) <= _TAIL_MAX:
        start = max(0, end - _TAIL_CHUNK)
        r.seek(start)
        buf = r.read(end - start) + buf
        end = start
        if buf.count(b"\n") >= 2:
            break
    complete = buf.endswith(b"\n")
    parts = (buf[:-1] if complete else buf).split(b"\n")
    if end > 0:
        parts = parts[1:]       # the first piece may start mid-line
    if complete:
        return (parts[-1] if parts else None), None
    return (parts[-2] if len(parts) >= 2 else None), (parts[-1] if parts
                                                       else buf)


def _state(r, size: int, alg: str, key, notes: list) -> tuple:
    """(prev for the next record, seq of the last good record, the
    incomplete last line or None)."""
    if size == 0:
        return genesis(alg), 0, None
    last, partial = _tail(r, size)
    if last is None:
        return genesis(alg), 0, partial
    parts = split_record(last)
    seq = _seq_of(parts[0]) if parts else None
    if parts is None or seq is None:
        # a record from before the chain: link to its bytes so that nothing
        # can be slipped in between it and what follows
        if key:
            notes.append("the audit log's last line is not a keyed record "
                         "(an older or unkeyed log): `verify-audit` with the "
                         "key will report the chain as broken there")
        return digest(last, alg, key), 0, partial
    body, h = parts
    last_alg = h.split(":", 1)[0]
    if key and (last_alg != KEYED or digest(body, KEYED, key) != h):
        notes.append("the audit log's last record was written without this "
                     "key or with a different one (or was edited): the "
                     "keyed chain is broken there")
    elif not key and last_alg == KEYED:
        notes.append("the audit log is keyed but no audit key is set "
                     f"({KEY_FILE_ENV}): these records break its keyed chain")
    return h, seq, partial


def _encode(record: dict, alg: str, key) -> tuple[bytes, str]:
    body = json.dumps(record, ensure_ascii=True).encode("ascii")
    h = digest(body, alg, key)
    return body[:-1] + b', "hash": "' + h.encode("ascii") + b'"}\n', h


def append(path: str, event: dict, opener, warn=None) -> None:
    """Add `event` to the log at `path` as the next link of the chain.
    `opener(path)` returns a binary append handle (created 0600); `warn`
    takes a line for stderr (each kind once per log per process). Raises
    OSError when the record cannot be written, KeyProblem for a bad key."""
    key = audit_key()
    alg = _alg(key)
    with _lock, opener(path) as f, _FileLock(path, f):
        st = os.fstat(f.fileno())
        size, ident = st.st_size, (st.st_dev, st.st_ino)
        cached = _cache.get(path)
        out = b""
        if cached is not None and cached[0] == (size, ident) and \
                cached[1].startswith(alg + ":"):
            prev, seq = cached[1], cached[2]
        else:
            notes: list = []
            with open(path, "rb") as r:
                prev, seq, partial = _state(r, size, alg, key, notes)
            for note in notes:
                if warn is not None and (path, note) not in _warned:
                    _warned.add((path, note))
                    warn(note)
            if partial is not None:
                rec = {"event": "recovered", "decision": "note",
                       "reason": f"an interrupted write left an incomplete "
                                 f"line ({len(partial)} bytes); it is kept "
                                 f"as it is and named here",
                       "damaged": digest(partial, alg, key),
                       "at": int(time.time()), "session": SESSION,
                       "seq": seq + 1, "prev": prev}
                line, prev = _encode(rec, alg, key)
                seq += 1
                out = b"\n" + line
        record = dict(event)
        record["seq"] = seq + 1
        record["prev"] = prev
        line, h = _encode(record, alg, key)
        out += line
        f.write(out)
        f.flush()
        _cache[path] = ((size + len(out), ident), h, seq + 1)


# -- verifying --------------------------------------------------------------


class Report:
    def __init__(self):
        self.records = 0          # chained records checked
        self.legacy = 0           # unchained lines before the chain began
        self.recovered = 0        # interrupted writes, marked by a record
        self.torn_tail = 0        # bytes of an incomplete last line, if any
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

    With `key`, the log must be keyed throughout: every record hmac-sha256
    under that key, no unchained lines (older records), and not empty.
    `anchor`: a hash printed by an earlier verify (a head you kept); the
    chain must still contain it, or the log was rewritten or cut."""
    rep = Report()
    strict = key is not None
    prev_hash: "str | None" = None   # hash of the last chained record
    prev_seq = 0
    legacy_line: "bytes | None" = None   # last unchained line before chain
    held: "tuple[int, bytes] | None" = None   # an unchained line, undecided
    found = anchor is None

    def fail(why, no):
        rep.problem, rep.line_no = why, no
        return rep

    def settle_held() -> "Report | None":
        """The unchained line held back was not followed by a record that
        marks it recovered: an older record, or a line slipped in."""
        nonlocal held, legacy_line
        no, line = held
        held = None
        if prev_hash is not None:
            return fail("a line without a hash inside the chain: inserted "
                        "or damaged", no)
        if strict:
            return fail("an unchained line in a keyed log (an older or "
                        "unkeyed record, or one slipped in)", no)
        rep.legacy += 1
        legacy_line = line
        return None

    with open(path, "rb") as f:
        no = 0
        for no, raw in enumerate(f, 1):
            if not raw.endswith(b"\n"):     # the last line, incomplete
                if held is not None and settle_held():
                    return rep
                rep.torn_tail = len(raw)
                break
            line = raw[:-1]
            if line.endswith(b"\r"):
                return fail("line ends in CR LF: the file was rewritten (a "
                            "text editor or a line-ending conversion)", no)
            parts = split_record(line)
            if parts is None:
                if held is not None and settle_held():
                    return rep
                held = (no, line)
                continue
            body, h = parts
            alg = h.split(":", 1)[0]
            try:
                rec = json.loads(body)
            except (ValueError, RecursionError):
                return fail("not valid JSON", no)
            if not isinstance(rec, dict):
                return fail("not a JSON object", no)
            if strict and alg != KEYED:
                return fail("an unkeyed (sha256) record in a keyed log: "
                            "written without the key, or forged", no)
            if alg == KEYED and key is None:
                return fail(f"keyed record (hmac-sha256): set {KEY_FILE_ENV} "
                            f"(or {KEY_ENV}) to verify it", no)
            if digest(body, alg, key) != h:
                return fail("the record does not match its hash"
                            + (" under this key: edited, or written with a "
                               "different key" if alg == KEYED else
                               ": edited"), no)
            if held is not None:
                if (rec.get("event") == "recovered"
                        and rec.get("damaged") == digest(held[1], alg, key)):
                    held = None
                    rep.recovered += 1
                elif settle_held():
                    return rep
            if prev_hash is not None:
                expect_prev, expect_seq = prev_hash, prev_seq + 1
            elif legacy_line is not None:     # the first record after legacy
                expect_prev, expect_seq = digest(legacy_line, alg, key), 1
            else:
                expect_prev, expect_seq = genesis(alg), 1
            if rec.get("prev") != expect_prev:
                return fail("the link to the previous record is broken: a "
                            "record before this one was edited, removed or "
                            "reordered", no)
            seq = rec.get("seq")
            if seq != expect_seq or isinstance(seq, bool):
                return fail(f"seq is {seq!r}, expected {expect_seq}", no)
            found = found or h == anchor
            rep.records += 1
            rep.algs.add(alg)
            prev_hash, prev_seq = h, seq
        if held is not None and settle_held():
            return rep
    if strict and rep.records == 0:
        return fail("no keyed records: a keyed log is never empty once "
                    "mcp-leash has written to it (emptied, or the wrong file)",
                    None)
    rep.head_seq = prev_seq
    rep.head_hash = prev_hash or ""
    if not found:
        rep.problem = ("the anchor is not in the chain: the log was rewritten "
                       "or cut since that head was noted")
    return rep
