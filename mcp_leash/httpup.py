"""A remote MCP server (Streamable HTTP) presented to the proxy as if it were a
local process.

mcp-leash enforces its policy on newline-delimited JSON between two pipes.
For a server that lives at a URL, this module is the other end of those
pipes: it reads each message the proxy forwards, POSTs it to the server's MCP
endpoint, and writes whatever comes back (one JSON body, or a server-sent
event stream of messages) onto the pipe the proxy reads. The client still
talks to mcp-leash over stdio, so nothing changes for it; the policy, pins,
scanning, limits and audit log apply exactly as they do for a local server.

What it implements of the Streamable HTTP transport (spec revision
2025-03-26 and later): POST of one message or a batch with
`Accept: application/json, text/event-stream`; a 202 for notifications and
responses; a JSON body or an event stream in reply; the `Mcp-Session-Id`
header (kept and sent back, closed with DELETE at the end); the
`MCP-Protocol-Version` header taken from the initialize answer.

What it does not: server-initiated messages outside the stream of a request
(the optional GET stream), and resuming a dropped stream (`Last-Event-ID`).
Redirects are not followed (a credential header must not follow one), TLS
certificates are always verified, and plain `http://` is accepted only for
loopback unless the operator says otherwise.

Standard library only (urllib, threading, os.pipe).
"""

from __future__ import annotations

import http.client
import json
import os
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request

MAX_MESSAGE = 16 * 1024 * 1024      # one answer / one event, bytes
MAX_WORKERS = 32                    # requests in flight at once
_LOOPBACK = ("localhost", "127.0.0.1", "::1", "[::1]")
_TOKEN = frozenset("!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                   "abcdefghijklmnopqrstuvwxyz")


class UpstreamProblem(ValueError):
    """The URL or a header cannot be used."""


class _BadReply(Exception):
    """The server answered, with something that is not an MCP reply."""


def check_header(name: str, value: str) -> None:
    if not name or not set(name) <= _TOKEN:
        raise UpstreamProblem(f"{name!r} is not a valid header name")
    if any(c in value for c in "\r\n\x00") or not value.isascii():
        raise UpstreamProblem(f"the value of header {name} has a line break, "
                              f"NUL or non-ASCII character in it")
    reserved = {"content-type", "accept", "mcp-session-id", "host",
                "content-length", "transfer-encoding", "mcp-protocol-version"}
    if name.lower() in reserved:
        raise UpstreamProblem(f"header {name} is set by mcp-leash itself")


def check_url(url: str, allow_http: bool = False) -> urllib.parse.SplitResult:
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname
    except ValueError as e:
        raise UpstreamProblem(f"not a URL: {e}") from None
    if parts.scheme not in ("http", "https") or not host:
        raise UpstreamProblem(f"{url!r} is not an http(s) URL")
    if parts.username or parts.password:
        raise UpstreamProblem("put credentials in a header (--header-env), "
                              "not in the URL: URLs are logged")
    if parts.fragment:
        raise UpstreamProblem("a URL fragment is never sent: remove it")
    if parts.scheme == "http" and not allow_http and host not in _LOOPBACK:
        raise UpstreamProblem("plain http:// is allowed only for localhost "
                              "(a header with a credential would cross the "
                              "network in the clear); use https:// or "
                              "--allow-insecure-http")
    return parts


class Target:
    """What to connect to. Passed where a server command would be."""

    def __init__(self, url: str, headers: "dict | None" = None,
                 allow_http: bool = False, timeout: "float | None" = 30.0):
        self.parts = check_url(url, allow_http)
        self.url = url
        self.headers = dict(headers or {})
        for k, v in self.headers.items():
            check_header(k, v)
        self.timeout = timeout

    def __bool__(self) -> bool:
        return True

    def describe(self) -> str:
        p = self.parts
        host = p.hostname + (f":{p.port}" if p.port else "")
        return f"{p.scheme}://{host}{p.path or '/'}"

    def open(self) -> "HttpUpstream":
        return HttpUpstream(self)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _opener():
    return urllib.request.build_opener(_NoRedirect)


def _line_reader(fd: int):
    """readline() on a raw descriptor."""
    buf = bytearray()

    def readline() -> bytes:
        while True:
            i = buf.find(b"\n")
            if i >= 0:
                line = bytes(buf[:i + 1])
                del buf[:i + 1]
                return line
            chunk = os.read(fd, 65536)
            if not chunk:
                rest = bytes(buf)
                buf.clear()
                return rest
            buf.extend(chunk)
    return readline


def sse_events(resp):
    """The `data` of each event of a text/event-stream, as bytes. Comment
    lines, ids and retry hints are ignored; events of a type other than
    `message` are skipped; an event cut off by the end of the stream is not
    delivered (as the SSE standard says)."""
    data: list = []
    size = 0
    skip = False
    while True:
        raw = resp.readline(MAX_MESSAGE + 2)
        if not raw:
            return
        if len(raw) > MAX_MESSAGE + 1:
            raise ValueError("an event line is over the size limit")
        line = raw.rstrip(b"\r\n")
        if not line:
            if data and not skip:
                yield b"\n".join(data)
            data, size, skip = [], 0, False
            continue
        if line.startswith(b":"):
            continue
        field, _sep, value = line.partition(b":")
        if value.startswith(b" "):
            value = value[1:]
        if field == b"data":
            data.append(value)
            size += len(value) + 1
            if size > MAX_MESSAGE:
                raise ValueError("an event is over the size limit")
        elif field == b"event" and value not in (b"", b"message"):
            skip = True


class HttpUpstream:
    """Quacks like the subprocess.Popen the proxy expects: `stdin` takes the
    messages the proxy forwards, `stdout` gives the answers, and poll / wait /
    terminate / kill end it."""

    def __init__(self, target: Target):
        self.target = target
        self.returncode: "int | None" = None
        self.session: "str | None" = None
        self.protocol: "str | None" = None
        self._done = threading.Event()
        self._emit_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._closed = False
        self._slots = threading.Semaphore(MAX_WORKERS)
        self._workers: list = []
        self._opener = _opener()
        req_r, req_w = os.pipe()
        resp_r, resp_w = os.pipe()
        self._req_r, self._resp_w = req_r, resp_w
        self.stdin = os.fdopen(req_w, "wb", buffering=0)
        self.stdout = os.fdopen(resp_r, "rb")
        self.pid = None
        threading.Thread(target=self._pump, daemon=True,
                         name="mcp-leash-http-pump").start()

    # -- the Popen surface -------------------------------------------------

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if not self._done.wait(timeout):
            raise subprocess.TimeoutExpired("mcp-leash http upstream", timeout)
        return self.returncode

    def terminate(self) -> None:
        self._finish(-15)

    def kill(self) -> None:
        self._finish(-9)

    # -- internals -----------------------------------------------------------

    def _finish(self, code: int) -> None:
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
            self.returncode = code
        try:
            os.close(self._resp_w)       # the proxy reads end of file
        except OSError:
            pass
        self._done.set()

    def _emit(self, obj) -> None:
        if not isinstance(obj, (dict, list)):
            return
        data = json.dumps(obj, separators=(",", ":"),
                          ensure_ascii=True).encode("ascii") + b"\n"
        with self._emit_lock:
            if self._closed:
                return
            view = memoryview(data)
            try:
                while len(view):
                    n = os.write(self._resp_w, view)
                    view = view[n:]
            except OSError:
                pass

    def _error(self, req_id, message: str) -> None:
        self._emit({"jsonrpc": "2.0", "id": req_id,
                    "error": {"code": -32603, "message": message}})

    def _pump(self) -> None:
        readline = _line_reader(self._req_r)
        try:
            while True:
                line = readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                self._slots.acquire()
                t = threading.Thread(target=self._worker, args=(line,),
                                     daemon=True, name="mcp-leash-http-post")
                self._workers.append(t)
                t.start()
                self._workers = [w for w in self._workers if w.is_alive()]
        except OSError:
            pass
        finally:
            for t in list(self._workers):
                t.join(timeout=15)
            self._goodbye()
            try:
                os.close(self._req_r)
            except OSError:
                pass
            self._finish(0)

    def _goodbye(self) -> None:
        """End the session politely (the spec lets a server answer 405)."""
        if not self.session:
            return
        try:
            req = urllib.request.Request(
                self.target.url, method="DELETE",
                headers=self._headers({}))
            self._opener.open(req, timeout=5).close()
        except Exception:
            pass

    def _headers(self, extra: dict) -> dict:
        h = dict(self.target.headers)
        h.update(extra)
        if self.session:
            h["Mcp-Session-Id"] = self.session
        if self.protocol:
            h["MCP-Protocol-Version"] = self.protocol
        return h

    def _worker(self, line: bytes) -> None:
        ids: list = []
        try:
            try:
                msg = json.loads(line)
            except (ValueError, RecursionError):
                return
            for m in (msg if isinstance(msg, list) else [msg]):
                if isinstance(m, dict) and "method" in m and "id" in m:
                    ids.append(m["id"])
            answered: set = set()
            try:
                self._exchange(line, ids, answered)
            except urllib.error.HTTPError as e:
                self._http_error(e.code, ids, answered)
            except _BadReply as e:
                for i in ids:
                    if _key(i) not in answered:
                        self._error(i, f"upstream sent an unusable reply: {e}")
            except (urllib.error.URLError, http.client.HTTPException, OSError,
                    ValueError, TimeoutError) as e:
                why = getattr(e, "reason", e)
                for i in ids:
                    if _key(i) not in answered:
                        self._error(i, f"upstream unreachable: "
                                       f"{type(why).__name__}")
            else:
                for i in ids:
                    if _key(i) not in answered:
                        self._error(i, "upstream ended its reply without "
                                       "answering")
        finally:
            self._slots.release()

    def _http_error(self, code: int, ids: list, answered: set) -> None:
        if code == 404 and self.session:
            what = "the session has ended (HTTP 404): start a new one"
        elif 300 <= code < 400:
            what = f"upstream redirected (HTTP {code}); redirects are not followed"
        else:
            what = f"upstream answered HTTP {code}"
        for i in ids:
            if _key(i) not in answered:
                self._error(i, what)

    def _exchange(self, body: bytes, ids: list, answered: set) -> None:
        req = urllib.request.Request(
            self.target.url, data=body, method="POST",
            headers=self._headers({
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream"}))
        timeout = self.target.timeout or None
        resp = self._opener.open(req, timeout=timeout)
        with resp:
            sid = resp.headers.get("Mcp-Session-Id")
            if sid and not self.session and _plain_header(sid):
                self.session = sid
            if resp.status in (202, 204):
                return
            ctype = (resp.headers.get_content_type() or "").lower()
            if ctype == "application/json":
                data = resp.read(MAX_MESSAGE + 1)
                if len(data) > MAX_MESSAGE:
                    raise _BadReply("answer over the size limit")
                self._deliver(data, answered)
            elif ctype == "text/event-stream":
                try:
                    for data in sse_events(_Lines(resp)):
                        self._deliver(data, answered)
                except ValueError as e:
                    raise _BadReply(str(e)) from None
            else:
                raise _BadReply(f"content type {ctype or 'none'!r} is not "
                                f"JSON or an event stream")

    def _deliver(self, data: bytes, answered: set) -> None:
        try:
            obj = json.loads(data)
        except (ValueError, RecursionError):
            return          # not JSON: skipped (the request is answered below)
        for m in (obj if isinstance(obj, list) else [obj]):
            if not isinstance(m, dict):
                continue
            if "method" not in m and "id" in m:
                answered.add(_key(m["id"]))
                res = m.get("result")
                if (isinstance(res, dict) and self.protocol is None
                        and isinstance(res.get("protocolVersion"), str)
                        and _plain_header(res["protocolVersion"])):
                    self.protocol = res["protocolVersion"]
        self._emit(obj)


def _plain_header(value: str) -> bool:
    return (0 < len(value) <= 256 and value.isascii()
            and all(32 < ord(c) < 127 for c in value))


def _key(req_id) -> str:
    return f"{type(req_id).__name__}:{req_id!r}"


class _Lines:
    """readline(limit) for an HTTPResponse (it has it; this keeps the type
    that sse_events needs explicit and lets tests pass a BytesIO)."""

    def __init__(self, resp):
        self._r = resp

    def readline(self, limit: int = -1) -> bytes:
        return self._r.readline(limit)
