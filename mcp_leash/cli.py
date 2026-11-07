"""mcp-leash: runtime permission firewall for MCP servers.

A stdio proxy that enforces a JSON policy on every tool call. mcp-audit
finds the problems; mcp-leash enforces least-privilege at runtime.

  mcp-leash --policy policy.json -- npx -y some-mcp-server
  mcp-leash --init-policy                # write an annotated starter policy
  mcp-leash --audit                      # show the audit log
  mcp-leash learn --script calls.json --out policy.json -- <server cmd>
  mcp-leash pin --policy policy.json -- <server cmd>   # pin tool definitions
  mcp-leash check --policy policy.json [TOOL [ARGS]]   # dry-run a decision
  mcp-leash test --policy p.json cases.json            # policy test cases
  mcp-leash verify-audit                 # check the audit log's hash chain
  mcp-leash rotate-audit                 # start a new log file, chain intact
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import sys

from . import VERSION
from . import jail as jail_mod
from . import httpup
from . import ledger


# Tests patch this to exercise the Windows branch on any OS.
_WINDOWS = os.name == "nt"


def _pipe_gone(exc: BaseException) -> bool:
    """Did the reader of our stdout go away?

    POSIX raises BrokenPipeError (EPIPE). Windows reports the same thing as
    a plain OSError with errno EINVAL and no file name (measured on Windows
    11 / Python 3.11: errno 22, winerror None), raised by the FLUSH rather
    than by the print, and it fails a second time at interpreter exit
    (status 120) unless fd 1 is pointed at the null device first."""
    if isinstance(exc, BrokenPipeError):
        return True
    if not isinstance(exc, OSError):
        return False
    if exc.errno == errno.EPIPE:
        return True
    return (_WINDOWS and exc.errno == errno.EINVAL
            and getattr(exc, "filename", None) is None)


def _broken_pipe() -> int:
    """stdout's reader went away (`mcp-leash --audit | head`): leave
    quietly. stdout is pointed at the null device first so the
    interpreter's exit-time flush cannot raise the same error again."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError, AttributeError):
        pass
    return 0


def _harden_streams() -> None:
    """Never crash on a console that cannot encode a tool name or reason.

    The proxy itself writes protocol bytes (UTF-8) straight to the binary
    stdout; this only affects the human-facing text output (--audit,
    learn summaries, errors) on e.g. a cp1252 Windows console.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        # Both handlers raise UnicodeEncodeError on a character the code
        # page lacks: "strict" (the default) and "surrogateescape" (what a
        # piped stdout reports on Windows 11 / Python 3.11, with cp1252).
        if reconfigure is None or getattr(stream, "errors", None) not in (
                "strict", "surrogateescape"):
            continue
        try:
            reconfigure(errors="replace")
        except (OSError, ValueError):
            pass


class _Parser(argparse.ArgumentParser):
    """argparse with nowhere to complain. error() prints the usage with
    print_usage(sys.stderr), and print_usage(None) means standard OUTPUT -
    which is where a process started with stderr closed would put it. It
    exits 2 without a word then."""

    def error(self, message):
        if sys.stderr is None:
            self.exit(2)
        super().error(message)


def _seconds(text: str) -> float:
    """argparse type for --timeout: a finite number of seconds, 0 or more.
    float() alone takes "nan" and "inf" and a minus sign."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a number of seconds") from None
    why = jail_mod.seconds_problem(value)
    if why is not None:
        raise argparse.ArgumentTypeError(f"{text!r} {why}")
    return value


def _positive_count(text: str) -> int:
    """argparse type for --limit: a whole number, 1 or more. int() alone takes
    0 (which showed the whole log) and negatives (which dropped lines): the
    log is cut with a slice that counts from the end."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a whole number") from None
    if value < 1:
        raise argparse.ArgumentTypeError(f"{text!r} is not 1 or more")
    return value


def cmd_init_policy(args) -> int:
    path = jail_mod.expand_path(args.path)
    if os.path.exists(path) and not args.force:
        jail_mod._say(f"exists: {path} (use --force to overwrite)")
        return 2
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(jail_mod.default_policy(), f, indent=2)
        f.write("\n")
    print(f"wrote {path}")
    return 0


def _plain(value) -> str:
    """A field of an audit record as one line of printable text. The log is
    JSON, so a newline, a terminal escape or a bidi override inside a reason
    (or a tool name: the client chooses it) is harmless there; printed as it
    is, it would forge lines in the report and drive the terminal. Whatever is
    not printable is shown as its escape: \\n, \\x1b, \\u202e."""
    if value is None:
        return ""
    if not isinstance(value, str):
        try:
            value = json.dumps(value)
        except (TypeError, ValueError):
            value = repr(value)
    return "".join(ch if ch.isprintable()
                   else ch.encode("unicode_escape").decode("ascii")
                   for ch in value)


def cmd_audit(args) -> int:
    path = jail_mod.audit_log_path()
    if not os.path.exists(path):
        print("no audit log yet.")
        return 0
    denies = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.readlines()[-args.limit:]
    for ln in lines:
        try:
            e = json.loads(ln)
        except (ValueError, RecursionError):
            continue
        if not isinstance(e, dict):
            continue
        decision = e.get("decision")
        denied = decision == "deny"
        denies += denied
        marks = {"deny": "DENY ", "would_deny": "WOULD", "redact": "REDACT",
                 "would_redact": "WOULD", "flag": "FLAG "}
        mark = marks.get(decision, "allow") if isinstance(decision, str) \
            else "allow"
        what = e.get("tool")
        if what is None and e.get("event") == "recovered":
            print(f"note  audit log: {_plain(e.get('reason', ''))}")
            continue
        if what is None:
            if e.get("rejected") is not None:  # a message the jail would not relay
                what = f"{_plain(e['rejected'])} message"
            else:  # a whole method refused by deny_methods
                what = f"method {_plain(e.get('method'))}"
        print(f"{mark} {_plain(what)} {_plain(e.get('reason', ''))}")
    print(f"\n{denies} denied in last {len(lines)} calls")
    return 0


def cmd_learn(argv: list[str]) -> int:
    p = _Parser(
        prog="mcp-leash learn",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Observe a server session and generate a tight-fit "
                    "allowlist policy: only the tools actually called, with "
                    "per-argument allow patterns derived from the values "
                    "seen.\n\n--script drives canned calls against the "
                    "server (no client needed); without it, learn proxies "
                    "stdin/stdout until stdin EOF or Ctrl-C.")
    p.add_argument("--script",
                   help="JSON array of {\"tool\": name, "
                        "\"arguments\": {...}} to drive against the server")
    p.add_argument("--out", help="write the policy here (default: stdout)")
    p.add_argument("--timeout", type=_seconds, default=30.0,
                   help="seconds to wait for each server response "
                        "(default: 30; 0 waits for ever)")
    p.add_argument("--grace", type=_seconds, default=jail_mod.DEFAULT_GRACE,
                   help="live mode: seconds to give the server to exit on "
                        "its own once stdin has ended, before it is sent "
                        "SIGTERM (default: 5; 0 stops it at once)")
    _add_url_options(p)
    p.add_argument("server", nargs=argparse.REMAINDER,
                   help="server command after -- : "
                        "mcp-leash learn --script c.json -- <cmd>")
    args = p.parse_args(argv)
    cmd = _server_cmd(args.server)
    cmd = _target(args, cmd)
    if not cmd:
        jail_mod._say("error: no server command: "
                      "mcp-leash learn [--script c.json] [--out p.json] "
                      "-- <cmd>  (or --url URL)")
        return 2
    return jail_mod.learn(cmd, script=args.script, out=args.out,
                          timeout=args.timeout, grace=args.grace)


def _server_cmd(server: list[str]) -> list[str]:
    cmd = list(server)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    return cmd


def _add_url_options(p) -> None:
    p.add_argument("--url", metavar="URL",
                   help="a remote MCP server (Streamable HTTP) instead of a "
                        "command: mcp-leash speaks stdio to your client, "
                        "HTTP to the server, and enforces the policy "
                        "between them")
    p.add_argument("--header", action="append", default=[],
                   metavar="'Name: value'",
                   help="send this header to --url (repeatable). The value "
                        "is visible in the process list: for a credential "
                        "use --header-env")
    p.add_argument("--header-env", action="append", default=[],
                   metavar="Name=ENVVAR",
                   help="send header Name with the value of environment "
                        "variable ENVVAR (e.g. Authorization=MY_TOKEN_HEADER "
                        "where it holds 'Bearer ...')")
    p.add_argument("--allow-insecure-http", action="store_true",
                   help="allow a plain http:// --url that is not localhost")


def _target(args, cmd: list[str]):
    """The server to run: the command, or a remote one from --url. None
    (after saying why) when the options cannot be used."""
    if not args.url:
        if args.header or args.header_env or args.allow_insecure_http:
            jail_mod._say("error: --header, --header-env and "
                          "--allow-insecure-http go with --url")
            return None
        return cmd or None
    if cmd:
        jail_mod._say("error: give a server command or --url, not both")
        return None
    headers = {}
    try:
        for text in args.header:
            name, sep, value = text.partition(":")
            if not sep:
                raise httpup.UpstreamProblem(f"--header {text!r}: expected "
                                             f"'Name: value'")
            headers[name.strip()] = value.strip()
        for text in args.header_env:
            name, sep, var = text.partition("=")
            if not sep or not var:
                raise httpup.UpstreamProblem(f"--header-env {text!r}: "
                                             f"expected Name=ENVVAR")
            value = os.environ.get(var)
            if not value:
                raise httpup.UpstreamProblem(f"--header-env: environment "
                                             f"variable {var} is not set")
            headers[name.strip()] = value.strip()
        return httpup.Target(args.url, headers, args.allow_insecure_http,
                             timeout=args.timeout or None)
    except httpup.UpstreamProblem as e:
        jail_mod._say(f"error: {e}")
        return None


def cmd_pin(argv: list[str]) -> int:
    default_policy = jail_mod.default_policy_path()
    p = _Parser(
        prog="mcp-leash pin",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Start the server, list its tools, and record the "
                    "SHA-256 of each tool the policy allows in the policy's "
                    "tool_pins. While mcp-leash runs, a pinned tool whose "
                    "description or schema changes (a rug pull) is hidden "
                    "and its calls are denied until you review it and pin "
                    "again. Changed and new tools are shown with their "
                    "description first.")
    p.add_argument("--policy", default=default_policy, metavar="FILE",
                   help=f"policy file to update (default: {default_policy})")
    p.add_argument("--timeout", type=_seconds, default=30.0, metavar="SECS",
                   help="seconds to wait for each server response "
                        "(default: 30; 0 waits for ever)")
    p.add_argument("--dry-run", action="store_true",
                   help="show what would change, write nothing")
    p.add_argument("--accept-changed", action="store_true",
                   help="replace the pins of tools whose definition changed "
                        "(without it they keep their old pin, stay denied, "
                        "and the exit status is 1)")
    _add_url_options(p)
    p.add_argument("server", nargs=argparse.REMAINDER,
                   help="server command after -- ")
    args = p.parse_args(argv)
    cmd = _target(args, _server_cmd(args.server))
    if not cmd:
        jail_mod._say("error: no server command: "
                      "mcp-leash pin --policy p.json -- <cmd>  (or --url URL)")
        return 2
    return jail_mod.pin(args.policy, cmd, timeout=args.timeout,
                        dry_run=args.dry_run,
                        accept_changed=args.accept_changed)


def cmd_check(argv: list[str]) -> int:
    default_policy = jail_mod.default_policy_path()
    p = _Parser(
        prog="mcp-leash check",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Dry-run a policy, no server needed.\n\n"
                    "  mcp-leash check --policy p.json\n"
                    "      load it, summarise it, warn about weak settings "
                    "(exit 0; 2 if mcp-leash would refuse it)\n"
                    "  mcp-leash check --policy p.json run_cmd "
                    "'{\"cmd\": \"rm -rf /\"}'\n"
                    "      the decision for that call and why "
                    "(exit 0 allow, 1 deny)")
    p.add_argument("--policy", default=default_policy, metavar="FILE",
                   help=f"policy file (default: {default_policy})")
    p.add_argument("--method", default="tools/call",
                   help="JSON-RPC method of the call (default: tools/call); "
                        "for resources/read give the URI as TOOL; for "
                        "completion/complete a URI or a prompt name, made "
                        "into the ref the proxy judges")
    p.add_argument("--params", metavar="JSON",
                   help="the call's whole params object, judged exactly as "
                        "the proxy judges it (instead of TOOL and ARGS)")
    p.add_argument("tool", nargs="?", help="tool name (or URI)")
    p.add_argument("arguments", nargs="?",
                   help="the call's arguments as a JSON object "
                        "(default: {})")
    args = p.parse_args(argv)
    return jail_mod.check(args.policy, args.tool, args.arguments,
                          method=args.method, params_text=args.params)


def cmd_test(argv: list[str]) -> int:
    default_policy = jail_mod.default_policy_path()
    p = _Parser(
        prog="mcp-leash test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Run a file of expected decisions against a policy, no "
                    "server needed, with the proxy's own code. Each case is "
                    "{\"tool\": ..., \"arguments\": {...}, \"expect\": "
                    "\"allow\"|\"deny\", \"reason_contains\": ...} and/or "
                    "{\"answer\": text, \"expect_answer\": "
                    "\"clean\"|\"flag\"|\"redact\"|\"deny\"}. Keep the file "
                    "next to the policy and run it in CI.\n\nexit status: 0 "
                    "all passed, 1 some failed, 2 unusable policy or file")
    p.add_argument("--policy", default=default_policy, metavar="FILE",
                   help=f"policy file (default: {default_policy})")
    p.add_argument("cases", help="JSON array of cases")
    args = p.parse_args(argv)
    return jail_mod.run_cases(args.policy, args.cases)


def cmd_verify_audit(argv: list[str]) -> int:
    p = _Parser(
        prog="mcp-leash verify-audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Check the audit log's hash chain: every record must "
                    "match its hash and link to the one before it, so an "
                    "edited, deleted, inserted or reordered record is found. "
                    f"Records written with an audit key ({ledger.KEY_FILE_ENV}"
                    f" or {ledger.KEY_ENV}) are HMAC-keyed and need the same "
                    "key here; with a key, every record must be keyed. Prints the head "
                    "(last seq and hash): keep a copy elsewhere to catch "
                    "records cut off the end.\n\nexit status: 0 intact, "
                    "1 broken (the first bad line is named), 2 no log")
    p.add_argument("file", nargs="?",
                   help="audit log (default: the one mcp-leash writes)")
    p.add_argument("--all", action="store_true",
                   help="also check the rotated files beside the log, oldest "
                        "first, and that each one carries on from the last "
                        "(see rotate-audit)")
    p.add_argument("--anchor", metavar="HASH",
                   help="a head hash noted earlier: the chain must still "
                        "contain it (catches a log rewritten from scratch or "
                        "cut back past it)")
    args = p.parse_args(argv)
    path = (jail_mod.expand_path(args.file) if args.file
            else jail_mod.audit_log_path())
    try:
        if args.all:
            return _verify_all(path, args.anchor)
        rep = ledger.verify(path, ledger.audit_key(), anchor=args.anchor)
    except ledger.KeyProblem as e:
        jail_mod._say(f"mcp-leash verify-audit: audit key: {e}")
        return 2
    except FileNotFoundError:
        jail_mod._say(f"mcp-leash verify-audit: no audit log at {path}")
        return 2
    except OSError as e:
        jail_mod._say(f"mcp-leash verify-audit: cannot read {path}: {e}")
        return 2
    if not rep.ok:
        where = f"line {rep.line_no}: " if rep.line_no else ""
        print(f"BROKEN {path}: {where}{rep.problem}")
        print(f"  {rep.records} record(s) before it verified")
        return 1
    legacy = (f"; {rep.legacy} older unchained line(s) at the start"
              if rep.legacy else "")
    recovered = (f"; {rep.recovered} interrupted write(s), marked recovered"
                 if rep.recovered else "")
    algs = "/".join(sorted(rep.algs)) or "none"
    print(f"OK {path}: {rep.records} chained record(s) ({algs})"
          f"{legacy}{recovered}")
    if rep.torn_tail:
        print(f"  note: the last line is incomplete ({rep.torn_tail} bytes: "
              f"an interrupted write); the next record mcp-leash writes "
              f"marks it recovered")
    if rep.continues:
        print(f"  note: this file begins after a rotation (it carries on from "
              f"seq {rep.continues[1]} {rep.continues[0]}); check the older "
              f"files with --all")
    if rep.records:
        print(f"  head: seq {rep.head_seq} {rep.head_hash}")
    return 0


def _verify_all(path: str, anchor) -> int:
    files = ledger.segments(path)
    if not files:
        raise FileNotFoundError(path)
    key = ledger.audit_key()
    start, total = None, 0
    for i, name in enumerate(files):
        last = i == len(files) - 1
        rep = ledger.verify(name, key, anchor=anchor if last else None,
                            start=start)
        if not rep.ok:
            where = f"line {rep.line_no}: " if rep.line_no else ""
            print(f"BROKEN {name}: {where}{rep.problem}")
            return 1
        if start is None and rep.continues:
            print(f"  note: the oldest file kept, {os.path.basename(name)}, "
                  f"begins after a rotation: older files are not here")
        total += rep.records
        if rep.records:
            start = (rep.head_hash, rep.head_seq)
    print(f"OK {len(files)} file(s), {total} chained record(s), one unbroken "
          f"chain")
    if start:
        print(f"  head: seq {start[1]} {start[0]}")
    return 0


def cmd_rotate_audit(argv: list[str]) -> int:
    p = _Parser(
        prog="mcp-leash rotate-audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Move the audit log aside (audit.jsonl.<UTC stamp>) and "
                    "start a new file whose first record carries on the hash "
                    "chain, so the files together stay one verifiable chain "
                    "(`verify-audit --all`). Nothing is ever deleted. The "
                    "policy key audit_max_bytes does this by itself when the "
                    "log reaches that size.\n\nexit status: 0 rotated, 1 "
                    "nothing to rotate, 2 failed")
    p.parse_args(argv)
    path = jail_mod.audit_log_path()
    try:
        old = ledger.rotate_now(path, jail_mod._open_private_append)
    except (OSError, ledger.KeyProblem) as e:
        jail_mod._say(f"mcp-leash rotate-audit: {e}")
        return 2
    if old is None:
        print("nothing to rotate (no log, an empty one, an older unchained "
              "one, or one that cannot be moved right now)")
        return 1
    print(f"rotated: {old}\nnew log: {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    default_policy = jail_mod.default_policy_path()
    p = _Parser(
        prog="mcp-leash", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="subcommands (each has --help): learn, pin, check, test, "
               "verify-audit, rotate-audit\n\n"
               "exit status: 0 a clean session; 2 an unusable policy or "
               "command; 3 the server failed (it exited or closed its pipes, "
               "stopped reading its input, or did not answer a request "
               "within --timeout); 128+N (143, 129) stopped by SIGTERM or "
               "SIGHUP after closing the server's input and waiting --grace")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    p.add_argument("--policy", default=default_policy, metavar="FILE",
                   help=f"policy file; ~ and environment variables are "
                        f"expanded (default: {default_policy})")
    p.add_argument("--init-policy", action="store_true",
                   help="write an annotated starter policy to --path and "
                        "exit (allows every tool: edit it)")
    p.add_argument("--path", default=default_policy, metavar="FILE",
                   help=f"where --init-policy writes "
                        f"(default: {default_policy})")
    p.add_argument("--force", action="store_true",
                   help="let --init-policy overwrite an existing file")
    p.add_argument("--audit", action="store_true",
                   help="print the last --limit audit-log entries "
                        "(allow/deny per tool call) and exit")
    p.add_argument("--limit", type=_positive_count, default=50, metavar="N",
                   help="how many audit entries --audit shows: the last N, "
                        "a whole number, 1 or more (default: 50)")
    p.add_argument("--timeout", type=_seconds, default=30.0, metavar="SECS",
                   help="seconds to wait for each server response, and for "
                        "the server to take each message off its stdin "
                        "(default: 30; 0 waits for ever)")
    p.add_argument("--grace", type=_seconds, default=jail_mod.DEFAULT_GRACE,
                   metavar="SECS",
                   help="seconds to give the server to finish and exit on "
                        "its own once the client's input has ended and every "
                        "request is answered; then it is sent SIGTERM, and "
                        "killed if it ignores that (default: 5; 0 stops it "
                        "at once)")
    _add_url_options(p)
    p.add_argument("--monitor", action="store_true",
                   help="dry run on live traffic: judge every message and "
                        "write the audit record, but block, hide and redact "
                        "nothing (decisions read would_deny / would_redact). "
                        "Use it to see what a new policy would break before "
                        "you enforce it")
    p.add_argument("server", nargs=argparse.REMAINDER,
                   help="server command after -- : "
                        "mcp-leash --policy p.json -- npx -y srv")
    return p


def _main(argv: list[str]) -> int:
    if argv[:1] == ["learn"]:
        return cmd_learn(argv[1:])
    if argv[:1] == ["pin"]:
        return cmd_pin(argv[1:])
    if argv[:1] == ["check"]:
        return cmd_check(argv[1:])
    if argv[:1] == ["test"]:
        return cmd_test(argv[1:])
    if argv[:1] == ["verify-audit"]:
        return cmd_verify_audit(argv[1:])
    if argv[:1] == ["rotate-audit"]:
        return cmd_rotate_audit(argv[1:])
    args = build_parser().parse_args(argv)
    if args.init_policy:
        return cmd_init_policy(args)
    if args.audit:
        return cmd_audit(args)
    cmd = _target(args, _server_cmd(args.server))
    if not cmd:
        jail_mod._say("error: no server command: "
                      "mcp-leash --policy p.json -- <cmd>  (or --url URL)")
        return 2
    return jail_mod.run(args.policy, cmd, timeout=args.timeout,
                        grace=args.grace, monitor=args.monitor)


def main(argv=None) -> int:
    _harden_streams()
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        rc = _main(argv)
        if sys.stdout is not None:
            sys.stdout.flush()  # a closed pipe surfaces here, not at interpreter exit
        return rc
    except OSError as e:
        if _pipe_gone(e):
            return _broken_pipe()
        raise


if __name__ == "__main__":
    sys.exit(main())
