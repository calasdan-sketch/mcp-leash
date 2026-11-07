"""Measure what mcp-leash adds to one tools/call round trip.

Runs the same echo MCP server twice, once directly and once behind
mcp-leash, and times N sequential tools/call requests through real pipes
(the way an MCP client talks to a stdio server). Prints p50 / p90 / p99 per
call and the difference. Uses only the standard library.

    python benchmarks/bench_overhead.py            # 2000 calls
    python benchmarks/bench_overhead.py --calls 5000 --policy learned

The audit log goes to a throwaway HOME, so your real ~/.mcp-leash is not
touched. Every allowed call writes one hash-chained audit record, so the
numbers include that write (and its flush) - they are the real cost.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time

ECHO = r"""
import json, sys
inp, out = sys.stdin.buffer, sys.stdout.buffer
for raw in iter(inp.readline, b""):
    req = json.loads(raw)
    if "id" not in req:
        continue
    if req["method"] == "tools/list":
        r = {"tools": [{"name": "read_file", "inputSchema": {"type": "object"}}]}
    else:
        r = {"content": [{"type": "text", "text": "ok"}]}
    out.write(json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": r}).encode() + b"\n")
    out.flush()
"""

POLICIES = {
    # what --init-policy writes
    "starter": {"allow_tools": ["*"], "deny_tools": [], "arg_rules": {}},
    # what learn writes: allowlist, typed argument rule, pin
    "learned": {
        "allow_tools": ["read_file"],
        "arg_rules": {"read_file": {"allow": {"path": [{
            "type": "string",
            "pattern": r"\A(?!.*(?:^|[/\\])\.\.(?:[/\\]|$))/srv/data/[a-zA-Z0-9_.-]*\Z"}]}}},
        "strict_args": True,
    },
    # the learned policy plus content scanning both ways (see bench_scan.py)
    "scanned": {
        "allow_tools": ["read_file"],
        "arg_rules": {"read_file": {"allow": {"path": [{
            "type": "string",
            "pattern": r"\A(?!.*(?:^|[/\\])\.\.(?:[/\\]|$))/srv/data/[a-zA-Z0-9_.-]*\Z"}]}}},
        "strict_args": True,
        "scan": {"arguments": {"secrets": "deny", "pii": "deny"},
                 "results": {"secrets": "redact", "pii": "redact",
                             "injection": "deny", "hidden": "redact"}},
    },
}


def run(cmd: list[str], calls: int, env: dict) -> list[float]:
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            env=env)
    w, r = proc.stdin, proc.stdout
    times = []
    try:
        for i in range(calls + 50):          # the first 50 warm up
            msg = {"jsonrpc": "2.0", "id": i, "method": "tools/call",
                   "params": {"name": "read_file",
                              "arguments": {"path": f"/srv/data/f{i}.txt"}}}
            data = (json.dumps(msg) + "\n").encode()
            t0 = time.perf_counter()
            w.write(data)
            w.flush()
            line = r.readline()
            t1 = time.perf_counter()
            if b'"result"' not in line:
                raise SystemExit(f"unexpected answer: {line[:200]!r}")
            if i >= 50:
                times.append((t1 - t0) * 1e6)
    finally:
        w.close()
        proc.wait(timeout=30)
    return times


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--calls", type=int, default=2000)
    ap.add_argument("--policy", choices=sorted(POLICIES), default="learned")
    ap.add_argument("--also", nargs="+", metavar="CMD",
                    help="time another stdio proxy too: its command, up to "
                         "the `--` before the server (it gets `-- python "
                         "echo.py`)")
    args = ap.parse_args()
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with tempfile.TemporaryDirectory() as tmp:
        server = os.path.join(tmp, "echo.py")
        with open(server, "w", encoding="utf-8") as f:
            f.write(ECHO)
        policy = os.path.join(tmp, "policy.json")
        with open(policy, "w", encoding="utf-8") as f:
            json.dump(POLICIES[args.policy], f)
        env = dict(os.environ, HOME=tmp, USERPROFILE=tmp,
                   PYTHONPATH=repo + os.pathsep + os.environ.get("PYTHONPATH", ""))
        env.pop("PYTHONUNBUFFERED", None)
        direct = run([sys.executable, server], args.calls, env)
        leashed = run([sys.executable, "-m", "mcp_leash", "--policy", policy,
                       "--", sys.executable, server], args.calls, env)
        other = (run(args.also + ["--", sys.executable, server], args.calls, env)
                 if args.also else None)
        audit = os.path.join(tmp, ".mcp-leash", "audit.jsonl")
        with open(audit, "rb") as f:
            records = sum(1 for _ in f)
    print(f"{platform.system()} {platform.machine()}, Python "
          f"{platform.python_version()}, {args.calls} sequential calls, "
          f"policy '{args.policy}', {records} audit records written")
    print(f"{'':10}{'p50':>10}{'p90':>10}{'p99':>10}{'mean':>10}   (microseconds)")
    rows = [("direct", direct), ("mcp-leash", leashed)]
    if other is not None:
        rows.append((os.path.basename(args.also[-1])[:9], other))
    for name, xs in rows:
        print(f"{name:10}{pct(xs, 50):10.0f}{pct(xs, 90):10.0f}"
              f"{pct(xs, 99):10.0f}{statistics.mean(xs):10.0f}")
    print(f"{'added':10}{pct(leashed, 50) - pct(direct, 50):10.0f}"
          f"{pct(leashed, 90) - pct(direct, 90):10.0f}"
          f"{pct(leashed, 99) - pct(direct, 99):10.0f}"
          f"{statistics.mean(leashed) - statistics.mean(direct):10.0f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
