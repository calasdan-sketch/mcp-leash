"""How well does content scanning find secrets, and what does it cost?

Builds a corpus at run time (so no complete credential is ever written in
this repository): fake tokens, card numbers and the like in realistic
sentences, and benign text that looks a little like them (git hashes, UUIDs,
timestamps, base64, ordinary prose). Then it reports:

  * detection: of the N planted values, how many mcp-leash's scanner finds
    (recall), and how many of the benign samples it wrongly flags
    (false positives);
  * speed: megabytes of text scanned per second;
  * with --proxy, the same corpus sent through any other stdio proxy that
    sits in front of a server (give its command up to the `--`), counting a
    planted value as stopped when it no longer appears, unchanged, in the
    answer the client receives. That is an apples-to-apples way to compare
    with a tool that redacts or blocks responses, using its default rules.

    python benchmarks/bench_scan.py
    python benchmarks/bench_scan.py --proxy npx mcpwall      # the proxy runs `-- python server.py`
    python benchmarks/bench_scan.py --seed 3 --per-kind 100

The corpus is a sample, not a standard: a different seed or kind of text will
move the numbers, and a rule list can only know the formats it was given.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import string
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from mcp_leash import scan  # noqa: E402

ALNUM = string.ascii_letters + string.digits
UPPER = string.ascii_uppercase + string.digits
HEX = "0123456789abcdef"
B64 = ALNUM + "-_"


def rs(r, n, alphabet=ALNUM):
    return "".join(r.choice(alphabet) for _ in range(n))


def luhn_complete(r, prefix, length):
    body = prefix + "".join(r.choice(string.digits) for _ in range(length - len(prefix) - 1))
    for d in "0123456789":
        cand = body + d
        total, flip = 0, False
        for ch in reversed(cand):
            x = int(ch)
            if flip:
                x = x * 2 - 9 if x * 2 > 9 else x * 2
            total += x
            flip = not flip
        if total % 10 == 0:
            return cand
    raise AssertionError


# kind -> function(rng) -> the planted value (assembled from pieces here)
PLANTED = {
    "github_token": lambda r: "gh" + "p_" + rs(r, 36),
    "aws_access_key": lambda r: "AK" + "IA" + rs(r, 16, UPPER),
    "slack_token": lambda r: "xo" + "xb-" + rs(r, 12, string.digits) + "-" + rs(r, 24),
    "stripe_key": lambda r: "sk" + "_live_" + rs(r, 24),
    "google_api_key": lambda r: "AI" + "za" + rs(r, 35, B64),
    "anthropic_key": lambda r: "sk-" + "ant-api03-" + rs(r, 40, B64),
    "jwt": lambda r: "ey" + "J" + rs(r, 24, B64) + ".ey" + "J" + rs(r, 30, B64) + "." + rs(r, 32, B64),
    "private_key": lambda r: ("-----BEGIN " + "RSA PRIVATE KEY-----\n" + rs(r, 64) + "\n"
                              + rs(r, 64) + "\n-----END " + "RSA PRIVATE KEY-----"),
    "db_url_password": lambda r: "postgres://svc:" + rs(r, 16) + "@db.internal:5432/app",
    "assigned_secret": lambda r: r.choice(["API_KEY", "client_secret", "password"]) + "=" + rs(r, 28),
    "card_number": lambda r: luhn_complete(r, "4", 16),
    "huggingface_token": lambda r: "hf" + "_" + rs(r, 36),
    "gitlab_token": lambda r: "glp" + "at-" + rs(r, 20, B64),
    "google_oauth_token": lambda r: "ya" + "29." + rs(r, 50, B64),
    "https_url_password": lambda r: "https://svc:" + rs(r, 14) + "@host.example/p",
    "us_ssn": lambda r: "%03d-%02d-%04d" % (r.randint(100, 665), r.randint(1, 99), r.randint(1, 9999)),
}

SENTENCES = [
    "Here is the value you asked for: {v}",
    "config loaded ok\n{v}\nstarting server",
    '{{"result": "{v}", "status": "ok"}}',
    "Error: request failed with {v} in the header, retrying",
    "export THING={v}",
]


def benign(r):
    choices = [
        lambda: "commit " + rs(r, 40, HEX),
        lambda: "id " + "-".join([rs(r, 8, HEX), rs(r, 4, HEX), rs(r, 4, HEX), rs(r, 4, HEX), rs(r, 12, HEX)]),
        lambda: "sha256 " + rs(r, 64, HEX),
        lambda: "ts " + str(r.randint(10**15, 10**16 - 1)),
        lambda: "order 4111 1111 1111 1112 failed",
        lambda: "the password field is required and must be 12 characters",
        lambda: "api_key: <your key here>",
        lambda: "token = os.environ['TOKEN']",
        lambda: "build " + rs(r, 12, HEX) + " passed in 41s on 3 workers",
        lambda: "see https://example.com/docs/" + rs(r, 20, string.ascii_lowercase),
        lambda: "version 1.2.3-rc.4+build." + str(r.randint(1, 999)),
        lambda: "phone 204-555-" + "%04d" % r.randint(0, 9999),
        lambda: " ".join(r.choice(["alpha", "beta", "gamma", "delta", "key", "secret", "token"])
                         for _ in range(30)),
        lambda: "data:image/png;base64," + rs(r, 120, B64),
        lambda: "hash " + rs(r, 32, HEX),
    ]
    return r.choice(choices)()


def build(seed, per_kind, benign_n):
    r = random.Random(seed)
    planted, clean = [], []
    for kind, make in PLANTED.items():
        for _ in range(per_kind):
            v = make(r)
            planted.append((kind, v, r.choice(SENTENCES).format(v=v)))
    for _ in range(benign_n):
        clean.append(benign(r))
    return planted, clean


def detection(planted, clean):
    kinds = scan.KINDS[:2]          # secrets + pii: what other tools call "secrets"
    per = {}
    for kind, value, text in planted:
        out, found = scan.redact_text(text, kinds)
        hit = bool(found) and value not in out
        row = per.setdefault(kind, [0, 0])
        row[0] += hit
        row[1] += 1
    fp = [t for t in clean if scan.find(t, kinds)]
    return per, fp


def speed(planted, clean):
    """MB/s on text dense with planted values, and on benign text only (the
    usual case: most answers contain nothing to find)."""
    out = []
    for texts in ([t for _k, _v, t in planted] + clean, clean):
        blob = "\n".join(texts) * (40 if len(texts) > 700 else 120)
        t0 = time.perf_counter()
        scan.redact_text(blob, scan.KINDS)
        dt = time.perf_counter() - t0
        out.append((len(blob.encode()) / 1e6 / dt, len(blob) / 1e6))
    return out


ECHO = r"""
import json, sys
for raw in sys.stdin.buffer:
    req = json.loads(raw)
    if "id" not in req:
        continue
    if req["method"] == "tools/call":
        text = req["params"]["arguments"].get("say", "")
        r = {"content": [{"type": "text", "text": text}]}
    else:
        r = {}
    sys.stdout.buffer.write(json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": r}).encode() + b"\n")
    sys.stdout.buffer.flush()
"""


def via_proxy(prefix, planted, clean, home):
    """Send every sample through `prefix -- python echo.py` and count what
    the client gets back."""
    server = os.path.join(home, "echo.py")
    with open(server, "w", encoding="utf-8") as f:
        f.write(ECHO)
    env = dict(os.environ, HOME=home, USERPROFILE=home)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.Popen(prefix + ["--", sys.executable, server], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
    kept = {}
    fp = 0
    try:
        samples = [(k, v, t) for k, v, t in planted] + [("_clean", None, t) for t in clean]
        for i, (kind, value, text) in enumerate(samples):
            msg = {"jsonrpc": "2.0", "id": i + 1, "method": "tools/call",
                   "params": {"name": "echo", "arguments": {"say": text}}}
            proc.stdin.write((json.dumps(msg) + "\n").encode())
            proc.stdin.flush()
            line = proc.stdout.readline()
            if not line:
                raise SystemExit("the proxy closed without answering")
            reply = line.decode("utf-8", "replace")
            intact = json.dumps(text)[1:-1] in reply
            if kind == "_clean":
                fp += (not intact)
            else:
                row = kept.setdefault(kind, [0, 0])
                row[0] += (value not in json.loads(line).get("result", {}).get(
                    "content", [{}])[0].get("text", "")) if "result" in json.loads(line) else 1
                row[1] += 1
    finally:
        proc.stdin.close()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
    return kept, fp


def blind_spots():
    """Ways of hiding a value from a pattern list. Reported so the 100% above
    is not mistaken for a promise: some of these are seen, some are not."""
    import base64
    import urllib.parse
    r = random.Random(99)
    tok = PLANTED["github_token"](r)
    forms = {
        "base64": base64.b64encode(tok.encode()).decode(),
        "hex": tok.encode().hex(),
        "url-encoded": urllib.parse.quote("".join(c + "\x00" for c in tok)),
        "split in two": tok[:20] + "\n" + tok[20:],
        "spaced out": " ".join(tok),
        "reversed": tok[::-1],
        "zero-width inside": tok[:10] + "\u200b" + tok[10:],
        "full-width letters": "".join(
            chr(0xFF01 + ord(c) - 33) if c.isalnum() else c for c in tok),
        "Cyrillic look-alike": tok.replace("p", "\u0440", 1),
        "percent-escaped": "".join("%%%02x" % ord(c) for c in tok),
        "base64 url-safe, with a prefix": base64.urlsafe_b64encode(("key=" + tok).encode()).decode(),
    }
    kinds = scan.KINDS[:2]
    return {k: (bool(scan.find("x " + v, kinds)), bool(scan.find("x " + v, kinds, True)))
            for k, v in forms.items()}


def table(per, total_clean, fp, title):
    stopped = sum(a for a, _b in per.values())
    n = sum(b for _a, b in per.values())
    print(f"\n{title}")
    print(f"  {'kind':18}{'stopped':>10}")
    for kind, (a, b) in per.items():
        print(f"  {kind:18}{a:>5}/{b:<4}")
    print(f"  {'ALL':18}{stopped:>5}/{n:<4} = {100 * stopped / n:.0f}%   "
          f"false positives on benign text: {fp}/{total_clean} = {100 * fp / total_clean:.1f}%")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--per-kind", type=int, default=50)
    ap.add_argument("--benign", type=int, default=600)
    ap.add_argument("--proxy", nargs="+", metavar="CMD",
                    help="also run the corpus through this proxy command "
                         "(up to the `--` before the server)")
    args = ap.parse_args()
    planted, clean = build(args.seed, args.per_kind, args.benign)
    per, fp = detection(planted, clean)
    table(per, len(clean), len(fp), "mcp-leash scanner (in process, secrets+pii)")
    (dense, dsize), (plain, psize) = speed(planted, clean)
    print(f"\n  speed, all four detector kinds: {dense:.1f} MB/s on {dsize:.1f} MB "
          f"dense with planted values; {plain:.1f} MB/s on {psize:.1f} MB of benign text")
    blind = blind_spots()
    print(f"  evasions tried on one token ({len(blind)}): found by default "
          f"{sum(a for a, _b in blind.values())}, with scan.decode "
          f"{sum(b for _a, b in blind.values())}")
    for k, (a, b) in blind.items():
        print(f"    {k:32} default {'found ' if a else 'MISSED'}  decode {'found' if b else 'MISSED'}")
    with tempfile.TemporaryDirectory() as home:
        policy = os.path.join(home, "policy.json")
        with open(policy, "w", encoding="utf-8") as f:
            json.dump({"allow_tools": ["*"], "hide_denied": False,
                       "scan": {"results": {"secrets": "redact", "pii": "redact"}}}, f)
        kept, fpp = via_proxy([sys.executable, "-m", "mcp_leash", "--policy", policy],
                              planted, clean, home)
        table(kept, len(clean), fpp, "mcp-leash through a real proxy session (results redacted)")
        if args.proxy:
            kept, fpp = via_proxy(args.proxy, planted, clean, home)
            table(kept, len(clean), fpp, f"{' '.join(args.proxy)} through a real proxy session")
    return 0


if __name__ == "__main__":
    sys.exit(main())
