# Round 4: the stranger's first hour

Scope: what a person gets from `pip install mcp-leash` and the README alone.
Branch `expert-2`. Nothing was published, tagged or pushed.

**How this was done, honestly.** One agent played every specialist in turn.
No independent sub-agents were available in this run, so these are
perspectives, not independent reviewers. Each finding below names the command
that showed it. Everything ran on Linux (Python 3.13 for the work; 3.11 and
3.12 for the final test and install runs). The machine was shared and busy
(load average about 10), so timings are noisy.

## Findings by specialist

| Specialist | Finding | Proof |
|---|---|---|
| First-time user (README only, clean venv, folder name with spaces) | The README quick start needs an MCP server the reader may not have; nothing to try in 5 seconds. | Followed the README in a fresh venv: `learn`, `check`, wrapped session, `--audit`, `verify-audit` all worked, but only after writing a fake server. Fixed: `mcp-leash demo`. |
| First-time user on Windows | A policy saved by Notepad (UTF-8 with BOM) was refused: "Unexpected UTF-8 BOM". UTF-16 (PowerShell `>`) gave "'utf-8' codec can't decode byte 0xff". | `printf '\xef\xbb\xbf...' > bom.json; mcp-leash check --policy bom.json` (rc 2 before, OK after). |
| Release engineer | Registry has 0.7.0 only; repo is 0.9.0 and 0.8.0 was never released. README said "install from git". Project URLs pointed at the old `mcp-jail` repo name. No author field; sdist lacked the changelog. | `pip index versions mcp-leash` (0.7.0); `tar tzf dist/*.tar.gz`; `unzip -p *.whl '*/METADATA'`. |
| Release engineer | The documented test command `python -m unittest discover -s tests` (README and CI) loads 370 tests and reports FAILED: three modules use relative imports. pytest runs 467. | `python3 -m unittest discover -s tests` before; with `-t .` after. CI was red for this reason. |
| Supply-chain reviewer | Zero runtime dependencies, so nothing to pin. No build-time secrets or personal paths in sdist/wheel (checked by listing both). Workflow actions are pinned by tag, not by commit hash. No trusted-publishing workflow exists. | `unzip -l`, `tar tzf`, `grep -r` over the built files. Not changed: see ideas 13, 14. |
| Hostile-input fuzzer | A 30,000-case random fuzz of `judge_call` found no crash. A 3 MB random-bytes stdin and a 200,000-deep JSON gave clean parse errors. Scanner timing over 70 adversarial strings, 300 KB each: worst 0.7 s, no catastrophic backtracking. | `fuzz.py`, `redos.py` (scratch scripts, not committed). |
| Performance engineer | A 16 MB argument made the scanner use 1.1 GB (about 70 bytes per character): the hex and percent regexes repeat a group, and Python keeps a mark per pass. Now 118 MB. Reading one long client line re-searched the whole buffer for each 64 KB chunk (quadratic). | `tracemalloc` on `scan_value`; peak RSS of a child run before/after. |
| Operator / SRE | With a read-only or full audit directory the call still goes through, with a warning on stderr. Some operators want the opposite. | Ran as an unprivileged user with a read-only `~/.mcp-leash`. Added `audit_required`. |
| Network-less user | `--url` to an unreachable host answered "upstream unreachable: OSError". | Run with `.invalid` host and a closed port. Fixed for refused, timeout, TLS, no such host (this sandbox routes through a proxy, so the DNS case still shows `OSError` here: **unverified** for a plain network). |
| Competitor's maintainer | mcpwall is still 0.3.1 on npm (last modified 2026-02-25). VellaVeto could not be re-read (the sandbox has no access to that repository). Comparison table left as it was, dated. | `npm view mcpwall version time.modified`. |
| Docs/DX | README install line, tests line and the file-encoding promise were wrong or silent. Fixed. | Re-read against actual output. |

## Windows static review (not run on Windows)

Read by eye and with source-scanning tests; **no Windows machine was
available.** Checked: no `shell=True` (test added); every text-mode `open()`
names its encoding (test added); POSIX-only signals are looked up with
`getattr` or guarded (test added); atomic policy write uses temp file plus
`os.replace`, whose failure on a locked file ends in a plain exit 2; log
rotation uses `os.rename` and reports failure on stderr; the append lock is a
separate `.lock` file with `msvcrt`; console output replaces unencodable
characters rather than raising; CRLF in JSON files is fine. Gap found and
fixed: UTF-8 BOM and UTF-16 files. Still unverified on Windows: everything
that needs a real console, `msvcrt.locking` under contention, `terminate()`
of an `npx.cmd` child tree, antivirus holding the log open during rotation.
CI now installs the wheel and runs `mcp-leash demo` on `windows-latest`; that
job has never run.

## Scored ideas (user value / differentiation / effort / risk, 1 to 5; effort and risk: low is good)

| # | Idea | Value | Diff. | Effort | Risk | Status |
|---|---|---|---|---|---|---|
| 1 | `mcp-leash demo`, a tour needing no server | 5 | 4 | 2 | 1 | DONE |
| 2 | Read UTF-8 BOM, explain UTF-16 | 4 | 1 | 1 | 1 | DONE |
| 3 | `audit_required` (fail closed when the log cannot be written) | 4 | 4 | 2 | 2 | DONE |
| 4 | Fix the documented test command (`-t .`) | 3 | 1 | 1 | 1 | DONE |
| 5 | Scanner memory 70x to 7x on long runs | 4 | 1 | 2 | 2 | DONE |
| 6 | Linear long-line reader | 2 | 1 | 1 | 1 | DONE |
| 7 | Plain-English upstream errors | 3 | 1 | 1 | 1 | DONE |
| 8 | Package metadata (author, URLs, classifiers, MANIFEST) | 3 | 1 | 1 | 1 | DONE |
| 9 | README: install line, limits on very large messages | 3 | 1 | 1 | 1 | DONE |
| 10 | Windows wheel job in CI | 3 | 1 | 1 | 1 | DONE (never run) |
| 11 | Static Windows-safety tests | 3 | 1 | 1 | 1 | DONE |
| 12 | Cap on one message's size (`limits.max_message_bytes`), refuse and resync | 5 | 3 | 4 | 3 | NOT-DONE (needs a design decision: what the client sees, how to resync after an oversized line) |
| 13 | Trusted-publishing release workflow (OIDC, no stored token) | 5 | 1 | 2 | 3 | NOT-DONE (changes how Dan publishes; his call) |
| 14 | Pin GitHub Actions by commit hash | 3 | 1 | 1 | 2 | NOT-DONE (needs network to look the hashes up) |
| 15 | `mcp-leash doctor` (environment self-check) | 3 | 2 | 2 | 1 | NOT-DONE |
| 16 | JSON Schema for policy files (editor autocomplete) | 4 | 3 | 3 | 2 | NOT-DONE (would drift from `POLICY_KEYS` without a generating test) |
| 17 | Print a ready client-config snippet (`wrap`) | 4 | 2 | 2 | 2 | NOT-DONE |
| 18 | Client-side SSE/GET stream for remote servers | 4 | 2 | 5 | 4 | NOT-DONE (earlier round) |
| 19 | Process isolation helper (container wrapper) | 4 | 5 | 5 | 4 | NOT-DONE (earlier round) |
| 20 | Signed audit checkpoints (Ed25519) | 3 | 4 | 5 | 3 | NOT-DONE (stdlib has no Ed25519) |
| 21 | Policy for server-started sampling/elicitation (not just scanning) | 4 | 4 | 4 | 3 | NOT-DONE (earlier round) |
| 22 | `--audit --follow` | 2 | 1 | 2 | 1 | NOT-DONE |
| 23 | `test` output as JUnit XML | 2 | 1 | 2 | 1 | NOT-DONE |
| 24 | Shell completion | 1 | 1 | 2 | 1 | NOT-DONE |
| 25 | Faster scanning (fewer passes per rule; today 1 to 3 MB/s) | 3 | 2 | 4 | 3 | NOT-DONE |

## Numbers

| | before round 4 | after |
|---|---|---|
| `pytest -q` | 467 passed, 3 skipped, 153 s | 491 passed, 3 skipped, 91 s (3.13) |
| `unittest discover -s tests` (old command) | 370 run, 3 import errors | `-t .`: 494 run, OK on 3.11; on 3.12 one timing test (`test_a_client_that_asks_nothing_is_a_clean_session...`) failed once while three suites ran at once, and passed alone 3 of 3 times: a load-sensitive test, not new |
| `bench_scan.py` | 800/800, 0/600 false positives | 800/800, 0/600 (unchanged) |
| scan speed | 1.2 to 1.5 MB/s (noisy, load ~10) | 1.0 to 1.6 MB/s (same within noise) |
| overhead, learned policy, p50 | 0.2 ms (README) | 0.22 ms added (one quiet run) |
| 16 MB argument, peak memory | 1.1 GB | 118 MB |

## What could not be tested

Windows (any part). Python 3.10 (the stated minimum; 3.11, 3.12, 3.13 were
run). macOS. A real MCP client (Claude Desktop, Cursor) in front of the proxy.
A real remote Streamable HTTP server this round (earlier rounds tested the
official SDK). Plain-network DNS failure text. The sandbox's package index was
reachable for read-only version lookups only; nothing was uploaded.
