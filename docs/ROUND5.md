# Round 5: policy, proxy and attacker views

Branch `expert-2`. Nothing was published, tagged or pushed. Author line set
to "Calas Automations Inc." everywhere (see the end of this file for proof).

**How this was done, honestly.** One agent played every specialist in turn;
no independent sub-agents ran, so these are perspectives, not independent
reviewers. Each finding names the command that showed it. Linux only,
Python 3.13 for the work. Windows, macOS and Python 3.10 were not run.

## Findings by specialist

| Specialist | Finding | Proof (command) |
|---|---|---|
| Upgrade tester (registry 0.7.0 to this tree) | A 0.7.0 `~/.mcp-leash` folder, its policy and its unchained audit log work unchanged: calls are judged, the log gets chained records after the old line, `verify-audit` says "1 older unchained line(s)", `rotate-audit` and `verify-audit --all` pass. No migration needed. | `pip download mcp-leash==0.7.0 --no-deps`, installed in a scratch venv, ran a session with it, then ran this tree on the same `HOME`. |
| Firewall / proxy engineer | **Defect:** no ceiling on one JSON-RPC line (ROUND4 idea 12). A 200 MB argument used 973 MB and 42 s; a hostile peer could use all memory. Fixed: `limits.max_message_bytes` (28 MB, 0.4 s with a 1 MiB ceiling; the next request on the same pipe still works). | `python rss.py` driver (scratch) with and without the ceiling; tests in `tests/test_round5.py` (client line, server line by head id and tail id, exactly-at-ceiling, endless line without newline, fd reader). |
| Firewall / proxy engineer | The queue between the reader threads and the judge is unbounded, so many maximum-size lines sent faster than they are judged still grow memory. Not fixed (needs back-pressure); stated in the README. | Read `_Proxy.serve`. |
| Red-teamer | **Defect:** an allow rule such as `^/data/` admitted `/data/%2e%2e/x`, `/data/..%2fx` and `/data/%252e%252e/x` (a server that decodes URLs or `file://` paths reads the parent), and full-width dots `/data/．．/x`. Windows trims trailing dots and spaces, so `C:\data\.. ` is `..`. All refused now unless the pattern spells out `\.\.`. | `judge_call` over 60,000 random strings built from `%`, `2e`, `..`, spaces, full-width dots (invariant: anything that decodes to a `..` segment is refused): 0 missed after the fix. Timing of the new check on 600 KB hostile strings: 0.3 s at worst. |
| Policy-engine designer | The decision logic obeys its laws for 40 seeded random cases each: deny wins over allow; a name outside the allowlist is denied; names are equal under case, invisible characters and full-width forms; key order never changes a decision; adding `strict_args` or a deny rule can only remove permissions; no input makes the judge raise; re-encoding a message is a fixed point and ASCII; a forged internal marker in a policy file is refused. No violations found. | `tests/test_round5_props.py` (seeded; hypothesis is not installed and is not a dependency). |
| Test-methodology reviewer | Mutation check: 13 one-line breaks of key conditions (deny ignored, allowlist inverted, argument deny inverted, traversal veto dropped, evaluation errors failing open, no case folding, dotdot opt-in inverted, percent decoding removed, ceiling ignored, hide_denied ignored, require_pins ignored, Luhn broken, audit hash never checked): all killed. The script found one of its own mutants stale after a refactor ("BROKEN MUTANT") and refuses to count that as a pass. Output formats had no stored copy: `tests/golden/` now holds 10 outputs (check summary and decision, test, junit, audit text/json/summary/filter, demo, schema). | `python benchmarks/mutation_sanity.py` (about 3 minutes); `python -m pytest tests/test_round5.py`. |
| Claude Code / Desktop user | Wiring mcp-leash in meant hand-editing JSON with an absolute policy path. `wrap` prints the entry (or the `claude mcp add` line). `check --json` gives a hook or script one line to parse. | `mcp-leash wrap NAME -- npx -y srv`; the printed entry is run by a test. |
| CI engineer | `test` could not feed a CI dashboard. `--junit FILE` writes JUnit XML (well-formed with control and bidi characters in case names; the golden test parses it). | `mcp-leash test --policy p cases --junit r.xml`. |
| Editor / DX | No schema for the policy file. `mcp-leash schema` prints one, generated from the loader's own key list and the scanner's detectors; a test fails if they drift, and validates what `learn`, the default policy and hand-written policies produce (when `jsonschema` is installed). | `tests/test_round5.py::TestSchema`. |
| Locale / paths / concurrency | `LC_ALL=C` with ASCII-only stdout: non-ASCII names print as `?`, no crash. A policy path and `HOME` with spaces work. Six concurrent sessions (18 runs) wrote one log: `verify-audit` reports 36 chained records, intact. | Shell runs, scratch folder. |
| Type check | `mypy` (not a project dependency) reports 30 errors, all false positives from untyped code and `None`-able pipes; none from this round's code. Not added to CI. | `mypy --ignore-missing-imports mcp_leash` in a scratch venv. |
| Competitor's maintainer | mcpwall is still 0.3.1 on npm (modified 2026-02-25). VellaVeto is on neither npm nor PyPI under that name and its GitHub README was not re-read (no way to reach it): comparison table left as dated, README says so. | `npm view mcpwall version time.modified`; `pip index versions vellaveto`; `npm view vellaveto`. |

## Windows static review (not run on Windows)

New code read for Windows: `_FdLineReader.readline(limit)` is used only for
real file descriptors and does the same work on every OS; no new `open()`
without an encoding; `wrap --format claude-code` quotes with
`subprocess.list2cmdline` on Windows (unverified in a real `cmd.exe`);
`_write_atomic` writes the JUnit file. The trailing-dot-and-space rule for
`..` is from Microsoft's path-normalisation documentation as remembered, not
tested on Windows.

## Scored ideas (user value / differentiation / effort / risk, 1 to 5; effort and risk: low is good)

| # | Idea | Value | Diff. | Effort | Risk | Status |
|---|---|---|---|---|---|---|
| 1 | Ceiling on one message (`limits.max_message_bytes`) (ROUND4 #12) | 5 | 3 | 3 | 2 | DONE |
| 2 | Refuse `%2e%2e`, full-width and Windows-trimmed `..` behind allow rules | 5 | 3 | 2 | 2 | DONE |
| 3 | `wrap`: print the client-config entry (ROUND4 #17) | 4 | 2 | 2 | 1 | DONE |
| 4 | JSON Schema of the policy file, drift-tested (ROUND4 #16) | 4 | 3 | 3 | 1 | DONE |
| 5 | `test --junit` (ROUND4 #23) | 2 | 1 | 2 | 1 | DONE |
| 6 | `check --json` for scripts and hooks | 3 | 2 | 1 | 1 | DONE |
| 7 | Seeded property tests of the policy engine | 4 | 1 | 2 | 1 | DONE |
| 8 | Mutation-style sanity script | 3 | 1 | 2 | 1 | DONE |
| 9 | Golden files for every output format | 3 | 1 | 2 | 1 | DONE |
| 10 | `learn` writes a 16 MiB ceiling | 3 | 1 | 1 | 1 | DONE |
| 11 | `check` warns when no ceiling is set | 2 | 1 | 1 | 1 | DONE |
| 12 | Author line "Calas Automations Inc." everywhere, pinned by tests | 3 | 1 | 1 | 1 | DONE |
| 13 | Back-pressure: bound the bytes waiting between reader threads and the judge | 4 | 3 | 3 | 3 | NOT-DONE (a blocked reader changes timing on both pipes; needs its own round and Windows testing) |
| 14 | Trusted-publishing release workflow (ROUND4 #13) | 5 | 1 | 2 | 3 | NOT-DONE (changes how Dan publishes) |
| 15 | Pin GitHub Actions by commit hash (ROUND4 #14) | 3 | 1 | 1 | 2 | NOT-DONE (needs network lookups) |
| 16 | `mcp-leash doctor` (ROUND4 #15) | 3 | 2 | 2 | 1 | NOT-DONE |
| 17 | Client-side SSE/GET stream for remote servers (ROUND4 #18) | 4 | 2 | 5 | 4 | NOT-DONE |
| 18 | Process isolation helper / container wrapper (ROUND4 #19) | 4 | 5 | 5 | 4 | NOT-DONE |
| 19 | Signed audit checkpoints (ROUND4 #20) | 3 | 4 | 5 | 3 | NOT-DONE (stdlib has no Ed25519) |
| 20 | Policy (not just scanning) for server-started sampling and elicitation (ROUND4 #21) | 4 | 4 | 4 | 3 | NOT-DONE |
| 21 | `--audit --follow` (ROUND4 #22) | 2 | 1 | 2 | 1 | NOT-DONE |
| 22 | Faster scanning (ROUND4 #25) | 3 | 2 | 4 | 3 | NOT-DONE |
| 23 | SARIF output for `check` and `pin` findings | 2 | 2 | 3 | 1 | NOT-DONE (no consumer asked for it) |
| 24 | Explain mode: which rule decided, with the rule's path in the reason | 3 | 3 | 3 | 2 | NOT-DONE |
| 25 | Policy include/extends (a shared base policy per team) | 3 | 2 | 4 | 3 | NOT-DONE (precedence rules would need designing) |
| 26 | Shell completion (ROUND4 #24) | 1 | 1 | 2 | 1 | NOT-DONE |

## Numbers

| | before round 5 | after |
|---|---|---|
| `pytest -q` | 495 passed, 169 s (measured after the author-line edits, before anything else) | 535 passed, 124 s (3.13; quiet machine) |
| `bench_scan.py` | 800/800, 0/600 false positives | 800/800, 0/600 (unchanged) |
| overhead, learned policy, p50 added | 308 us | 241 us (noisy; same code path, treat as equal) |
| 200 MB single line, peak memory / time | 973 MB / 42 s | 28 MB / 0.4 s (with `max_message_bytes` 1 MiB) |
| mutants caught | n/a | 13 of 13 |

## What could not be tested

Windows (any part, including `wrap --format claude-code` quoting and the
trailing-dot-and-space rule). Python 3.10 (the stated minimum), macOS. A real
MCP client in front of the proxy. A real remote Streamable HTTP server this
round (the message ceiling was exercised with local fake servers and the
existing HTTP tests still pass). Plain-network DNS failure text. VellaVeto's
current README. `hypothesis` (not installed; the generator is seeded instead).
Memory growth from many queued maximum-size lines (idea 13).

## Author-line proof

`unzip -p dist/mcp_leash-0.9.0-py3-none-any.whl '*/METADATA'` prints
`Author: Calas Automations Inc.` and `Maintainer: Calas Automations Inc.`;
the licence file inside the wheel reads `Copyright (c) 2026 Calas Automations
Inc.`; the sdist's PKG-INFO carries the same; `twine check --strict` passes
for both. No email address was added (none existed for this project). The
repository URLs in the package metadata and README are unchanged. Whether
`calasdan-sketch/mcp-leash` is public could not be checked from this
session (GitHub access was refused). If it is private, remove the four
`[project.urls]` lines in `pyproject.toml` and the `pip install git+https://...`
lines in `README.md` before uploading, because PyPI would show links that
lead nowhere for other people.
