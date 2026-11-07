# Changelog

## 0.9.0 (unreleased)

- **Content scanning** (`scan` policy block, `mcp_leash/scan.py`): secrets, card/SIN/SSN/IBAN numbers, injected-instruction phrases and hidden characters, in call arguments (`deny`/`flag`), server answers (`redact`/`deny`/`flag`) and tool descriptions (`hide`/`flag`). Invisible characters and full-width forms do not hide a value. Findings carry the rule and location, never the text. `benchmarks/bench_scan.py` measures recall, false positives and speed, and can run another proxy through the same corpus.
- **Remote servers**: `--url` (also `learn`, `pin`) speaks Streamable HTTP to the server; tested against the official Python SDK's server. `--header-env`, TLS always verified, no redirects, http only for localhost.
- **`--monitor`**: dry run on live traffic (`would_deny`, `would_redact` records).
- **`limits`**: per-session call ceilings, per-minute rate, per-tool limits, `max_result_bytes`.
- **`mcp-leash test`**: expected-decision files for policies (CI). `check` applies `scan.arguments`.
- **Audit**: secrets and card numbers are redacted from logged arguments and rejected lines (`audit_redact`, default on: records change for such values); rotation (`audit_max_bytes`, `rotate-audit`, `verify-audit --all`) keeps one chain across files. Breaking: the append lock is now `audit.jsonl.lock` beside the log on POSIX too; `test` and `rotate-audit` are subcommands (put `--` before a server command with that name).

## 0.8.0 (unreleased)

- **Tamper-evident audit log.** Every record now carries `seq`, `prev` and `hash`: a SHA-256 hash chain, so an edited, deleted, inserted or reordered record is detected. New `mcp-leash verify-audit [FILE] [--anchor HASH]` checks it (exit 0 intact, 1 broken, 2 no log) and prints the head to keep elsewhere. With `MCP_LEASH_AUDIT_KEY` set the chain is HMAC-SHA256 under that key; the key is removed from the wrapped server's environment. Processes sharing one log take a file lock per append (fcntl on POSIX, msvcrt on Windows), so the chain does not fork. Logs from older versions are carried on (their lines count as unchained). Each record also names the session and the policy file's hash (`session`, `policy`).
- **Tool pins (rug-pull detection).** New policy key `tool_pins` (tool name -> `sha256:` hash of the tool's definition). A pinned tool listed with a different description or schema is removed from `tools/list`, audited once, and its calls are denied for the rest of the session. `learn` now writes pins for the tools it allowlists; new `mcp-leash pin --policy FILE [--dry-run] -- <server>` adds or refreshes them, showing new and changed descriptions first, and replaces the file atomically.
- **`mcp-leash check`.** Loads a policy without a server, summarises it and warns about weak settings; with a tool name and arguments, prints the decision and reason (exit 0 allow, 1 deny, 2 unusable).
- `benchmarks/bench_overhead.py` measures the per-call overhead; README gives measured numbers (about 0.13 ms added at p50 on a 2-vCPU Linux VM).
- README: one-line value, quick start, demo output, comparison table with sources, honest limits (stdio only, no content scanning).
- Panel review fixes (before release):
  - Keyed logs: `verify-audit` with a key requires every record to be hmac-sha256 under that key, refuses unchained lines and an empty log, and names a record written with a different key; mcp-leash warns on stderr when appending to a log last written with another key or none.
  - New `MCP_LEASH_AUDIT_KEY_FILE` (a 0600 file, read and never put in an environment) is the documented way to key the log; `MCP_LEASH_AUDIT_KEY` still works but is readable via `/proc/<pid>/environ`. A key file that others can read, empty or missing stops start-up (exit 2). Both variables are stripped from the server's environment. README states that a server running as the same user is not contained.
  - Windows: the append lock is taken on a separate `audit.jsonl.lock`, so readers of the log are never blocked. A lock that cannot be had is an error: records are never written unlocked, and a record that cannot be written is reported on stderr as `AUDIT RECORD NOT WRITTEN`.
  - An interrupted write no longer breaks the chain for good: the next append ends the incomplete line and writes a `recovered` record naming it, which `verify-audit` counts as recovered.
  - Pinned tools are callable only after a `tools/list` in the session showed their pinned definition, and not while a `tools/list` is unanswered. New `require_pins: true` denies every tool without a pin. Names that look like a pinned tool (Cyrillic/Greek look-alikes, `0`/`1`, `-`/`_`, accents) are hidden and denied; `check` warns about look-alike names.
  - `pin` keeps the old pin of a changed tool (exit 1) unless `--accept-changed` is given.
  - `check` judges calls with the proxy's own code: `completion/complete` by its `ref`, and `--params JSON` for the whole params object.
- **Breaking:** `pin`, `check` and `verify-audit` are now subcommands. A server command named one of them, given first (`mcp-leash check ...`), is read as the subcommand: put `--` before it (`mcp-leash --policy p.json -- check`), as client configs already do. Policies that `learn` writes now carry `tool_pins`, so a client must list tools before calling a pinned one (MCP clients do).
- Compatibility otherwise: existing policies load unchanged. Audit records gain fields; `--audit` output is unchanged except for `note` lines for recovered writes.

## 0.7.0

- Renamed the project to **mcp-leash** (PyPI rejected `mcp-jail` as too similar to the existing project `mcpjail`). The import package is now `mcp_leash`, the primary command is `mcp-leash`, and `python -m mcp_leash` replaces `python -m mcp_jail`.
- The old `mcp-jail` command is kept as a second console script, so existing MCP client configs keep working.
- Config location is now `~/.mcp-leash` (policy.json, audit.jsonl). If `~/.mcp-leash` does not exist and `~/.mcp-jail` does, the old directory is used, so nothing has to be moved.
- Source repository is unchanged (still named mcp-jail on GitHub).
- No behaviour change to the policy engine. It remains a policy filter, not a sandbox.

## 0.6.3

- README states plainly that it is a policy filter, not a sandbox; ruff config, project URLs and classifiers, metadata tests.
