# Changelog

## 0.8.0 (unreleased)

- **Tamper-evident audit log.** Every record now carries `seq`, `prev` and `hash`: a SHA-256 hash chain, so an edited, deleted, inserted or reordered record is detected. New `mcp-leash verify-audit [FILE] [--anchor HASH]` checks it (exit 0 intact, 1 broken, 2 no log) and prints the head to keep elsewhere. With `MCP_LEASH_AUDIT_KEY` set the chain is HMAC-SHA256 under that key; the key is removed from the wrapped server's environment. Processes sharing one log take a file lock per append (fcntl on POSIX, msvcrt on Windows), so the chain does not fork. Logs from older versions are carried on (their lines count as unchained). Each record also names the session and the policy file's hash (`session`, `policy`).
- **Tool pins (rug-pull detection).** New policy key `tool_pins` (tool name -> `sha256:` hash of the tool's definition). A pinned tool listed with a different description or schema is removed from `tools/list`, audited once, and its calls are denied for the rest of the session. `learn` now writes pins for the tools it allowlists; new `mcp-leash pin --policy FILE [--dry-run] -- <server>` adds or refreshes them, showing new and changed descriptions first, and replaces the file atomically.
- **`mcp-leash check`.** Loads a policy without a server, summarises it and warns about weak settings; with a tool name and arguments, prints the decision and reason (exit 0 allow, 1 deny, 2 unusable).
- `benchmarks/bench_overhead.py` measures the per-call overhead; README gives measured numbers (about 0.13 ms added at p50 on a 2-vCPU Linux VM).
- README: one-line value, quick start, demo output, comparison table with sources, honest limits (stdio only, no content scanning).
- Compatibility: existing policies load unchanged; `learn` output gains `tool_pins` only when it saw the tools listed. Audit records gain fields; `--audit` output is unchanged. `pin`, `check` and `verify-audit` are now subcommands, so a server command literally named one of them must come after `--` (as `learn` always did).

## 0.7.0

- Renamed the project to **mcp-leash** (PyPI rejected `mcp-jail` as too similar to the existing project `mcpjail`). The import package is now `mcp_leash`, the primary command is `mcp-leash`, and `python -m mcp_leash` replaces `python -m mcp_jail`.
- The old `mcp-jail` command is kept as a second console script, so existing MCP client configs keep working.
- Config location is now `~/.mcp-leash` (policy.json, audit.jsonl). If `~/.mcp-leash` does not exist and `~/.mcp-jail` does, the old directory is used, so nothing has to be moved.
- Source repository is unchanged (still named mcp-jail on GitHub).
- No behaviour change to the policy engine. It remains a policy filter, not a sandbox.

## 0.6.3

- README states plainly that it is a policy filter, not a sandbox; ruff config, project URLs and classifiers, metadata tests.
