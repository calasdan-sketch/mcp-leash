# Changelog

## 0.7.0

- Renamed the project to **mcp-leash** (PyPI rejected `mcp-jail` as too similar to the existing project `mcpjail`). The import package is now `mcp_leash`, the primary command is `mcp-leash`, and `python -m mcp_leash` replaces `python -m mcp_jail`.
- The old `mcp-jail` command is kept as a second console script, so existing MCP client configs keep working.
- Config location is now `~/.mcp-leash` (policy.json, audit.jsonl). If `~/.mcp-leash` does not exist and `~/.mcp-jail` does, the old directory is used, so nothing has to be moved.
- Source repository is unchanged (still named mcp-jail on GitHub).
- No behaviour change to the policy engine. It remains a policy filter, not a sandbox.

## 0.6.3

- README states plainly that it is a policy filter, not a sandbox; ruff config, project URLs and classifiers, metadata tests.
