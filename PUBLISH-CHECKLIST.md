# Publish checklist for mcp-leash 0.9.0 (in plain words)

Nothing here has been run for you. Do it from a normal terminal, in order.

**Version to release: 0.9.0.** PyPI has 0.7.0. The versions 0.8.0 and 0.9.0
were never uploaded, so this release carries both; skip 0.8.0. It changes
behaviour from 0.7.0 (new subcommands, new audit-log format), which is fine
for a 0.x number but tell people in the release notes (they are in CHANGELOG.md).

## Check first
1. You are on the branch you mean to release, and it is clean: `git status`.
2. Tests pass on your machine: `python -m pytest -q` (about 2 to 3 minutes).
3. The CI run on GitHub is green for Windows, macOS and Linux. It has never run
   the new Windows wheel job, so look at that one first.
4. Version is 0.9.0 everywhere: `grep -n 0.9.0 pyproject.toml mcp_leash/__init__.py CHANGELOG.md`.
5. In CHANGELOG.md, change "0.9.0 (unreleased)" to "0.9.0" with today's date.

## Build and look (nothing is uploaded yet)
```
python -m pip install build twine
python -m build
python -m twine check --strict dist/*
```
Then install the wheel in a new environment and try it:
```
python -m venv /tmp/try && /tmp/try/bin/pip install dist/*.whl
/tmp/try/bin/mcp-leash --version      # must say 0.9.0
/tmp/try/bin/mcp-leash demo           # must end with "hash chain intact"
```
(On Windows the folder is `Scripts`, not `bin`.)

## Upload (this part cannot be undone: a version number can never be reused)
Try TestPyPI first if you have never done this:
`python -m twine upload --repository testpypi dist/*`
Then the real one: `python -m twine upload dist/*`
Better: set up PyPI "trusted publishing" for the GitHub repo and let a tag
trigger it, so no token sits on your computer (not set up yet; see
docs/ROUND4.md idea 13).

## After
`pip index versions mcp-leash` should list 0.9.0. Tag it: `git tag v0.9.0 && git push origin v0.9.0`.
Then make `pip install mcp-leash` the install line in any other README that
still says "install from a checkout".
