# Publish checklist for mcp-leash 0.9.0 (in plain words)

Nothing here has been run for you. Do it from a normal terminal, in order.
The upload step is yours: this checklist never does it.

**Version to release: 0.9.0.** PyPI has 0.7.0. The versions 0.8.0 and 0.9.0
were never uploaded, so this release carries both; skip 0.8.0. It changes
behaviour from 0.7.0 (new subcommands, new audit-log format), which is fine
for a 0.x number but tell people in the release notes (they are in
CHANGELOG.md). Round 5 changed behaviour inside the unreleased 0.9.0 (a
wider `..` refusal, `learn` writing a size ceiling), so the version stays 0.9.0.

## Decide first
1. Is the GitHub repository `calasdan-sketch/mcp-leash` public? The package
   page on PyPI will link to it. If it is private, delete the four lines
   under `[project.urls]` in `pyproject.toml` and the
   `pip install git+https://github.com/...` lines in `README.md` first.
2. The author shown on PyPI is "Calas Automations Inc." (no email). That is
   what you asked for; it is what the built files say.

## Check first
1. You are on the branch you mean to release, and it is clean: `git status`.
2. Tests pass on your machine: `python -m pytest -q` (about 2 to 3 minutes).
3. The CI run on GitHub is green for Windows, macOS and Linux. It has never
   run the Windows wheel job, so look at that one first.
4. Version is 0.9.0 everywhere: `grep -n 0.9.0 pyproject.toml mcp_leash/__init__.py CHANGELOG.md`.
5. In CHANGELOG.md, change "0.9.0 (unreleased)" to "0.9.0" with today's date.

## Build and look (nothing is uploaded yet)
```
python -m pip install build twine
python -m build
python -m twine check --strict dist/*
unzip -p dist/*.whl '*/METADATA' | grep -E '^(Author|Maintainer|Version)'
```
The last line must show `Calas Automations Inc.` twice and `Version: 0.9.0`.
Then install the wheel in a new environment and try it:
```
python -m venv /tmp/try && /tmp/try/bin/pip install dist/*.whl
/tmp/try/bin/mcp-leash --version      # must say 0.9.0
/tmp/try/bin/mcp-leash demo           # must end with "hash chain intact"
/tmp/try/bin/mcp-leash schema | head -3
```
(On Windows the folder is `Scripts`, not `bin`.)

## Upload (this part cannot be undone: a version number can never be reused)
Try TestPyPI first if you have never done this:
`python -m twine upload --repository testpypi dist/*`
Then the real one: `python -m twine upload dist/*`
Better: set up PyPI "trusted publishing" for the GitHub repo and let a tag
trigger it, so no token sits on your computer (not set up yet; see
docs/ROUND5.md idea 14).

## After
`pip index versions mcp-leash` should list 0.9.0. Tag it: `git tag v0.9.0 && git push origin v0.9.0`.
Then make `pip install mcp-leash` the install line in any other README that
still says "install from a checkout".
