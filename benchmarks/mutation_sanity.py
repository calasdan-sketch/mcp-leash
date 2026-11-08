"""Mutation-style sanity check: break one key condition at a time in a COPY
of the package and confirm the test-suite notices.

    python benchmarks/mutation_sanity.py [--all-tests]

A mutant the tests do not catch is printed as SURVIVED and the exit status is
1. Nothing in the real tree is touched (the copy lives in a temporary folder).
By default a fast subset of the tests runs (about a minute per surviving
mutant); --all-tests runs everything.
"""

import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (file, text to find exactly once, replacement, what it breaks)
MUTANTS = [
    ("jail.py", "    if _denied_by_name(norm, deny):",
     "    if False and _denied_by_name(norm, deny):", "deny_tools ignored"),
    ("jail.py", 'if "*" not in allow and not _name_listed(norm, allow):',
     'if "*" not in allow and _name_listed(norm, allow):', "allowlist inverted"),
    ("jail.py", "                    and rule.pattern.search(text)):",
     "                    and not rule.pattern.search(text)):", "arg deny rule inverted"),
    ("jail.py", "            continue  # vetoed", "            return True, False",
     ".. traversal veto dropped"),
    ("jail.py", """        return False, f"tool '{name}': arguments rejected ({e})\"""",
     """        return True, \"\"""", "evaluation errors fail open"),
    ("jail.py", '    text = unicodedata.normalize("NFKC", name).casefold()',
     '    text = unicodedata.normalize("NFKC", name)', "names no longer case-folded"),
    ("jail.py", "if _has_traversal(text) and not rule.dotdot_ok:",
     "if _has_traversal(text) and rule.dotdot_ok:", "dotdot opt-in inverted"),
    ("jail.py", "        seen = urllib.parse.unquote(seen, errors=\"replace\")\n",
     "        seen = seen\n", "percent-encoded .. no longer decoded"),
    ("jail.py", "        if len(line) <= self._cap or line.endswith(b\"\\n\"):",
     "        if True:", "message ceiling ignored"),
    ("jail.py", "                       and tool_visible(pol, t.get(\"name\"))[0]]",
     "                       and True]", "hide_denied no longer hides"),
    ("jail.py", "            pins = _compile_pins(pol.get(\"tool_pins\"))\n        if norm not in pins:\n",
     "            pins = _compile_pins(pol.get(\"tool_pins\"))\n        if False:\n",
     "require_pins ignored"),
    ("scan.py", "        if flip:\n            d *= 2", "        if not flip:\n            d *= 2",
     "Luhn check broken"),
    ("ledger.py", "            if digest(body, alg, key) != h:",
     "            if False:", "audit hash never checked"),
]


def run_tests(tree, all_tests):
    targets = (["tests"] if all_tests else
               ["tests/test_round5_props.py", "tests/test_round5.py",
                "tests/test_round3.py", "tests/test_round4.py",
                "tests/test_metadata.py", "tests/test_expert2.py",
                "tests/test_jail.py", "-k", "not Signal and not Real"])
    cmd = [sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider"] + targets
    p = subprocess.run(cmd, cwd=tree, capture_output=True, text=True, timeout=1500)
    return p.returncode


def main():
    all_tests = "--all-tests" in sys.argv
    survived = 0
    for fname, old, new, what in MUTANTS:
        if what is None:
            continue
        with tempfile.TemporaryDirectory(prefix="mutant-") as tree:
            shutil.copytree(os.path.join(ROOT, "mcp_leash"), os.path.join(tree, "mcp_leash"),
                            ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copytree(os.path.join(ROOT, "tests"), os.path.join(tree, "tests"),
                            ignore=shutil.ignore_patterns("__pycache__"))
            for extra in ("README.md", "CHANGELOG.md", "LICENSE", "pyproject.toml",
                          "MANIFEST.in", "PUBLISH-CHECKLIST.md"):
                if os.path.exists(os.path.join(ROOT, extra)):
                    shutil.copy(os.path.join(ROOT, extra), tree)
            path = os.path.join(tree, "mcp_leash", fname)
            with open(path, encoding="utf-8") as f:
                text = f.read()
            if text.count(old) != 1:
                print(f"BROKEN MUTANT ({what}): pattern found {text.count(old)} times")
                survived += 1
                continue
            with open(path, "w", encoding="utf-8") as f:
                f.write(text.replace(old, new))
            rc = run_tests(tree, all_tests)
            print(f"{'killed  ' if rc != 0 else 'SURVIVED'}  {what}", flush=True)
            survived += rc == 0
    print(f"{survived} mutant(s) not caught")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
