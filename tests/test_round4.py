"""Round 4 tests: what a stranger who installs the package meets first
(Windows-written files, an unwritable audit log, readable network errors) and
static checks that keep Windows-hostile code out of the source.
"""

import ast
import io
import json
import os
import pathlib
import re
import socket
import ssl
import unittest
from contextlib import redirect_stderr, redirect_stdout

from mcp_leash import cli
from mcp_leash import httpup
from mcp_leash import jail as jail_mod
from mcp_leash import scan as scan_mod

from . import test_jail as tj
from .test_expert2 import (ProxyCase, fake_github, setUpModule as _set,
                           tearDownModule as _tear)

ROOT = pathlib.Path(__file__).resolve().parent.parent
PKG = ROOT / "mcp_leash"


def setUpModule():
    _set()


def tearDownModule():
    _tear()


class TestWindowsWrittenFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tj.mktemp()
        self.body = json.dumps({"allow_tools": ["a"]}, indent=2)

    def write(self, name, data: bytes) -> str:
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def test_policy_with_utf8_bom_and_crlf_loads(self):
        data = b"\xef\xbb\xbf" + self.body.replace("\n", "\r\n").encode("utf-8")
        pol = jail_mod.load_policy(self.write("bom.json", data))
        self.assertEqual(pol["allow_tools"], ["a"])

    def test_utf16_policy_is_refused_in_plain_words(self):
        path = self.write("u16.json", self.body.encode("utf-16"))
        with self.assertRaises(ValueError) as cm:
            jail_mod.load_policy(path)
        self.assertIn("UTF-16", str(cm.exception))
        self.assertIn("UTF-8", str(cm.exception))

    def test_utf16_without_bom_is_also_caught(self):
        path = self.write("u16le.json", self.body.encode("utf-16-le"))
        with self.assertRaises(ValueError) as cm:
            jail_mod.load_policy(path)
        self.assertIn("UTF-16", str(cm.exception))

    def test_latin1_policy_is_a_plain_error(self):
        path = self.write("l1.json", b'{"_comment": "caf\xe9"}')
        with self.assertRaises(ValueError) as cm:
            jail_mod.load_policy(path)
        self.assertIn("not valid UTF-8", str(cm.exception))

    def test_script_with_bom_loads(self):
        data = b"\xef\xbb\xbf" + json.dumps([{"tool": "t"}]).encode("utf-8")
        calls = jail_mod.load_script(self.write("calls.json", data))
        self.assertEqual(calls[0]["tool"], "t")

    def test_check_reports_a_utf16_policy_with_exit_2(self):
        path = self.write("u16.json", self.body.encode("utf-16"))
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(["check", "--policy", path])
        err = err.getvalue()
        self.assertEqual(code, 2)
        self.assertIn("UTF-16", err)
        self.assertNotIn("Traceback", err)


class TestAuditRequired(ProxyCase):
    def break_audit(self):
        """An audit path whose parent is a file: makedirs/open must fail."""
        blocker = os.path.join(self.tmp, "blocker")
        with open(blocker, "w", encoding="utf-8") as f:
            f.write("x")
        jail_mod.AUDIT_LOG = os.path.join(blocker, "audit.jsonl")

    def test_default_allows_the_call_when_the_log_is_unwritable(self):
        self.break_audit()
        code, out = self.session({}, [tj.call(1, "echo", {"say": "hi"})])
        self.assertIn("result", out[0])

    def test_audit_required_denies_instead(self):
        self.break_audit()
        code, out = self.session({"audit_required": True},
                                 [tj.call(1, "echo", {"say": "hi"})])
        self.assertIn("error", out[0])
        self.assertIn("audit_required", out[0]["error"]["message"])

    def test_audit_required_changes_nothing_when_the_log_works(self):
        code, out = self.session({"audit_required": True},
                                 [tj.call(1, "echo", {"say": "hi"})])
        self.assertIn("result", out[0])
        self.assertEqual(self.audit()[0]["decision"], "allow")

    def test_audit_required_must_be_a_boolean(self):
        with self.assertRaises(ValueError):
            jail_mod.compile_policy({"audit_required": "yes"})


class TestUpstreamReasons(unittest.TestCase):
    def test_reasons_are_readable_and_carry_no_exception_text(self):
        self.assertIn("host name", httpup._why(socket.gaierror(-2, "secret.example")))
        self.assertIn("refused", httpup._why(ConnectionRefusedError("http://u:p@h")))
        self.assertIn("timed out", httpup._why(TimeoutError("x")))
        self.assertIn("TLS", httpup._why(ssl.SSLError("bad cert for h")))
        for e in (socket.gaierror(-2, "secret.example"), ssl.SSLError("tok123")):
            self.assertNotIn("secret.example", httpup._why(e))
            self.assertNotIn("tok123", httpup._why(e))
        self.assertEqual(httpup._why(KeyError("k")), "KeyError")


class TestScanDecodeRuns(unittest.TestCase):
    def test_hex_encoded_token_is_found_and_odd_length_runs_are_not_decoded(self):
        tok = fake_github()
        hexed = tok.encode().hex()
        self.assertEqual(found_with_decode({"a": "x " + hexed + " y"}), ["hex:github_token"])
        self.assertEqual(found_with_decode({"a": "x " + hexed + "a y"}), [])

    def test_percent_encoded_token_is_found_with_the_right_offsets(self):
        tok = fake_github()
        enc = "".join("%%%02x" % b for b in tok.encode())
        self.assertEqual(found_with_decode({"a": "k=" + enc + "&z"}), ["percent:github_token"])

    def test_a_long_run_does_not_cost_memory_in_proportion_to_ten_times_its_size(self):
        import tracemalloc
        text = "A" * 1_000_000
        tracemalloc.start()
        try:
            found_with_decode({"a": text})
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        # before round 4 this was about 70 bytes per character
        self.assertLess(peak, 25 * len(text))


def found_with_decode(value):
    rep = scan_mod.Report()
    scan_mod.scan_value(value, scan_mod.KINDS, rep, decode=True, skip_binary=False)
    return sorted({r for _k, r, _p in rep.items})


class TestDemo(unittest.TestCase):
    def test_the_demo_runs_and_shows_each_outcome(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main(["demo"])
        text = out.getvalue()
        self.assertEqual(code, 0, text)
        self.assertIn("allowed", text)
        self.assertEqual(text.count("BLOCKED"), 4, text)
        self.assertIn("github_token", text)
        self.assertIn("read_file is gone", text)
        self.assertIn("hash chain intact", text)
        self.assertNotIn("Traceback", text)

    def test_the_demo_leaves_the_users_own_folder_alone(self):
        before = os.path.exists(os.path.join(os.path.expanduser("~"), ".mcp-leash"))
        with redirect_stdout(io.StringIO()):
            cli.main(["demo"])
        self.assertEqual(
            os.path.exists(os.path.join(os.path.expanduser("~"), ".mcp-leash")), before)

    def test_the_demo_takes_no_arguments(self):
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(cli.main(["demo", "--bogus"]), 2)


class TestSourceIsWindowsSafe(unittest.TestCase):
    """Static: these were reviewed by reading, not by running on Windows."""

    def sources(self):
        for p in sorted(PKG.glob("*.py")):
            yield p, p.read_text(encoding="utf-8")

    def test_no_shell_true(self):
        for p, text in self.sources():
            self.assertNotRegex(text, r"shell\s*=\s*True", p.name)

    def test_every_text_mode_open_names_its_encoding(self):
        for p, text in self.sources():
            for node in ast.walk(ast.parse(text)):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id == "open"):
                    mode = ""
                    if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                        mode = node.args[1].value
                    for kw in node.keywords:
                        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                            mode = kw.value.value
                    if "b" in str(mode):
                        continue
                    names = {kw.arg for kw in node.keywords}
                    self.assertIn("encoding", names, f"{p.name}:{node.lineno}")

    def test_signals_not_on_windows_are_looked_up_safely(self):
        for p, text in self.sources():
            for m in re.finditer(r"signal\.(SIGHUP|SIGKILL|SIGUSR1|SIGUSR2|SIGALRM)\b", text):
                line = text[:m.start()].count("\n")
                window = "\n".join(text.splitlines()[max(0, line - 6):line + 1])
                self.assertRegex(window, r"getattr|hasattr|_WINDOWS|os\.name|platform",
                                 f"{p.name}:{line + 1}")


class TestPackagingMetadata(unittest.TestCase):
    def setUp(self):
        self.pp = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    def test_urls_point_at_this_repo_under_its_current_name(self):
        for line in re.findall(r"https://github\.com/[^\s\"]+", self.pp):
            self.assertIn("calasdan-sketch/mcp-leash", line)

    def test_author_and_changelog_are_named(self):
        self.assertIn('authors = [{name = "Dan Calas"}]', self.pp)
        self.assertTrue((ROOT / "CHANGELOG.md").exists())

    def test_changelog_has_the_current_version(self):
        log = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        import mcp_leash
        self.assertIn(f"## {mcp_leash.VERSION}", log)

    def test_manifest_ships_the_changelog_in_the_sdist(self):
        self.assertIn("CHANGELOG.md", (ROOT / "MANIFEST.in").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
