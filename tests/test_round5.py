"""Round 5 tests: the message-size ceiling, the author line, and the
properties and golden outputs added this round."""

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from contextlib import redirect_stderr, redirect_stdout

from mcp_leash import cli
from mcp_leash import jail as jail_mod

from . import test_jail as tj
from .test_expert2 import (ProxyCase, setUpModule as _set,
                           tearDownModule as _tear)


def setUpModule():
    _set()


def tearDownModule():
    _tear()


SERVER_BIG = r"""
import json, sys
for line in sys.stdin:
    req = json.loads(line)
    rid = req.get("id")
    if rid is None:
        continue
    if req["method"] == "tools/call":
        n = req["params"]["arguments"]["n"]
        if req["params"]["name"] == "tail":
            out = '{"jsonrpc":"2.0","result":{"content":[{"type":"text","text":"' + "x" * n + '"}]},"id":%d}' % rid
        else:
            out = json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"content": [
                {"type": "text", "text": "x" * n}]}})
    else:
        out = json.dumps({"jsonrpc": "2.0", "id": rid, "result": {}})
    sys.stdout.write(out + "\n")
    sys.stdout.flush()
"""

CAP = {"limits": {"max_message_bytes": 8192}}


class TestMessageCeiling(ProxyCase):
    def test_a_huge_client_line_is_refused_under_its_id_and_the_session_goes_on(self):
        code, out = self.session(
            CAP, [tj.call(1, "echo", {"say": "x" * 20000}),
                  tj.call(2, "echo", {"say": "ok"})])
        self.assertEqual(code, 0)
        self.assertEqual(out[0]["id"], 1)
        self.assertEqual(out[0]["error"]["code"], -32600)
        self.assertIn("message too large", out[0]["error"]["message"])
        self.assertIn("result", out[1])
        rec = [r for r in self.audit() if r.get("rejected") == "client"]
        self.assertEqual(len(rec), 1)
        self.assertIn("message too large", rec[0]["reason"])

    def test_the_oversize_line_never_reaches_the_server(self):
        code, out = self.session(
            CAP, [tj.call(1, "echo", {"say": "NEEDLE" + "x" * 20000})])
        self.assertNotIn("NEEDLE", json.dumps(out))
        self.assertEqual([r for r in self.audit() if r.get("decision") == "allow"], [])

    def test_a_line_exactly_at_the_ceiling_is_accepted(self):
        base = len(json.dumps(tj.call(1, "echo", {"say": ""})))
        pad = 8192 - base
        code, out = self.session(CAP, [tj.call(1, "echo", {"say": "y" * pad})])
        self.assertIn("result", out[0])
        code, out = self.session(CAP, [tj.call(1, "echo", {"say": "y" * (pad + 2)})])
        self.assertIn("error", out[0])

    def test_without_a_ceiling_nothing_changes(self):
        code, out = self.session({}, [tj.call(1, "echo", {"say": "x" * 20000})])
        self.assertIn("result", out[0])

    def test_a_huge_server_answer_fails_the_request_by_id(self):
        src = SERVER_BIG
        srv = tj.write_server(self.tmp, src, "big.py")
        path = tj.write_policy(self.tmp, dict(tj.ALLOW_ALL, **{
            "limits": {"max_message_bytes": 4096}}))
        code, raw = tj.drive_rc(path, [sys.executable, srv], [
            tj.call(1, "big", {"n": 50000}), tj.call(2, "big", {"n": 10}),
            tj.call(3, "tail", {"n": 50000})])
        out = {m["id"]: m for m in map(json.loads, raw)}
        self.assertEqual(out[1]["error"]["code"], -32603)
        self.assertIn("message too large", out[1]["error"]["message"])
        self.assertIn("result", out[2])
        self.assertEqual(out[3]["error"]["code"], -32603)   # id read from the tail
        rec = [r for r in self.audit() if r.get("rejected") == "server"]
        self.assertEqual(len(rec), 2)

    def test_ceiling_is_validated(self):
        for bad in (0, 100, True, "9", 4095, 1.5):
            with self.assertRaises(ValueError, msg=repr(bad)):
                jail_mod.compile_policy({"limits": {"max_message_bytes": bad}})
        jail_mod.compile_policy({"limits": {"max_message_bytes": 4096}})

    def test_check_warns_when_there_is_no_ceiling(self):
        warn = jail_mod.policy_warnings(jail_mod.compile_policy({}))
        self.assertTrue(any("max_message_bytes" in w for w in warn))
        pol = jail_mod.compile_policy({"limits": {"max_message_bytes": 1 << 20}})
        self.assertFalse(any("max_message_bytes" in w
                             for w in jail_mod.policy_warnings(pol)))


class TestTraversalVeto(unittest.TestCase):
    """An allow rule on a path must not be a door to `..` however it is written."""

    def pol(self):
        return jail_mod.compile_policy({"allow_tools": ["r"], "arg_rules": {"r": {
            "allow": {"path": r"^(C:\\data\\|/data/)"}}}})

    def ok(self, value):
        return jail_mod.judge_call(self.pol(), "tools/call",
                                   {"name": "r", "arguments": {"path": value}})[2]

    def test_encoded_and_trimmed_forms_are_refused(self):
        for v in ("/data/%2e%2e/x", "/data/%2E%2E%2fx", "/data/..%2fx", "/data/%252e%252e/x",
                  "/data/%25252e%25252e/x", "/data/%2e%2e", "/data/\uff0e\uff0e/x",
                  "C:\\data\\..", "C:\\data\\.. ", "C:\\data\\.. .", "/data/.. ",
                  "C:\\data\\%2e%2e%5cx"):
            self.assertFalse(self.ok(v), v)

    def test_ordinary_values_are_still_allowed(self):
        for v in ("/data/a.txt", "/data/a..b", "/data/...x", "/data/100%25 done",
                  "/data/v1.2/notes", "C:\\data\\a b.txt", "/data/%zz", "/data/caf\u00e9"):
            self.assertTrue(self.ok(v), v)

    def test_a_pattern_that_spells_out_dotdot_still_opts_in(self):
        pol = jail_mod.compile_policy({"allow_tools": ["r"], "arg_rules": {"r": {
            "allow": {"path": r"^/data/\.\./ok$"}}}})
        self.assertTrue(jail_mod.judge_call(pol, "tools/call", {
            "name": "r", "arguments": {"path": "/data/../ok"}})[2])


class TestHeadId(unittest.TestCase):
    def test_only_a_top_level_leading_id_is_trusted(self):
        h = jail_mod._head_id
        self.assertEqual(h(b'{"jsonrpc":"2.0","id":7,"method":"x"'), 7)
        self.assertEqual(h(b'{ "id" : "abc" , "x"'), "abc")
        self.assertIs(h(b'{"jsonrpc":"2.0","method":"x","params":{"id":9}'), jail_mod._NO_ID)
        self.assertIs(h(b'{"jsonrpc":"2.0","id":1.5,'), jail_mod._NO_ID)
        self.assertIs(h(b'[{"id":1,'), jail_mod._NO_ID)
        self.assertIs(h(b''), jail_mod._NO_ID)
        self.assertEqual(h(b'{"method":"x","params":{}', b'..."params":{},"id":42}'), 42)
        self.assertIs(h(b'{"method":"x"', b'"params":{"a":1,"id":9}}'), jail_mod._NO_ID)
        self.assertIs(h(b'{"method":"x"', b'"say":"a,\\"id\\":9}"}'), jail_mod._NO_ID)


class TestReaderCap(unittest.TestCase):
    def pump(self, data, cap, reader=None):
        import io
        import queue
        q = queue.SimpleQueue()
        stream = reader or io.BytesIO(data)
        r = jail_mod._Reader(stream, "t", q, cap)
        r.run()
        out = []
        while not q.empty():
            out.append(q.get())
        return out

    def test_lines_around_the_ceiling(self):
        data = b"a" * 10 + b"\n" + b"b" * 5000 + b"\n" + b"c" * 3 + b"\n"
        items = self.pump(data, 100)
        self.assertEqual(items[0], ("t", b"a" * 10 + b"\n"))
        self.assertIsInstance(items[1][1], jail_mod._Oversize)
        self.assertEqual(items[1][1].size, 5001)
        self.assertEqual(items[2], ("t", b"ccc\n"))
        self.assertEqual(items[3], ("t", None))

    def test_an_endless_line_without_a_newline_ends_at_eof(self):
        items = self.pump(b"q" * 100000, 1000)
        self.assertIsInstance(items[0][1], jail_mod._Oversize)
        self.assertEqual(items[0][1].size, 100000)
        self.assertEqual(items[-1], ("t", None))

    def test_the_fd_reader_honours_a_limit(self):
        import os
        r, w = os.pipe()
        os.write(w, b"x" * 300 + b"\nok\n")
        os.close(w)
        rd = jail_mod._FdLineReader(r)
        items = self.pump(None, 100, reader=rd)
        os.close(r)
        self.assertIsInstance(items[0][1], jail_mod._Oversize)
        self.assertEqual(items[0][1].size, 301)
        self.assertEqual(items[1], ("t", b"ok\n"))


HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "golden")
ROOT = os.path.dirname(HERE)


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(argv)
    return rc, out.getvalue(), err.getvalue()


class TestGolden(unittest.TestCase):
    """Every output format against a stored copy (tests/golden). To accept a
    deliberate change: UPDATE_GOLDEN=1 python -m pytest tests/test_round5.py,
    then read the diff."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="r5-golden-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.policy = os.path.join(self.tmp, "policy.json")
        shutil.copy(os.path.join(GOLDEN, "policy.json"), self.policy)

    def golden(self, name, text):
        text = text.replace(self.tmp, "<TMP>")
        path = os.path.join(GOLDEN, name)
        if os.environ.get("UPDATE_GOLDEN"):
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
        with open(path, encoding="utf-8", newline="") as f:
            self.assertEqual(text, f.read(), f"{name} changed")

    def audit_file(self):
        dst = os.path.join(self.tmp, "audit.jsonl")
        shutil.copy(os.path.join(GOLDEN, "audit.jsonl"), dst)
        old = jail_mod.AUDIT_LOG
        jail_mod.AUDIT_LOG = dst
        self.addCleanup(setattr, jail_mod, "AUDIT_LOG", old)

    def test_check_summary(self):
        rc, out, err = run_cli(["check", "--policy", self.policy])
        self.assertEqual(rc, 0)
        self.golden("check_summary.txt", out + "--stderr--\n" + err)

    def test_check_a_denied_call(self):
        rc, out, err = run_cli(["check", "--policy", self.policy, "read_file",
                                '{"path": "/etc/passwd"}'])
        self.assertEqual(rc, 1)
        self.golden("check_deny.txt", out + "--stderr--\n" + err)

    def test_check_json_is_one_ascii_line_and_keeps_the_exit_status(self):
        rc, out, err = run_cli(["check", "--json", "--policy", self.policy, "read_file",
                                '{"path": "/srv/data/\u202e.txt"}'])
        self.assertEqual(rc, 1)
        rec = json.loads(out)
        self.assertEqual((rec["decision"], rec["tool"]), ("deny", "read_file"))
        out.encode("ascii")
        self.assertEqual(len(out.splitlines()), 1)
        rc, out, err = run_cli(["check", "--json", "--policy", self.policy, "search", "{}"])
        self.assertEqual((rc, json.loads(out)["decision"]), (0, "allow"))
        rc, out, err = run_cli(["check", "--json", "--policy", self.policy])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["policy"], "ok")

    def test_test_command_and_junit(self):
        cases = os.path.join(GOLDEN, "cases.json")
        xml = os.path.join(self.tmp, "r.xml")
        rc, out, err = run_cli(["test", "--policy", self.policy, cases, "--junit", xml])
        self.assertEqual(rc, 1)
        self.golden("test_output.txt", out + "--stderr--\n" + err)
        with open(xml, encoding="utf-8") as f:
            text = f.read()
        self.golden("test_junit.xml", text.replace(
            "mcp-leash " + jail_mod.VERSION, "mcp-leash <VERSION>"))
        root = ET.fromstring(text)           # well-formed whatever the case names held
        suite = root.find("testsuite")
        self.assertEqual((suite.get("tests"), suite.get("failures")), ("5", "2"))
        self.assertEqual(len(suite.findall("testcase/failure")), 2)

    def test_junit_without_failures_exits_zero_and_still_writes(self):
        cases = os.path.join(self.tmp, "ok.json")
        with open(cases, "w") as f:
            json.dump([{"tool": "delete_all", "expect": "deny"}], f)
        xml = os.path.join(self.tmp, "r.xml")
        rc, out, err = run_cli(["test", "--policy", self.policy, cases, "--junit", xml])
        self.assertEqual(rc, 0)
        self.assertEqual(ET.parse(xml).getroot().find("testsuite").get("failures"), "0")

    def test_junit_to_an_unwritable_place_is_exit_2(self):
        cases = os.path.join(self.tmp, "ok.json")
        with open(cases, "w") as f:
            json.dump([{"tool": "delete_all", "expect": "deny"}], f)
        rc, out, err = run_cli(["test", "--policy", self.policy, cases, "--junit",
                                os.path.join(self.tmp, "no", "such", "dir", "r.xml")])
        self.assertEqual(rc, 2)
        self.assertIn("cannot write", err)

    def test_audit_text_json_and_summary(self):
        self.audit_file()
        rc, out, err = run_cli(["--audit"])
        self.assertEqual(rc, 0)
        self.golden("audit_text.txt", out)
        rc, out, err = run_cli(["--audit", "--decision", "deny", "--json"])
        self.golden("audit_json.txt", out)
        for line in out.splitlines():
            json.loads(line)
        rc, out, err = run_cli(["--audit", "--summary"])
        self.golden("audit_summary.txt", out)
        rc, out, err = run_cli(["--audit", "--tool", "read_*"])
        self.golden("audit_tool_filter.txt", out)

    def test_demo_transcript(self):
        rc, out, err = run_cli(["demo"])
        self.assertEqual(rc, 0, err)
        self.golden("demo.txt", out + "--stderr--\n" + err)

    def test_schema_output(self):
        rc, out, err = run_cli(["schema"])
        self.assertEqual(rc, 0)
        self.golden("schema.json", out)

    def test_wrap_outputs(self):
        argv = ["wrap", "--command", "mcp-leash", "--policy", "/p/pol.json"]
        rc, out, err = run_cli(argv + ["files", "--", "npx", "-y", "srv", "/my dir"])
        self.assertEqual(rc, 0)
        entry = json.loads(out)["mcpServers"]["files"]
        self.assertEqual(entry, {"command": "mcp-leash", "args": [
            "--policy", os.path.abspath("/p/pol.json"), "--", "npx", "-y", "srv", "/my dir"]})
        rc, out, err = run_cli(["wrap", "--format", "claude-code", "--command", "mcp-leash",
                                "--policy", "/p/pol.json", "files", "--", "npx", "srv", "/my dir"])
        if os.name != "nt":
            self.assertEqual(out.strip(), "claude mcp add files -- mcp-leash --policy "
                             "/p/pol.json -- npx srv '/my dir'")
        rc, out, err = run_cli(argv + ["--url", "https://h/mcp", "--header-env",
                                       "Authorization=TOK", "remote"])
        self.assertEqual(json.loads(out)["mcpServers"]["remote"]["args"][2:], [
            "--url", "https://h/mcp", "--header-env", "Authorization=TOK"])
        for bad in (["x"], ["x", "--url", "https://h/m", "--", "cmd"]):
            self.assertEqual(run_cli(argv + bad)[0], 2, bad)

    def test_wrapped_entry_really_starts(self):
        """The printed entry is what a client would run: do it."""
        import subprocess
        pol = os.path.join(self.tmp, "pol.json")
        with open(pol, "w") as f:
            json.dump({"allow_tools": ["*"]}, f)
        rc, out, err = run_cli(["wrap", "--policy", pol, "t", "--", sys.executable, "-c", "print(1)"])
        entry = json.loads(out)["mcpServers"]["t"]
        env = tj.child_env()
        for var in ("HOME", "USERPROFILE", "APPDATA"):
            env[var] = self.tmp
        env["PYTHONPATH"] = ROOT
        cmd = [entry["command"]] + entry["args"]
        if entry["command"] == sys.executable or os.path.basename(entry["command"]).startswith("python"):
            p = subprocess.run(cmd, input=b"", capture_output=True, env=env, timeout=30)
            self.assertIn(p.returncode, (0, 3))


class TestSchema(unittest.TestCase):
    def test_schema_covers_exactly_the_keys_the_loader_accepts(self):
        from mcp_leash import schema
        sc = schema.policy_schema()
        self.assertEqual(set(sc["properties"]),
                         set(jail_mod.POLICY_KEYS) | set(jail_mod.NOTE_KEYS))
        self.assertIs(sc["additionalProperties"], False)

    def test_schema_matches_scan_detectors_and_actions(self):
        from mcp_leash import schema, scan
        sc = schema.policy_schema()["properties"]["scan"]["properties"]
        for section, (kinds, actions) in scan.SECTIONS.items():
            self.assertEqual(set(sc[section]["properties"]), set(kinds))
            for k in kinds:
                self.assertEqual(sc[section]["properties"][k]["enum"], list(actions))

    def test_policies_the_tool_writes_validate_and_typos_do_not(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is not installed")
        from mcp_leash import schema
        sc = schema.policy_schema()
        v = jsonschema.Draft202012Validator(sc)
        jsonschema.Draft202012Validator.check_schema(sc)
        good = [jail_mod.default_policy(),
                json.load(open(os.path.join(GOLDEN, "policy.json"))),
                jail_mod.generate_policy(["a", "b"], [("a", {"path": "/x"})]),
                {"allow_tools": ["a"], "limits": {
                    "max_message_bytes": 4096, "per_tool": {"a": {"max_calls": 3}}},
                    "tool_pins": {"a": "sha256:" + "0" * 64}, "audit_max_bytes": 5000,
                    "arg_rules": {"a": {"allow": {"p": [{"type": "string", "pattern": "x"}]},
                                        "deny": ["bad"]}}}]
        for pol in good:
            self.assertEqual(list(v.iter_errors(pol)), [], pol)
            jail_mod.compile_policy(json.loads(json.dumps(pol)))     # the loader agrees
        bad = [{"alow_tools": []}, {"allow_tools": "read"}, {"audit_args": "some"},
               {"limits": {"max_message_bytes": 10}}, {"scan": {"arguments": {"secrets": "redact"}}},
               {"tool_pins": {"a": "md5:00"}}, {"strict_args": "yes"}]
        for pol in bad:
            self.assertTrue(list(v.iter_errors(pol)), pol)
            with self.assertRaises(ValueError):
                jail_mod.compile_policy(json.loads(json.dumps(pol)))


class TestLearnWritesTheCeiling(unittest.TestCase):
    def test_a_learned_policy_loads_and_carries_a_16_mib_ceiling(self):
        pol = jail_mod.generate_policy(["a"], [("a", {"x": "1"})])
        self.assertEqual(pol["limits"]["max_message_bytes"], 16 * 1024 * 1024)
        jail_mod.compile_policy(json.loads(json.dumps(pol)))


if __name__ == "__main__":
    unittest.main()
