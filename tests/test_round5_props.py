"""Round 5: property tests with a seeded generator (hypothesis is not a
dependency), run against the policy engine.  A failing case prints its seed
and the generated input so it can be replayed.
"""

import copy
import json
import random
import string
import unittest

from mcp_leash import jail as jail_mod

SEEDS = range(40)
ZW = ["​", "‍", "⁠", "﻿", "­"]


def rname(rng):
    n = rng.randint(1, 12)
    return "".join(rng.choice(string.ascii_letters + string.digits + "_-.")
                   for _ in range(n))


def variant(rng, name):
    """The same tool name written another way: case, invisible characters,
    full-width letters, surrounding spaces."""
    out = []
    for ch in name:
        r = rng.random()
        if r < 0.3:
            ch = ch.swapcase()
        if r > 0.85 and ch.isascii() and ch.isalnum():
            ch = chr(ord(ch) + 0xFEE0)        # full-width form
        out.append(ch)
        if rng.random() < 0.15:
            out.append(rng.choice(ZW))
    return rng.choice(["", " "]) + "".join(out) + rng.choice(["", " "])


def rvalue(rng, depth=0):
    r = rng.random()
    if depth > 3 or r < 0.5:
        return rng.choice([rname(rng), rng.randint(-5, 5), None, True, 1.5,
                           "", "/etc/passwd", "../x", "é‮"])
    if r < 0.75:
        return [rvalue(rng, depth + 1) for _ in range(rng.randint(0, 3))]
    return {rname(rng): rvalue(rng, depth + 1) for _ in range(rng.randint(0, 3))}


def plant(rng, value, key, payload, depth=0):
    """Hide `payload` under `key` somewhere inside a random structure."""
    box = {rname(rng): rvalue(rng) for _ in range(rng.randint(0, 2))}
    cur = box
    for _ in range(rng.randint(0, 3)):
        nxt = {rname(rng): rvalue(rng)}
        cur[rname(rng)] = rng.choice([nxt, [nxt, rvalue(rng)]])
        cur = nxt
    cur[key] = payload
    return box


def decide(pol, name, args):
    pol = copy.deepcopy(pol)
    _n, _a, ok, reason = jail_mod.judge_call(
        jail_mod.compile_policy(pol), "tools/call",
        {"name": name, "arguments": args})
    return ok, reason


class TestPolicyProperties(unittest.TestCase):
    def test_a_denied_name_is_denied_however_it_is_written(self):
        for seed in SEEDS:
            rng = random.Random(seed)
            name = rname(rng)
            others = [rname(rng) for _ in range(3)]
            pol = {"allow_tools": ["*"], "deny_tools": [name]}
            for _ in range(8):
                v = variant(rng, name)
                ok, why = decide(pol, v, rvalue(rng) if False else {})
                self.assertFalse(ok, f"seed={seed} {v!r}")
            for o in others:
                if jail_mod.normalize_tool_name(o) != jail_mod.normalize_tool_name(name):
                    self.assertTrue(decide(pol, o, {})[0], f"seed={seed} {o!r}")

    def test_a_tool_outside_the_allowlist_is_denied(self):
        for seed in SEEDS:
            rng = random.Random(1000 + seed)
            allowed = [rname(rng) for _ in range(3)]
            pol = {"allow_tools": allowed}
            norm = {jail_mod.normalize_tool_name(a) for a in allowed}
            for _ in range(10):
                t = rname(rng)
                ok = decide(pol, t, {})[0]
                self.assertEqual(ok, jail_mod.normalize_tool_name(t) in norm,
                                 f"seed={seed} {t!r}")
            for a in allowed:
                self.assertTrue(decide(pol, variant(rng, a), {})[0], f"seed={seed}")

    def test_deny_wins_over_allow(self):
        for seed in SEEDS:
            rng = random.Random(2000 + seed)
            name = rname(rng)
            pol = {"allow_tools": [name, "*"], "deny_tools": [name]}
            self.assertFalse(decide(pol, name, {})[0], f"seed={seed}")
            pol = {"allow_tools": [name], "deny_tools": ["*"]}
            self.assertFalse(decide(pol, name, {})[0], f"seed={seed}")

    def test_a_denied_value_is_found_at_any_depth_in_any_shape(self):
        for seed in SEEDS:
            rng = random.Random(3000 + seed)
            pol = {"allow_tools": ["t"],
                   "arg_rules": {"t": {"allow": "*", "deny": {"**": "FORBIDDEN"}}}}
            args = plant(rng, None, rname(rng), "xx FORBIDDEN xx")
            ok, why = decide(pol, "t", args)
            self.assertFalse(ok, f"seed={seed} {json.dumps(args)}")

    def test_a_denied_key_name_is_found_at_any_depth_whatever_its_case(self):
        for seed in SEEDS:
            rng = random.Random(4000 + seed)
            pol = {"allow_tools": ["t"],
                   "arg_rules": {"t": {"allow": "*", "deny": {"path": "^/etc"}}}}
            key = "".join(rng.choice([c.lower(), c.upper()]) for c in "path")
            args = plant(rng, None, key, "/etc/shadow")
            # the rule is on the top-level key only, so a nested "path" is
            # judged by `**`-less matching: the result must not depend on
            # what else is in the object
            top = decide(pol, "t", {key: "/etc/shadow"})[0]
            self.assertFalse(top, f"seed={seed}")
            noise = {rname(rng): rvalue(rng) for _ in range(4)}
            noise.pop("path", None)
            noise = {k: v for k, v in noise.items() if k.lower() != "path"}
            noise[key] = "/etc/shadow"
            self.assertFalse(decide(pol, "t", noise)[0], f"seed={seed}")
            self.assertTrue(decide(pol, "t", {k: v for k, v in noise.items()
                                              if k != key})[0], f"seed={seed}")
            del args

    def test_the_decision_does_not_depend_on_the_order_of_keys(self):
        for seed in SEEDS:
            rng = random.Random(5000 + seed)
            pol = {"allow_tools": ["t"],
                   "arg_rules": {"t": {"allow": "*", "deny": {"**": "BAD"}}}}
            items = [(rname(rng), rvalue(rng)) for _ in range(6)]
            if rng.random() < 0.5:
                items.append((rname(rng), "a BAD b"))
            a = dict(items)
            b = dict(reversed(items))
            self.assertEqual(decide(pol, "t", a)[0], decide(pol, "t", b)[0],
                             f"seed={seed}")

    def test_no_input_makes_the_judge_raise(self):
        pol = jail_mod.compile_policy({"allow_tools": ["t"], "strict_args": True,
                                       "arg_rules": {"t": {"allow": {"a": "^x"},
                                                           "deny": {"**": "z"}}}})
        for seed in SEEDS:
            rng = random.Random(6000 + seed)
            for _ in range(25):
                params = rng.choice([
                    rvalue(rng), {"name": rvalue(rng), "arguments": rvalue(rng)},
                    {"name": "t", "arguments": rvalue(rng)},
                    {"name": "t", "arguments": {"a": rvalue(rng)}}])
                jail_mod.judge_call(pol, "tools/call", params)

    def test_a_strict_policy_is_never_looser_than_a_lax_one(self):
        # adding strict_args or a deny rule can only remove permissions
        for seed in SEEDS:
            rng = random.Random(7000 + seed)
            lax = {"allow_tools": ["t"]}
            strict = {"allow_tools": ["t"], "strict_args": True}
            deny = {"allow_tools": ["t"], "arg_rules": {"t": {"allow": "*",
                                                              "deny": {"**": "q"}}}}
            for _ in range(10):
                args = {rname(rng): rvalue(rng) for _ in range(rng.randint(0, 3))}
                l = decide(lax, "t", args)[0]
                self.assertTrue(l or not (decide(strict, "t", args)[0]), f"seed={seed}")
                self.assertTrue(l or not (decide(deny, "t", args)[0]), f"seed={seed}")


class TestWireProperties(unittest.TestCase):
    def test_re_encoding_is_a_fixed_point_and_ascii(self):
        for seed in SEEDS:
            rng = random.Random(8000 + seed)
            obj = {"jsonrpc": "2.0", "id": rng.randint(0, 99), "result": rvalue(rng)}
            once = jail_mod._encode(obj)
            msg, code, err = jail_mod._parse(once)
            self.assertIsNone(code, f"seed={seed} {err}")
            self.assertEqual(jail_mod._encode(msg), once, f"seed={seed}")
            once.decode("ascii")
            self.assertEqual(once.count(b"\n"), 1)

    def test_a_line_the_parser_refuses_is_never_half_accepted(self):
        bad = [b'{"id":1,"id":2,"method":"x"}\n', b'{"id":1,"method":"x\x01"}\n',
               b'{"id":NaN,"method":"x"}\n', b'{"id":1,"method":"x"} trailing\n',
               b'\xff\xfe{"id":1}\n']
        for line in bad:
            msg, code, err = jail_mod._parse(line)
            self.assertIsNotNone(code, line)

    def test_compile_policy_is_idempotent_and_marker_forgery_refused(self):
        for seed in SEEDS:
            rng = random.Random(9000 + seed)
            pol = {"allow_tools": [rname(rng)], "deny_tools": [rname(rng)]}
            once = jail_mod.compile_policy(copy.deepcopy(pol))
            twice = jail_mod.compile_policy(once)
            self.assertIs(once, twice)
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "p.json")
            for key in jail_mod._INTERNAL_KEYS:
                with open(p, "w") as f:
                    json.dump({"allow_tools": ["*"], key: True}, f)
                with self.assertRaises(ValueError, msg=key):
                    jail_mod.load_policy(p)


if __name__ == "__main__":
    unittest.main()
