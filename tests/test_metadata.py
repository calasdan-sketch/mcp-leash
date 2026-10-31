import pathlib
import re
import unittest

import mcp_leash

ROOT = pathlib.Path(__file__).resolve().parent.parent


class MetadataTests(unittest.TestCase):
    def test_version_matches_pyproject(self):
        pp = ROOT / "pyproject.toml"
        if not pp.exists():
            self.skipTest("pyproject.toml not present")
        m = re.search(r'^version\s*=\s*"([^"]+)"', pp.read_text(encoding="utf-8"), re.M)
        self.assertEqual(m.group(1), mcp_leash.VERSION)

    def test_readme_says_not_a_sandbox(self):
        rd = ROOT / "README.md"
        if not rd.exists():
            self.skipTest("README.md not present")
        self.assertIn("not a sandbox", rd.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
