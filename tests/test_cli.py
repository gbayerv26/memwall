import contextlib
import io
import json
import os
import tempfile
import unittest

from memwall import cli

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class CliTests(unittest.TestCase):
    def _run(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(list(argv))
        return code, out.getvalue()

    def test_poisoned_store_fails_ci_gate(self):
        code, out = self._run("scan", os.path.join(FIXTURES, "poisoned_memory.jsonl"), "--fail-on", "high")
        self.assertEqual(code, 1)
        self.assertIn("MW000", out)

    def test_benign_store_passes(self):
        code, out = self._run("scan", os.path.join(FIXTURES, "benign_memory.jsonl"), "--fail-on", "low")
        self.assertEqual(code, 0)
        self.assertIn("clean", out)

    def test_json_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "report.json")
            self._run("scan", os.path.join(FIXTURES, "mem0_poisoned.json"), "--json", dest)
            with open(dest, encoding="utf-8") as fh:
                data = json.load(fh)
        self.assertEqual(data["scanned"], 3)
        self.assertTrue(any(rec["severity"] == "CRITICAL" for rec in data["records"]))

    def test_rules_listing(self):
        code, out = self._run("rules")
        self.assertEqual(code, 0)
        self.assertIn("MW001", out)

    def test_quiet_output(self):
        code, out = self._run("scan", os.path.join(FIXTURES, "poisoned_memory.jsonl"), "--quiet")
        self.assertEqual(code, 1)
        self.assertIn("flagged", out)
        self.assertNotIn("MW000", out)

    def test_baseline_workflow(self):
        with tempfile.TemporaryDirectory() as tmp:
            baseline = os.path.join(tmp, "baseline.json")
            src = os.path.join(FIXTURES, "poisoned_memory.jsonl")

            code, out = self._run("scan", src, "--baseline", baseline, "--update-baseline")
            self.assertEqual(code, 0)
            self.assertIn("baseline written", out)

            code, out = self._run("scan", src, "--baseline", baseline)
            self.assertEqual(code, 0)  # everything accepted -> gate passes
            self.assertIn("clean", out)
            self.assertIn("suppressed", out)


if __name__ == "__main__":
    unittest.main()
