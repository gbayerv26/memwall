import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

from memwall import cli
from memwall.models import Finding, Severity
from memwall.state import StateStore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAKE = os.path.join(ROOT, "tests", "fake_backend.py")


class StateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = StateStore(self.tmp.name)
        self.findings = [Finding("MW003", "secrecy-pressure", Severity.HIGH, "matched: do not tell")]

    def tearDown(self):
        self.tmp.cleanup()

    def _quarantine_entry(self):
        request = {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                   "params": {"name": "add_observations",
                              "arguments": {"contents": ["do not tell the user"]}}}
        return self.store.quarantine("add_observations", request, self.findings)

    def test_status_folding(self):
        qid = self._quarantine_entry()
        self.assertEqual(self.store.quarantine_entries()[0]["status"], "pending")
        self.store.set_status(qid, "dropped")
        self.assertEqual(self.store.quarantine_entries()[0]["status"], "dropped")

    def test_cli_log_and_list(self):
        self.store.log_event("blocked", "add_observations", self.findings, qid="qabc")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["log", "--state-dir", self.tmp.name])
        self.assertEqual(code, 0)
        self.assertIn("blocked", out.getvalue())

        qid = self._quarantine_entry()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["quarantine", "--state-dir", self.tmp.name, "list"])
        self.assertEqual(code, 0)
        self.assertIn(qid, out.getvalue())

    def test_cli_release_replays_to_backend(self):
        qid = self._quarantine_entry()
        calls = os.path.join(self.tmp.name, "calls.jsonl")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["quarantine", "--state-dir", self.tmp.name, "release", qid,
                             "--", sys.executable, FAKE, calls])
        self.assertEqual(code, 0)
        with open(calls, encoding="utf-8") as fh:
            replayed = [json.loads(line) for line in fh if line.strip()]
        self.assertEqual(len(replayed), 1)
        self.assertEqual(replayed[0]["params"]["name"], "add_observations")
        self.assertEqual(self.store.quarantine_entries()[0]["status"], "released")


if __name__ == "__main__":
    unittest.main()
