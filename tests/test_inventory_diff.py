"""Public entry-point checks for inventory comparisons."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from memwall.cli import main


class InventoryComparison(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.store = self.root / "private-locator.json"
        self.secret = "PRIVATE-escalation-DO-NOT-SHARE"

    def cli(self, *args, expected=0):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = main(["inventory", *map(str, args)])
        self.assertEqual(code, expected, output.getvalue())
        return json.loads(output.getvalue())

    def snap(self, name, items, expected=0):
        self.store.write_text(json.dumps(items), encoding="utf-8")
        path = self.root / name
        self.cli("snapshot", self.store, "--format", "mem0", "--scope", "private-label",
                 "--out", path, expected=expected)
        return path

    def record(self, key, content=None):
        return {"id": key, "memory": content or self.secret, "user_id": "private-namespace"}

    def test_edit_and_share(self):
        a = self.snap("a", [self.record("private-key"), self.record("other")])
        b = self.snap("b", [self.record("other"), self.record("private-key", "Priority Support")])
        summary = self.root / "summary"
        result = self.cli("diff", a, b, "--summary", summary)
        self.assertEqual(result["summary"]["counts"]["changed"], 1)
        self.assertEqual(result["summary"]["counts"]["unchanged"], 1)
        edit, = result["details"]
        old, new = edit["before"][0], edit["after"][0]
        self.assertEqual(old["content"], self.secret)
        self.assertNotEqual(old["revision"], new["revision"])
        for token in (self.secret, "private-", str(self.root), self.store.name,
                      "Priority Support", old["revision"], new["revision"]):
            self.assertNotIn(token.encode(), summary.read_bytes())

    def test_directional_coverage(self):
        full = self.snap("full", [self.record("k"), self.record("other")])
        partial = self.snap("partial", [None, self.record("k", "updated")], expected=2)
        empty = self.snap("empty", [])
        for before, after in ((partial, full), (full, partial)):
            counts = self.cli("diff", before, after, expected=2)["summary"]["counts"]
            self.assertEqual((counts["presence_only"], counts["changed"]), (1, 1))
        self.assertEqual(self.cli("diff", full, empty)["summary"]["counts"]["absent_from_scope"], 2)
        self.assertEqual(self.cli("diff", empty, partial, expected=2)["summary"]["counts"]["added"], 1)

    def test_duplicate_and_weak(self):
        a = self.snap("a", [self.record("mem-0"), "word", "word"])
        b = self.snap("b", ["word", self.record("mem-0")])
        counts = self.cli("diff", a, b)["summary"]["counts"]
        self.assertEqual((counts["count_difference"], counts["unchanged"], counts["changed"]),
                         (1, 1, 0))
        c = self.snap("c", [self.record("mem-0"), self.record("mem-0", "another")])
        summary = self.cli("diff", a, c, expected=2)["summary"]
        self.assertIn("duplicate_key", summary["reason_codes"])
        self.assertEqual(summary["counts"]["changed"], 0)

    def test_paragraph_reorder_and_different_boundary(self):
        path = self.root / "notes.md"
        snaps = []
        for index, content in enumerate(("First\n\nRepeated\n\nRepeated", "Repeated\n\nFirst\n\nRepeated")):
            path.write_text(content, encoding="utf-8")
            snaps.append(self.root / str(index))
            self.cli("snapshot", path, "--scope", "s", "--out", snaps[-1])
        counts = self.cli("diff", *snaps)["summary"]["counts"]
        self.assertEqual((counts["changed"], counts["count_difference"]), (0, 0))
        other = self.root / "other.md"
        path.rename(other)
        self.cli("snapshot", other, "--scope", "s", "--out", self.root / "other")
        result = self.cli("diff", snaps[0], self.root / "other", expected=2)
        self.assertEqual(result["summary"]["reason_codes"], ["incompatible_boundary"])
