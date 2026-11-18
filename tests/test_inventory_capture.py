import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from memwall.inventory_capture import capture, publish, read_manifest, snapshot, validate


class InventoryCaptureTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.store = self.root / "memory.json"
        self.store.write_text('[{"id":"mem-0","memory":"a"},{"memory":"b"}]', encoding="utf-8")

    def test_extraction_remembers_native_key_and_location(self):
        self.store.write_text('["same",{"id":"mem-0","memory":"same"}]', encoding="utf-8")
        first, second = (capture(self.store, "mem0", "local") for _ in range(2))
        self.assertEqual(first["records"], second["records"])
        self.assertEqual([(r["key"], r["locator"]) for r in first["records"]],
                         [(None, "item[0]"), ("mem-0", "item[1]")])
        self.assertTrue(all(r["store_timestamp"] is None for r in first["records"]))

    def test_failed_empty_and_missing(self):
        empty = self.root / "empty"
        empty.mkdir()
        self.assertEqual(capture(empty, "auto", "s")["coverage"]["status"], "no_sources")
        self.assertEqual(capture(empty / "missing", "auto", "s")["coverage"]["status"], "failed")
        self.store.write_text("[]", encoding="utf-8")
        self.assertEqual(capture(self.store, "mem0", "s")["coverage"]["status"], "complete")

    def test_no_clobber_and_staging_failure(self):
        target = self.root / "snapshot.json"
        snapshot(self.store, "auto", "local", target)
        original = target.read_bytes()
        with self.assertRaises(FileExistsError):
            snapshot(self.store, "auto", "local", target)
        self.assertEqual(original, target.read_bytes())
        alias = self.root / "alias"
        os.link(self.store, alias)
        source = self.store.read_bytes()
        with self.assertRaises(FileExistsError):
            snapshot(self.store, "auto", "local", alias)
        self.assertEqual(source, self.store.read_bytes())
        with self.assertRaises(ValueError):
            snapshot(self.root, "auto", "local", self.root / "inside")
        uncommitted = self.root / "uncommitted"
        with patch("memwall.inventory_capture.os.fsync", side_effect=OSError("interrupt")):
            with self.assertRaises(OSError):
                publish(uncommitted, {"value": True})
        self.assertFalse(uncommitted.exists())
        self.assertEqual(list(self.root.glob(".memwall-*")), [])

    def test_manifest_validation(self):
        data = capture(self.store, "mem0", "s")
        changes = [("coverage", "status", "partial"), ("coverage", "records", False),
                   ("coverage", "issue_counts", {"source_missing": 1}),
                   ("boundary", "scope", None), ("boundary", "format", []),
                   ("records", 0, {})]
        for field, key, value in changes:
            with self.subTest(field=field, key=key), self.assertRaises(ValueError):
                invalid = copy.deepcopy(data)
                invalid[field][key] = value
                validate(invalid)
        for data in (None, 0, [], {}, {"schema": 999}):
            with self.assertRaises(ValueError):
                validate(data)
        self.store.write_text('{"schema":true,"schema":false}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
            read_manifest(self.store)

    def test_langgraph_selection(self):
        item = {"namespace": ["support"], "key": "policy", "value": {"content": "escalate"}}
        envelope = {"schema": "memwall.langgraph-export.v1", "store": "local-demo",
                    "namespaces": [["support"], ["billing"]], "complete": False, "items": [item]}
        self.store.write_text(json.dumps(envelope), encoding="utf-8")
        manifest = capture(self.store, "langgraph", "local")
        self.assertEqual(manifest["coverage"]["issue_counts"], {"export_limited": 1})
        record, = manifest["records"]
        self.assertEqual((record["namespace"], record["key"]), (["support"], "policy"))
        envelope["complete"] = True
        envelope["items"][0]["namespace"] = ["elsewhere"]
        self.store.write_text(json.dumps(envelope), encoding="utf-8")
        manifest = capture(self.store, "langgraph", "local")
        self.assertEqual(manifest["coverage"]["status"], "partial")
        self.assertEqual(manifest["records"], [])
