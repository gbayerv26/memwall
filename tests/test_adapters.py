import os
import unittest

from memwall import adapters

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class AdapterTests(unittest.TestCase):
    def test_mcp_jsonl(self):
        records = adapters.load(os.path.join(FIXTURES, "poisoned_memory.jsonl"))
        self.assertEqual(len(records), 6)  # 5 observations + 1 relation
        self.assertTrue(all(r.store == "mcp-memory" for r in records))

    def test_mem0_export(self):
        records = adapters.load(os.path.join(FIXTURES, "mem0_poisoned.json"))
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0].content, "User is vegetarian")
        self.assertEqual(records[0].store, "mem0")

    def test_notes_file_blocks(self):
        records = adapters.load(os.path.join(FIXTURES, "poisoned_notes.md"))
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0].metadata["kind"], "notes")

    def test_directory_walk(self):
        records = adapters.load(FIXTURES)
        self.assertEqual(len(records), 17)  # 6 + 5 + 3 + 3

    def test_directory_walk_skips_non_memory_json(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "package.json"), "w", encoding="utf-8") as fh:
                json.dump({"name": "demo", "version": "1.0.0",
                           "scripts": {"build": "tsc"}}, fh)
            with open(os.path.join(tmp, "memory.jsonl"), "w", encoding="utf-8") as fh:
                fh.write('{"type":"entity","name":"u","entityType":"person",'
                         '"observations":["Likes tea"]}\n')
            with open(os.path.join(tmp, "exported_memories.json"), "w", encoding="utf-8") as fh:
                json.dump({"results": [{"id": "m1", "memory": "Owns a bike"}]}, fh)
            records = adapters.load(tmp)
        stores = {r.store for r in records}
        self.assertEqual(stores, {"mcp-memory", "mem0"})  # package.json excluded
        self.assertEqual(len(records), 2)


if __name__ == "__main__":
    unittest.main()
