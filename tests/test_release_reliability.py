"""Behavioral regressions, runnable unchanged against the v0.7.1 baseline.

Set MEMWALL_EVIDENCE_DIR to preserve synthetic wire traffic and state snapshots.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from memwall import cli
from memwall.state import StateStore

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "tests" / "release_backend.py"


class ReleaseFixture:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.store = StateStore(str(self.state))
        self.request = {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {
            "name": "add_observations", "arguments": {"contents": ["synthetic observation"]}}}

    def entry(self):
        return self.store.quarantine("add_observations", self.request, [])

    def command(self, qid, mode="ok"):
        return [sys.executable, "-m", "memwall", "quarantine", "--state-dir", str(self.state),
                "release", qid, "--", sys.executable, str(BACKEND), str(self.root), mode]

    def release(self, qid, mode="ok"):
        proc = subprocess.run(self.command(qid, mode), cwd=ROOT, capture_output=True,
                              text=True, timeout=20)
        return {"exit": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}

    def effects(self):
        path = self.root / "effects.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def wait_for(self, predicate):
        end = time.monotonic() + 10
        while not predicate():
            if time.monotonic() > end:
                self.fail("fixture did not reach synchronization point")
            time.sleep(.01)

    def evidence(self, result):
        directory = os.environ.get("MEMWALL_EVIDENCE_DIR")
        if not directory:
            return
        files = {}
        for path in self.root.rglob("*"):
            if path.is_file() and path.suffix in (".jsonl",):
                files[path.relative_to(self.root).as_posix()] = path.read_bytes().decode("utf-8")
        target = Path(directory)
        target.mkdir(parents=True, exist_ok=True)
        (target / (self._testMethodName + ".json")).write_text(json.dumps({
            "observed": result, "raw_files": files}, indent=2), encoding="utf-8")


class ReleaseReliabilityTests(ReleaseFixture, unittest.TestCase):
    def test_identical_requests_have_separate_entries(self):
        with mock.patch.object(StateStore, "_now", return_value="2026-10-19T00:00:00Z"):
            ids = [self.entry(), self.entry()]
        entries = self.store.quarantine_entries()
        self.evidence({"ids": ids, "entries": len(entries)})
        self.assertNotEqual(*ids)
        self.assertEqual(len(entries), 2)

    def test_lost_response_cannot_replay_effect(self):
        qid = self.entry()
        first = self.release(qid, "lost")
        second = self.release(qid)
        status = self.store.quarantine_entries()[0]["status"]
        self.evidence({"first": first, "second": second, "status": status,
                       "effect_count": len(self.effects())})
        self.assertEqual(first["exit"], 1)
        self.assertNotEqual(second["exit"], 0)
        self.assertEqual(status, "uncertain")
        self.assertEqual(len(self.effects()), 1)

    def test_truncated_status_prevents_release(self):
        qid = self.entry()
        with open(self.store.quarantine_path, "ab") as fh:
            fh.write(b'{"type":"status","qid":"')
        result = self.release(qid)
        self.evidence({"release": result, "effect_count": len(self.effects())})
        self.assertNotEqual(result["exit"], 0)
        self.assertIn("journal", result["stderr"].lower())
        self.assertEqual(len(self.effects()), 0)

    def test_concurrent_release_dispatches_once(self):
        qid = self.entry()
        procs = []
        try:
            procs.append(subprocess.Popen(self.command(qid, "gate"), cwd=ROOT,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE))
            self.wait_for(lambda: list(self.root.glob("started-*")))
            procs.append(subprocess.Popen(self.command(qid, "gate"), cwd=ROOT,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE))
            self.wait_for(lambda: procs[1].poll() is not None or
                          len(list(self.root.glob("started-*"))) == 2)
            (self.root / "continue").touch()
            results = []
            for proc in procs:
                out, err = proc.communicate(timeout=15)
                results.append({"exit": proc.returncode, "stdout": out.decode(), "stderr": err.decode()})
            self.evidence({"processes": results, "effect_count": len(self.effects())})
            self.assertEqual(sorted(p.returncode for p in procs), [0, 2])
            self.assertEqual(len(self.effects()), 1)
        finally:
            (self.root / "continue").touch()
            for proc in procs:
                if proc.poll() is None:
                    proc.kill()
                proc.communicate(timeout=15)

    def test_completion_record_failure_cannot_replay_effect(self):
        qid = self.entry()
        original = StateStore.set_status

        def fail_completion(store, key, status, *args, **kwargs):
            if status == "released":
                raise OSError("injected completion write failure")
            return original(store, key, status, *args, **kwargs)

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(StateStore, "set_status", fail_completion), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                first = {"exit": cli.main(self.command(qid)[3:])}
            except OSError as exc:
                first = {"exception": str(exc)}
        first.update(stdout=out.getvalue(), stderr=err.getvalue())
        second = self.release(qid)
        self.evidence({"first": first, "second": second, "effect_count": len(self.effects())})
        self.assertNotEqual(second["exit"], 0)
        self.assertEqual(len(self.effects()), 1)


if __name__ == "__main__":
    unittest.main()
