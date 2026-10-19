"""v0.8 lifecycle, journal compatibility, and failure-boundary checks."""
import contextlib
import io
import json
import subprocess
import sys
import unittest
from unittest import mock

from memwall import cli
from memwall.state import StateError, StateStore
from tests.test_release_reliability import ReleaseFixture, ROOT


# Reuse fixture helpers without inheriting the baseline comparison test methods.
class QuarantineRecoveryTests(ReleaseFixture, unittest.TestCase):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["quarantine", "--state-dir", str(self.state), *args])
        return code, out.getvalue(), err.getvalue()

    def status(self):
        return self.store.quarantine_entries()[0]["status"]

    def test_collision_never_replaces_entry(self):
        with mock.patch("memwall.state.uuid.uuid4") as uuid:
            uuid.return_value.hex = "c" * 32
            self.entry()
            before = self.state.joinpath("quarantine.jsonl").read_bytes()
            with self.assertRaisesRegex(StateError, "collision"):
                self.entry()
        self.assertEqual(self.state.joinpath("quarantine.jsonl").read_bytes(), before)

    def test_reconcile_applied_prevents_replay(self):
        qid = self.entry()
        self.assertEqual(self.release(qid, "lost")["exit"], 1)
        self.assertEqual(self.run_cli("drop", qid)[0], 2)
        result = self.run_cli("reconcile", qid, "--outcome", "applied", "--reason",
                              "Read-back confirms the single synthetic effect")
        self.assertEqual(result[0], 0, result)
        self.assertEqual(self.status(), "released")
        self.assertNotEqual(self.release(qid)["exit"], 0)
        self.assertEqual(len(self.effects()), 1)

    def test_not_applied_requires_quiescence_and_reason_then_allows_one_attempt(self):
        qid = self.entry()
        self.store.set_status(qid, "releasing", attempt="a" * 32)
        self.store.set_status(qid, "uncertain", attempt="a" * 32)
        self.assertEqual(self.run_cli("reconcile", qid, "--outcome", "not-applied",
                                     "--reason", "Empty read-back")[0], 2)
        self.assertEqual(self.run_cli("reconcile", qid, "--outcome", "not-applied",
                                     "--backend-quiesced", "--reason", " ")[0], 2)
        result = self.run_cli("reconcile", qid, "--outcome", "not-applied", "--backend-quiesced",
                              "--reason", "Prior backend stopped; empty isolated store verified")
        self.assertEqual(result[0], 0, result)
        self.assertEqual(self.status(), "pending")
        self.assertIs(self.store.quarantine_entries()[0]["release"]["backend_quiesced"], True)
        self.assertEqual(self.release(qid)["exit"], 0)
        self.assertEqual(len(self.effects()), 1)
        self.assertNotEqual(self.release(qid)["exit"], 0)

    def test_launch_and_initialization_failures_are_retryable_without_dispatch(self):
        qid = self.entry()
        with mock.patch("memwall.mcp_client.MiniClient", side_effect=OSError("launch failure")):
            self.assertEqual(self.run_cli("release", qid, "--", "unused")[0], 1)
        self.assertEqual(self.status(), "pending")
        with mock.patch("memwall.mcp_client.MiniClient") as client:
            client.return_value.initialize.side_effect = RuntimeError("handshake failure")
            self.assertEqual(self.run_cli("release", qid, "--", "unused")[0], 1)
            client.return_value.call_tool.assert_not_called()
        self.assertEqual(self.status(), "pending")
        self.assertEqual(len(self.effects()), 0)
        self.assertEqual(self.release(qid)["exit"], 0)

    def test_live_attempt_blocks_drop_and_reconciliation(self):
        qid = self.entry()
        proc = subprocess.Popen(self.command(qid, "gate"), cwd=ROOT,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.wait_for(lambda: list(self.root.glob("started-*")))
            for args in (("drop", qid), ("reconcile", qid, "--outcome", "not-applied",
                          "--backend-quiesced", "--reason", "synthetic probe")):
                result = self.run_cli(*args)
                self.assertEqual(result[0], 2, result)
                self.assertIn("busy", result[2])
            self.assertEqual(self.status(), "releasing")
        finally:
            (self.root / "continue").touch()
            proc.communicate(timeout=15)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(len(self.effects()), 1)

    def test_killed_releaser_leaves_reservation_and_cannot_replay(self):
        qid = self.entry()
        proc = subprocess.Popen(self.command(qid, "hold"), cwd=ROOT,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.wait_for(lambda: list(self.root.glob("applied-*")))
            proc.kill()
            proc.wait(timeout=5)
            result = self.release(qid)
            self.assertEqual(result["exit"], 2)
            self.assertEqual(self.status(), "releasing")
            self.assertEqual(len(self.effects()), 1)
        finally:
            (self.root / "continue").touch()
            proc.communicate(timeout=15)
        result = self.run_cli("reconcile", qid, "--outcome", "applied", "--reason",
                              "Prior backend stopped; read-back confirms synthetic effect")
        self.assertEqual(result[0], 0, result)
        self.evidence({"killed_parent_exit": proc.returncode, "reconcile": result,
                       "status": self.status(), "effect_count": len(self.effects())})

    def test_reservation_write_failure_never_dispatches(self):
        qid = self.entry()
        original = StateStore._append

        def interrupted(store, path, record):
            if record.get("status") == "releasing":
                with open(path, "ab") as fh:
                    fh.write(b'{"version":2,"type":"status"')
                raise OSError("injected interrupted reservation")
            return original(store, path, record)

        with mock.patch.object(StateStore, "_append", interrupted), \
                mock.patch("memwall.mcp_client.MiniClient") as client:
            self.assertEqual(self.run_cli("release", qid, "--", "unused")[0], 2)
            client.assert_not_called()
        self.assertEqual(self.release(qid)["exit"], 2)
        self.assertEqual(len(self.effects()), 0)

    def test_fsync_failure_before_dispatch_never_launches_backend(self):
        qid = self.entry()
        with mock.patch("memwall.state.os.fsync", side_effect=OSError("injected fsync failure")), \
                mock.patch("memwall.mcp_client.MiniClient") as client:
            self.assertEqual(self.run_cli("release", qid, "--", "unused")[0], 2)
            client.assert_not_called()
        self.assertNotEqual(self.release(qid)["exit"], 0)
        self.assertEqual(len(self.effects()), 0)

    def test_completion_error_after_full_record_still_prevents_replay(self):
        qid = self.entry()
        original = StateStore._append

        def failed_after_write(store, path, record):
            original(store, path, record)
            if record.get("status") == "released":
                raise OSError("injected error after completion record")

        with mock.patch.object(StateStore, "_append", failed_after_write):
            result = self.run_cli("release", qid, "--", sys.executable,
                                  str(ROOT / "tests" / "release_backend.py"), str(self.root), "ok")
        self.assertEqual(result[0], 1, result)
        self.assertEqual(self.status(), "released")
        self.assertEqual(self.release(qid)["exit"], 2)
        self.assertEqual(len(self.effects()), 1)

    def test_legacy_pending_entry_is_readable_and_releasable(self):
        qid = self.entry()
        path = self.state / "quarantine.jsonl"
        record = json.loads(path.read_text())
        del record["version"]
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        self.assertEqual(self.release(qid)["exit"], 0)
        self.assertEqual(self.status(), "released")

    def test_legacy_finalized_entries_remain_finalized(self):
        self.entry()
        path = self.state / "quarantine.jsonl"
        record = json.loads(path.read_text())
        del record["version"]
        for status in ("released", "dropped"):
            path.write_text(json.dumps(record) + "\n" + json.dumps({"type": "status",
                "qid": record["qid"], "ts": "legacy", "status": status}) + "\n", encoding="utf-8")
            self.assertEqual(self.status(), status)
            self.assertEqual(self.release(record["qid"])["exit"], 2)

    def test_corruption_variants_refuse_reads_mutations_and_release(self):
        qid = self.entry()
        path = self.state / "quarantine.jsonl"
        original = path.read_bytes()
        corruptions = [original, b'[]\n', b'{"version":99}\n', b'{"type":"status","qid":"missing"}\n',
                       b'{"x":1,"x":2}\n', b'\xff\n', b'{"n":NaN}\n',
                       json.dumps({"version": 2, "type": "status", "ts": "now", "qid": qid,
                                   "previous": "pending", "status": "released"}).encode() + b'\n']
        for suffix in corruptions:
            with self.subTest(suffix=suffix):
                path.write_bytes(original + suffix)
                self.assertEqual(self.release(qid)["exit"], 2)
                with self.assertRaises(StateError):
                    self.entry()
                self.assertEqual(path.read_bytes(), original + suffix)
        self.assertEqual(len(self.effects()), 0)

    def test_excessive_depth_cannot_poison_new_journal(self):
        nested = "value"
        for _ in range(45):
            nested = {"nested": nested}
        self.request["params"]["arguments"]["nested"] = nested
        with self.assertRaises(StateError):
            self.entry()
        self.assertEqual(self.store.quarantine_entries(), [])

    def test_valid_gateway_depth_fits_journal_envelope(self):
        nested = "value"
        for _ in range(28):
            nested = {"nested": nested}
        self.request["params"]["arguments"]["nested"] = nested
        qid = self.entry()
        self.assertEqual(self.store.quarantine_entries()[0]["qid"], qid)

    def test_concurrent_quarantine_writers_preserve_all_entries(self):
        program = (
            "import json,sys; from memwall.state import StateStore; "
            "s=StateStore(sys.argv[1]); r=json.loads(sys.argv[2]); "
            "[s.quarantine('add_observations',r,[]) for _ in range(12)]"
        )
        procs = [subprocess.Popen([sys.executable, "-c", program, str(self.state), json.dumps(self.request)],
                                 cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        for proc in procs:
            out, err = proc.communicate(timeout=15)
            self.assertEqual(proc.returncode, 0, (out, err))
        entries = self.store.quarantine_entries()
        self.assertEqual(len(entries), 24)
        self.assertEqual(len({e["qid"] for e in entries}), 24)
