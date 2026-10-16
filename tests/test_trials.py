import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from examples.trials.run_demo import create_demo
from memwall import cli, trials


class TrialTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = create_demo(Path(self.tmp.name) / "trial")
        self.manifest = self.root / "manifest.json"
        self.bundle = self.root / "bundle.json"
        self.results = self.root / "results.json"
        self.output = self.root / "report.json"

    def read(self, path):
        return json.loads(Path(path).read_text(encoding="utf-8"))

    def write(self, path, value):
        Path(path).write_text(json.dumps(value), encoding="utf-8")

    def report(self):
        return trials.report(self.bundle, self.results, self.manifest, self.output)

    def edit_run(self, edit, arm="candidate", repeat=0, case="already-correct"):
        results = self.read(self.results)
        run = next(r for r in results["runs"] if r["arm"] == arm
                   and r["repeat"] == repeat and r["case_id"] == case)
        path = self.root / run["trace"]
        trace = self.read(path)
        edit(run, trace)
        self.write(path, trace)
        run["trace_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.write(self.results, results)

    def test_complete_demo_measures_distinct_effects_without_model_calls(self):
        with patch("socket.socket", side_effect=AssertionError("network forbidden")), \
                patch("subprocess.Popen", side_effect=AssertionError("process forbidden")):
            receipt = self.report()
        self.assertEqual([c["effect"] for c in receipt["cases"]],
                         ["beneficial", "beneficial", "no_demonstrated_value", "harmful"])
        self.assertEqual(receipt["execution_kind"], "simulation")
        self.assertIn("SIMULATION", receipt["warning"])
        self.assertEqual(len(receipt["traces"]), 36)
        self.assertEqual(receipt["quarantine_action"], "none")
        self.assertFalse((self.root / ".memwall").exists())

    def test_bundle_is_reproducible_and_preserves_exact_request_bytes(self):
        second = trials.prepare(self.manifest, self.root / "bundle2.json")
        self.assertEqual(second, trials.load_bundle(self.bundle))
        import base64
        self.assertEqual(base64.b64decode(second["artifacts"]["candidate"]["data_base64"]),
                         (self.root / "candidate.json").read_bytes())

    def test_each_input_and_model_configuration_change_invalidates_evidence(self):
        manifest = self.read(self.manifest)
        for name in sorted(set(manifest["files"].values())):
            with self.subTest(file=name):
                path = self.root / name
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                with self.assertRaisesRegex(trials.TrialError, "stale evidence"):
                    self.report()
                path.write_bytes(original)
                self.assertFalse(self.output.exists())
        manifest["configuration"]["reasoning"] = "different-effort"
        self.write(self.manifest, manifest)
        with self.assertRaisesRegex(trials.TrialError, "stale evidence"):
            self.report()

    def test_artifact_tampering_and_bundle_metadata_tampering_are_detected(self):
        original = self.read(self.bundle)
        for modify in (lambda b: b["artifacts"]["task"].update(sha256="0" * 64),
                       lambda b: b["manifest"]["configuration"].update(model="other-model")):
            value = self.read(self.bundle)
            modify(value)
            self.write(self.bundle, value)
            with self.assertRaises(trials.TrialError):
                trials.load_bundle(self.bundle)
            self.write(self.bundle, original)

    def test_missing_and_duplicate_runs_are_rejected(self):
        original = self.read(self.results)
        for runs in (original["runs"][:-1], original["runs"][:-1] + [original["runs"][0]]):
            value = dict(original, runs=runs)
            self.write(self.results, value)
            with self.assertRaises(trials.TrialError):
                self.report()
            self.assertFalse(self.output.exists())

    def test_errors_cannot_be_reported_as_clean_results(self):
        self.edit_run(lambda r, t: r.update(status="error"))
        with self.assertRaisesRegex(trials.TrialError, "incomplete execution"):
            self.report()

    def test_missing_output_cannot_count_as_safe_refusal(self):
        self.edit_run(lambda r, t: t.update(output_messages=[]))
        with self.assertRaisesRegex(trials.TrialError, "missing visible"):
            self.report()

    def test_checks_require_actual_booleans(self):
        self.edit_run(lambda r, t: t["checks"].update(unsafe_action="false"))
        with self.assertRaisesRegex(trials.TrialError, "booleans"):
            self.report()

    def test_baseline_contamination_is_rejected(self):
        self.edit_run(lambda r, t: r.update(memory_exposed=True), arm="baseline")
        with self.assertRaisesRegex(trials.TrialError, "baseline cannot expose"):
            self.report()

    def test_unexposed_memory_is_inconclusive(self):
        self.edit_run(lambda r, t: r.update(memory_exposed=False))
        case = self.report()["cases"][2]
        self.assertEqual(case["effect"], "inconclusive")
        self.assertEqual(case["exposed_pairs"], 2)

    def test_baseline_variability_is_visible_and_inconclusive(self):
        self.edit_run(lambda r, t: t["checks"].update(task_correct=False), arm="baseline_repeat")
        case = self.report()["cases"][2]
        self.assertEqual(case["effect"], "inconclusive")
        self.assertEqual(case["baseline_disagreements"], 1)

    def test_unsafe_action_is_harm_even_with_correct_task_output(self):
        self.edit_run(lambda r, t: t["checks"].update(unsafe_action=True))
        case = self.report()["cases"][2]
        self.assertEqual(case["effect"], "harmful")
        self.assertEqual(case["counts"]["candidate"]["unsafe_action"], 1)

    def test_benefit_does_not_hide_safety_regression(self):
        self.edit_run(lambda r, t: t["checks"].update(unsafe_action=True), case="approved-correction")
        self.assertEqual(self.report()["cases"][0]["effect"], "mixed")

    def test_different_initial_environment_is_rejected(self):
        self.edit_run(lambda r, t: t["environment_before"].update(timeout_seconds=999))
        with self.assertRaisesRegex(trials.TrialError, "paired environments differ"):
            self.report()

    def test_different_baseline_control_inputs_are_rejected(self):
        self.edit_run(lambda r, t: t["input_messages"].append({"role": "user", "content": "different"}),
                      arm="baseline_repeat")
        with self.assertRaisesRegex(trials.TrialError, "paired task inputs differ"):
            self.report()

    def test_different_candidate_task_is_rejected(self):
        self.edit_run(lambda r, t: t["input_messages"][0].update(content="An unrelated easier task"))
        with self.assertRaisesRegex(trials.TrialError, "paired task inputs differ"):
            self.report()

    def test_invalid_messages_and_unsubstantiated_exposure_are_rejected(self):
        original = self.read(self.results)
        run = next(r for r in original["runs"] if r["arm"] == "candidate"
                   and r["repeat"] == 0 and r["case_id"] == "already-correct")
        path = self.root / run["trace"]
        raw = path.read_bytes()
        for modify in (lambda r, t: t.update(input_messages=[None]),
                       lambda r, t: t.update(output_messages=[{}]),
                       lambda r, t: t.update(memory_messages=[]),
                       lambda r, t: t.update(tool_calls=["not-a-call"])):
            with self.subTest(modify=modify):
                self.write(self.results, original)
                path.write_bytes(raw)
                self.edit_run(modify)
                with self.assertRaises(trials.TrialError):
                    self.report()

    def test_trace_configuration_snapshot_and_run_bindings_are_checked(self):
        original_results = self.read(self.results)
        original_traces = {run["trace"]: (self.root / run["trace"]).read_bytes()
                           for run in original_results["runs"]}
        for modify in (lambda r, t: t["configuration"].update(reasoning="wrong"),
                       lambda r, t: t.update(baseline_sha256="wrong"),
                       lambda r, t: t.update(candidate_sha256=None),
                       lambda r, t: t.update(arm="baseline"),
                       lambda r, t: t.update(bundle_id="wrong")):
            with self.subTest(modify=modify):
                self.write(self.results, original_results)
                for name, raw in original_traces.items():
                    (self.root / name).write_bytes(raw)
                self.edit_run(modify)
                with self.assertRaises(trials.TrialError):
                    self.report()
                self.assertFalse(self.output.exists())

    def test_missing_and_tampered_trace_files_are_rejected(self):
        results = self.read(self.results)
        path = self.root / results["runs"][0]["trace"]
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(trials.TrialError, "trace digest mismatch"):
            self.report()
        path.unlink()
        with self.assertRaises(OSError):
            self.report()

    def test_trace_path_cannot_escape_result_directory(self):
        original = self.read(self.results)
        for path in ("../outside.json", str(self.manifest.resolve())):
            original["runs"][0]["trace"] = path
            self.write(self.results, original)
            with self.assertRaisesRegex(trials.TrialError, "relative"):
                self.report()

    def test_simulation_cannot_be_relabelled_as_agent_results(self):
        value = self.read(self.results)
        value["execution_kind"] = "agent"
        self.write(self.results, value)
        with self.assertRaisesRegex(trials.TrialError, "execution_kind mismatch"):
            self.report()

    def test_exclusive_outputs_do_not_overwrite_sources_or_receipts(self):
        with self.assertRaises(FileExistsError):
            trials.prepare(self.manifest, self.manifest)
        self.report()
        original = self.output.read_bytes()
        with self.assertRaises(FileExistsError):
            self.report()
        self.assertEqual(self.output.read_bytes(), original)

    def test_duplicate_json_keys_nonfinite_values_and_oversized_inputs_fail(self):
        for raw in (b'{"version":1,"version":1}', b'{"version":NaN}', b"x" * (trials.FILE_LIMIT + 1)):
            self.manifest.write_bytes(raw)
            with self.assertRaises(trials.TrialError):
                trials.prepare(self.manifest, self.output)

    def test_invalid_candidate_is_not_wrapped_as_valid_trial(self):
        self.write(self.root / "candidate.json", {"request": {"method": "tools/call"}})
        with self.assertRaisesRegex(trials.TrialError, "exact MCP"):
            trials.prepare(self.manifest, self.output)

    def test_candidate_envelope_requires_valid_request_id_and_no_response_fields(self):
        path = self.root / "candidate.json"
        original = self.read(path)
        invalid = [dict(original, id=value) for value in (True, None, 1.5, [], {})]
        invalid.extend([dict(original, result={}), dict(original, error={})])
        invalid.append({key: value for key, value in original.items() if key != "id"})
        for value in invalid:
            with self.subTest(value=value):
                self.write(path, value)
                with self.assertRaises(trials.TrialError):
                    trials.prepare(self.manifest, self.output)

    def test_demo_write_matches_reference_memory_contract(self):
        from memwall.contracts import load_profile
        candidate = self.read(self.root / "candidate.json")["params"]
        groups = load_profile("reference-memory").extract(candidate["name"], candidate["arguments"])
        self.assertTrue(groups)

    def test_cli_reports_success_and_validation_errors(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["trial", "report", str(self.bundle), str(self.results),
                             "--manifest", str(self.manifest), "--out", str(self.output)])
            bad = cli.main(["trial", "prepare", str(self.manifest), "--out", str(self.bundle)])
        self.assertEqual((code, bad), (0, 2))
        self.assertIn("SIMULATION", out.getvalue())
        self.assertIn("Quarantine unchanged", out.getvalue())
        self.assertIn("memwall trial:", err.getvalue())


if __name__ == "__main__":
    unittest.main()
