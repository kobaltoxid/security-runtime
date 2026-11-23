import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from benchmarks import demo, run as runner
from benchmarks.score import score
from security_runtime import triage_model


class ScriptedModel:
    """One-shot gets a conflicting verdict; the gated loop inspects checks and then agrees with them."""

    def __init__(self):
        self.calls = []

    def __call__(self, model, request, **kwargs):
        self.calls.append(request)
        if request["available_actions"] == ["finish"] and "gate_feedback" not in request:
            return {"action": "finish", "verdict": "evidence_conflicts_with_report",
                    "evidence_refs": sorted(request["observations"]), "reason": "scripted one-shot"}
        if "checks" not in request["observations"]:
            return {"action": "inspect_checks"}
        return {"action": "finish", "verdict": "evidence_supports_report",
                "evidence_refs": ["checks"], "reason": "scripted gated"}


class BenchmarkRunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        demo._write_bundles(self.root)
        self.labels = {"schema_version": 1, "dataset_id": "test-v1", "cases": [
            {"id": "src", "target_kind": "source", "expected_verdict": "evidence_supports_report",
             "scan_dir": "source", "advisory": "SYNTH-001"},
            {"id": "art", "target_kind": "artifact", "expected_verdict": "insufficient_evidence",
             "scan_dir": "artifact", "advisory": "SYNTH-001"},
        ]}
        self.labels_path = self.root / "labels.json"
        self.labels_path.write_text(json.dumps(self.labels))
        self.model = ScriptedModel()

    def run_benchmark(self):
        with patch.object(triage_model, "choose", self.model):
            return runner.run(self.labels_path, self.root, self.root / "out", "haiku", "claude2")

    def entry(self, result, mode, case_id):
        return next(item for item in result["runs"][mode] if item["id"] == case_id)

    def test_runs_validate_against_the_scorer(self):
        result = self.run_benchmark()
        comparison = score(self.labels, json.loads((self.root / "out" / "runs.json").read_text()))
        self.assertEqual(comparison["modes"]["gated"]["counts"]["correct"], 2)
        self.assertEqual(self.entry(result, "secdepth", "src")["model_calls"], 0)

    def test_one_shot_counts_a_verdict_the_checks_do_not_support(self):
        result = self.run_benchmark()
        one_shot = self.entry(result, "one_shot", "src")
        self.assertEqual((one_shot["verdict"], one_shot["unsupported_claims"], one_shot["model_calls"]),
                         ("evidence_conflicts_with_report", 1, 1))
        gated = self.entry(result, "gated", "src")
        self.assertEqual((gated["verdict"], gated["unsupported_claims"]), ("evidence_supports_report", 0))

    def test_missing_checks_end_as_insufficient_evidence(self):
        result = self.run_benchmark()
        self.assertEqual(self.entry(result, "gated", "art")["verdict"], "insufficient_evidence")

    def test_rerun_reuses_saved_cases_without_model_calls(self):
        self.run_benchmark()
        first = len(self.model.calls)
        self.run_benchmark()
        self.assertEqual(len(self.model.calls), first)


if __name__ == "__main__":
    unittest.main()
