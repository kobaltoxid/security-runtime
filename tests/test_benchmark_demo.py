import json
import tempfile
import unittest
from pathlib import Path

from benchmarks.demo import run


class BenchmarkDemoTests(unittest.TestCase):
    def test_demo_writes_bundles_and_real_gate_results(self):
        with tempfile.TemporaryDirectory() as directory:
            comparison = run(Path(directory))
            self.assertEqual(2, comparison["modes"]["gated"]["counts"]["total"])
            self.assertEqual(1.0, comparison["modes"]["gated"]["accuracy"])
            self.assertEqual(1, comparison["modes"]["gated"]["counts"]["abstentions"])
            self.assertEqual(5, comparison["modes"]["gated"]["model_calls"])
            self.assertEqual("0", comparison["modes"]["gated"]["known_cost_total_usd"])
            self.assertTrue((Path(directory) / "source" / "checks.json").is_file())
            artifact = json.loads((Path(directory) / "artifact" / "checks.json").read_text())
            self.assertEqual([], artifact["results"])
            runs = json.loads((Path(directory) / "runs.json").read_text())
            self.assertEqual(["evidence_supports_report", "insufficient_evidence"],
                             [entry["verdict"] for entry in runs["runs"]["gated"]])
            self.assertEqual([3, 2], [entry["model_calls"] for entry in runs["runs"]["gated"]])
            self.assertEqual(["evidence_conflicts_with_report", "evidence_supports_report"],
                             [entry["verdict"] for entry in runs["runs"]["one_shot"]])
            self.assertEqual([1, 1], [entry["unsupported_claims"] for entry in runs["runs"]["one_shot"]])
            self.assertTrue((Path(directory) / "source" / "triage.db").is_file())
            self.assertTrue((Path(directory) / "artifact" / "triage.db").is_file())

    def test_nonempty_output_is_refused_without_overwriting(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "keep.txt"
            marker.write_text("preserve")
            with self.assertRaises(ValueError):
                run(directory)
            self.assertEqual("preserve", marker.read_text())


if __name__ == "__main__":
    unittest.main()
