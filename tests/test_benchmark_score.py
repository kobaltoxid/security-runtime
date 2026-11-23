import unittest

from benchmarks.score import InputError, score


def labels(ids=("a", "b")):
    return {"schema_version": 1, "dataset_id": "demo", "cases": [
        {"id": case_id, "target_kind": "source", "expected_verdict": "evidence_supports_report"}
        for case_id in ids
    ]}


def runs(ids=("a", "b"), cost=None):
    def result(case_id):
        return {"id": case_id, "verdict": "evidence_supports_report", "unsupported_claims": 1,
                "elapsed_ms": 5, "model_calls": 2, "cost_usd": cost}

    return {"schema_version": 1, "dataset_id": "demo", "runs": {
        "secdepth": [result(case_id) for case_id in ids],
        "one_shot": [result(case_id) for case_id in ids],
        "gated": [result(case_id) for case_id in ids],
    }}


class BenchmarkScoreTests(unittest.TestCase):
    def test_aligned_runs_are_scored_deterministically(self):
        output = score(labels(), runs(cost="0.10"))
        self.assertEqual("demo", output["dataset_id"])
        self.assertEqual(1.0, output["modes"]["gated"]["accuracy"])
        self.assertEqual("0.20", output["modes"]["gated"]["known_cost_total_usd"])
        self.assertEqual("source", output["modes"]["gated"]["cases"][0]["target_kind"])

    def test_abstentions_and_unknown_costs_are_reported(self):
        data = runs(ids=("a", "b"))
        data["runs"]["gated"][1]["verdict"] = "insufficient_evidence"
        output = score(labels(), data)["modes"]["gated"]
        self.assertEqual(1, output["counts"]["abstentions"])
        self.assertEqual(0.5, output["accuracy"])
        self.assertEqual(1.0, output["answered_accuracy"])
        self.assertIsNone(output["known_cost_total_usd"])

    def test_duplicate_or_mismatched_case_sets_are_rejected(self):
        with self.assertRaises(InputError):
            score(labels(), runs(ids=("a", "a")))
        with self.assertRaises(InputError):
            score(labels(), runs(ids=("a",)))
        different_dataset = runs()
        different_dataset["dataset_id"] = "other"
        with self.assertRaises(InputError):
            score(labels(), different_dataset)


if __name__ == "__main__":
    unittest.main()
