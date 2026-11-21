import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / ".github" / "scripts"))
import select_pr_triage as selector


class SelectorTests(unittest.TestCase):
    def setUp(self):
        self.sha = "a" * 40
        self.pr = {
            "number": 2,
            "state": "open",
            "head": {"sha": self.sha, "repo": {"full_name": selector.REPOSITORY}},
            "base": {"ref": "main", "repo": {"full_name": selector.REPOSITORY}},
            "labels": [{"name": selector.OPT_IN_LABEL}],
        }
        candidates = patch.object(selector, "_candidate_issues", return_value=[{"number": 2}])
        candidates.start()
        self.addCleanup(candidates.stop)

    def test_unlabeled_pr_skips_scan_lookup(self):
        self.pr["labels"] = []
        with patch.object(selector, "gh_api", return_value=self.pr), patch.object(selector, "_latest_scan") as scan:
            self.assertIsNone(selector.select())
            scan.assert_not_called()

    def test_completed_commit_skips_scan_lookup(self):
        with (
            patch.object(selector, "gh_api", return_value=self.pr),
            patch.object(selector, "_live_receipt", return_value=True) as receipt,
            patch.object(selector, "_latest_scan") as scan,
        ):
            self.assertIsNone(selector.select())
            receipt.assert_called_once_with(f"triage-pr-2-{self.sha}")
            scan.assert_not_called()

    def test_select_returns_only_a_ready_scan(self):
        with patch.object(selector, "gh_api", return_value=self.pr), patch.object(selector, "_live_receipt", return_value=False):
            for result in (None, 123):
                with self.subTest(result=result), patch.object(selector, "_latest_scan", return_value=result) as scan:
                    self.assertEqual(result, selector.select())
                    scan.assert_called_once_with(2, self.sha)

    def test_scan_for_another_head_is_ignored(self):
        with (
            patch.object(selector, "gh_api", return_value={"workflow_runs": [{"id": 123}]}) as api,
            patch.object(selector, "_validate_run", return_value=(2, 1, "b" * 40)),
        ):
            self.assertIsNone(selector._latest_scan(2, self.sha))
            self.assertEqual(1, api.call_count)


if __name__ == "__main__":
    unittest.main()
