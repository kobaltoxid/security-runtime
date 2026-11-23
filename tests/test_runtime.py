import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from security_runtime import runtime


SCANNER = """\
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('target', type=Path)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--offline', action='store_true')
args = parser.parse_args()
scenario = json.loads(args.target.read_text())
if scenario is None:
    print('injected scanner failure')
    raise SystemExit(2)
scenario['report']['target']['offline'] = args.offline
(args.output / 'report.json').write_text(json.dumps(scenario))
(args.output / 'report.html').write_text('<!doctype html><title>Test report</title>')
"""


def finding(advisory, reachability="conditional"):
    return {
        "id": advisory,
        "affected_component_ids": ["npm:example@1.0.0"],
        "applicability": "affected",
        "exploitability": {"reachability": reachability},
        "review": {"needed": reachability == "conditional"},
    }


class RuntimeTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.state = root / "state"
        self.target = root / "target.json"
        self.scanner = root / "scanner.py"
        self.scanner.write_text(SCANNER, encoding="utf-8")
        self.options = ["--state", str(self.state), "--scanner", str(self.scanner)]

    def prepare(self, *findings, failures=()):
        report = {
            "report": {"target": {
                "coverage_complete": True,
                "coverage": {},
                "lookup_failures": list(failures),
                "not_queried": [],
            }},
            "vulnerabilities": list(findings),
        }
        self.target.write_text(json.dumps(report), encoding="utf-8")

    def invoke(self, command, *options):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = runtime.main([*self.options, command, str(self.target), "--stream", "example", *options])
        return code, [json.loads(line) for line in stdout.getvalue().splitlines()]

    def run_once(self, revision, *options):
        code, (run,) = self.invoke("run", "--trigger", "push", "--revision", revision, *options)
        return code, run

    def run_dir(self, run):
        return self.state / "example" / "runs" / run["run_id"]

    def test_partial_and_failed_runs_preserve_baseline(self):
        self.prepare(finding("advisory-a"), finding("advisory-b"))
        code, first = self.run_once("initial")
        self.assertEqual((0, "complete"), (code, first["status"]))
        self.assertEqual(["advisory-a", "advisory-b"], first["diff"]["new"])
        self.assertTrue((self.run_dir(first) / "report.html").is_file())
        self.assertEqual(first, json.loads((self.run_dir(first) / "summary.json").read_text()))

        failures = [{"advisory": "advisory-a", "reason": "unavailable"}]
        self.prepare(finding("advisory-c"), failures=failures)
        _, partial = self.run_once("partial")
        self.assertEqual("partial", partial["status"])
        self.assertEqual(failures, partial["lookup_failures"])
        self.assertEqual(["advisory-c"], partial["diff"]["new"])
        self.assertEqual([], partial["diff"]["missing"])
        self.assertTrue(partial["diff"]["missing_suppressed"])

        _, repeated = self.run_once("partial")
        self.assertEqual("partial", repeated["status"])
        self.assertEqual([], repeated["diff"]["new"])
        self.assertEqual([], repeated["diff"]["missing"])

        self.target.write_text("null", encoding="utf-8")
        code, failed = self.run_once("failed")
        self.assertNotEqual(0, code)
        self.assertEqual("failed", failed["status"])
        self.assertIn("injected scanner failure", (self.run_dir(failed) / "scan.log").read_text())

        self.prepare(finding("advisory-a", "reachable"), finding("advisory-c"))
        code, last = self.run_once("recovered")
        self.assertEqual((0, "complete"), (code, last["status"]))
        self.assertEqual([], last["diff"]["new"])
        self.assertEqual(["advisory-a"], last["diff"]["changed"])
        self.assertEqual(["advisory-b"], last["diff"]["missing"])

    def test_cache_only_result_cannot_claim_a_missing_finding(self):
        self.prepare(finding("advisory-a"))
        self.run_once("online")

        self.prepare()
        code, offline = self.run_once("offline", "--offline")
        self.assertEqual((0, "partial"), (code, offline["status"]))
        self.assertEqual([], offline["diff"]["missing"])
        self.assertTrue(offline["diff"]["missing_suppressed"])

    def test_repeat_event_is_deduplicated_but_scheduled_scan_is_fresh(self):
        self.prepare(finding("advisory-a"))
        _, first = self.run_once("unchanged")

        self.prepare(finding("advisory-a"), finding("advisory-b"))
        code, repeat = self.run_once("unchanged")
        self.assertEqual((0, "deduplicated"), (code, repeat["status"]))

        code, (scheduled,) = self.invoke("run", "--trigger", "scheduled", "--revision", "unchanged")
        self.assertEqual((0, "complete"), (code, scheduled["status"]))
        self.assertNotEqual(first["run_id"], scheduled["run_id"])
        self.assertEqual(["advisory-b"], scheduled["diff"]["new"])

    def test_watch_scans_immediately_and_retries_after_failure(self):
        self.target.write_text("null", encoding="utf-8")
        waits = []

        def sleep(seconds):
            waits.append(seconds)
            if len(waits) == 1:
                self.prepare()
            else:
                raise KeyboardInterrupt

        with patch.object(runtime, "time", SimpleNamespace(sleep=sleep)):
            code, runs = self.invoke("watch", "--interval", "5")
        self.assertEqual(130, code)
        self.assertEqual(["failed", "complete"], [run["status"] for run in runs])
        self.assertEqual(["scheduled", "scheduled"], [run["trigger"] for run in runs])
        self.assertEqual([5, 5], waits)


if __name__ == "__main__":
    unittest.main()
