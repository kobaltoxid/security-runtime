from pathlib import Path
import unittest
from unittest.mock import patch

import main


class MainTests(unittest.TestCase):
    def test_scan_dispatches_with_options_after_the_command(self):
        with patch.object(main.runtime, "run_command", return_value=1) as run:
            exit_code = main.main([
                "scan", "--state", ".state", "checkout", "--stream", "project-main",
                "--trigger", "push", "--revision", "test-commit",
            ])
        self.assertEqual(1, exit_code)
        args, = run.call_args.args
        self.assertEqual(("scan", "checkout", "project-main"), (args.command, args.target, args.stream))
        self.assertEqual((".state", "push", "test-commit"), (str(args.state), args.trigger, args.revision))

    def test_watch_dispatches_to_the_scan_runner(self):
        with patch.object(main.runtime, "run_command", return_value=0) as run:
            self.assertEqual(0, main.main(["watch", "checkout", "--stream", "example", "--interval", "10", "--once"]))
        args, = run.call_args.args
        self.assertEqual(("watch", 10.0, True), (args.command, args.interval, args.once))

    def test_triage_passes_the_requested_provider_and_checkpoint(self):
        with patch.object(main.triage, "run_command", return_value=130) as run:
            exit_code = main.main([
                "triage", "reports", "--db", "review.sqlite3", "--provider", "claude-oauth", "--step",
            ])
        self.assertEqual(130, exit_code)
        args, _parser = run.call_args.args
        self.assertEqual(("reports", Path("review.sqlite3"), "claude-oauth", True),
                         (args.artifact_dir, args.db, args.provider, args.step))


if __name__ == "__main__":
    unittest.main()
