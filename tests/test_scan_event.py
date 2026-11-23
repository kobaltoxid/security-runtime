import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / ".github" / "scripts"))
import scan_event as target


def git_checkout(directory, files):
    for name, text in files.items():
        (directory / name).write_text(text)
    environment = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
    for command in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "fixture"]):
        subprocess.run(["git", "-C", str(directory), *command], check=True, env=environment)
    return subprocess.run(["git", "-C", str(directory), "rev-parse", "HEAD"],
                          check=True, capture_output=True, text=True).stdout.strip()


class ResolveSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.source = Path(self.tmp.name)
        self.sha = git_checkout(self.source, {"go.mod": "module x\n", "go.sum": ""})

    def tearDown(self):
        self.tmp.cleanup()

    def test_push_uses_branch_stream_and_commit(self):
        result = target.resolve_source("push", "Feature/Login", self.sha, self.source, "go")
        self.assertEqual(result["stream"], "branch-feature-login")
        self.assertEqual(result["trigger"], "push")
        self.assertEqual(result["revision"], self.sha)

    def test_schedule_shares_the_branch_stream(self):
        result = target.resolve_source("schedule", "main", self.sha, self.source, "go")
        self.assertEqual((result["stream"], result["trigger"]), ("branch-main", "scheduled"))

    def test_rejects_a_different_head(self):
        with self.assertRaisesRegex(target.InputError, "did not match"):
            target.resolve_source("push", "main", "f" * 40, self.source, "go")

    def test_rejects_pull_request_events(self):
        with self.assertRaisesRegex(target.InputError, "pull_request"):
            target.resolve_source("pull_request", "main", self.sha, self.source, "go")

    def test_rejects_a_symlinked_manifest(self):
        (self.source / "go.sum").unlink()
        (self.source / "go.sum").symlink_to(self.source / "go.mod")
        with self.assertRaisesRegex(target.InputError, "go.sum is not a regular file"):
            target.resolve_source("push", "main", self.sha, self.source, "go")

    def test_npm_requires_a_lockfile(self):
        (self.source / "package.json").write_text("{}")
        with self.assertRaisesRegex(target.InputError, "no usable npm lockfile"):
            target.resolve_source("push", "main", self.sha, self.source, "npm")
        (self.source / "package-lock.json").write_text("{}")
        self.assertEqual(target.resolve_source("push", "main", self.sha, self.source, "npm")["revision"], self.sha)


class ResolveReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.artifact = self.root / "dist"
        self.artifact.mkdir()
        (self.artifact / "App-Linux.tar.gz").write_bytes(b"release bytes")

    def tearDown(self):
        self.tmp.cleanup()

    def test_records_the_artifact_digest(self):
        result = target.resolve_release("release", self.artifact, "App-Linux.tar.gz")
        self.assertEqual(result["revision"], "sha256:" + hashlib.sha256(b"release bytes").hexdigest())
        self.assertEqual((result["stream"], result["trigger"]), ("release-app-linux.tar.gz", "release"))

    def test_rejects_paths_outside_the_artifact(self):
        (self.root / "outside").write_bytes(b"x")
        for name in ("../outside", str(self.root / "outside"), "x\nstream=evil"):
            with self.subTest(name=name), self.assertRaises(target.InputError):
                target.resolve_release("release", self.artifact, name)

    def test_rejects_a_symlinked_artifact(self):
        (self.root / "outside").write_bytes(b"x")
        (self.artifact / "link").symlink_to(self.root / "outside")
        with self.assertRaisesRegex(target.InputError, "not a regular file"):
            target.resolve_release("release", self.artifact, "link")


class MainTests(unittest.TestCase):
    def test_stream_override_is_validated(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp)
            (artifact / "app").write_bytes(b"x")
            output = artifact / "out"
            self.assertEqual(target.main(["resolve", "--event", "release", "--release-dir", tmp,
                                          "--release-file", "app", "--stream", "Bad Stream"]), 1)
            self.assertEqual(target.main(["resolve", "--event", "release", "--release-dir", tmp,
                                          "--release-file", "app", "--stream", "release-app-linux",
                                          "--github-output", str(output)]), 0)
            self.assertIn("stream=release-app-linux\n", output.read_text())

    def test_summarize_reports_the_diff_and_run_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            summary = {"status": "complete", "stream": "branch-main", "run_id": "000000000002",
                       "trigger": "scheduled", "revision": "a" * 40,
                       "diff": {"new": ["GHSA-1"], "changed": [], "missing": [], "missing_suppressed": False}}
            (root / "summary.json").write_text(json.dumps(summary) + "\n")
            output, step = root / "out", root / "step.md"
            code = target.main(["summarize", str(root / "summary.json"), "--state", str(root / "state"),
                                "--github-output", str(output), "--step-summary", str(step)])
            self.assertEqual(code, 0)
            self.assertIn(f"run_dir={root / 'state' / 'branch-main' / 'runs' / '000000000002'}\n", output.read_text())
            self.assertIn("New findings: 1", step.read_text())


if __name__ == "__main__":
    unittest.main()
