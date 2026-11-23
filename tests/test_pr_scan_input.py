import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / ".github" / "scripts"))
import pr_scan_input as target


def archive(run_id=425513024, attempt=1, sha="a" * 40, pr=7):
    entries = {
        "report.json": {"report": {}, "vulnerabilities": [], "components": []},
        "checks.json": {"results": []},
        "run.json": {"ecosystem": "go", "pull_request": pr, "head_sha": sha,
                      "run_id": run_id, "run_attempt": attempt},
    }
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as zf:
        for name, value in entries.items():
            zf.writestr(name, json.dumps(value))
    return stream.getvalue()


class PrScanInputTests(unittest.TestCase):
    def setUp(self):
        self.run_id = 99
        self.sha = "a" * 40
        self.pr = 7
        self.data = archive(self.run_id, 1, self.sha, self.pr)
        self.responses = {
            f"repos/{target.REPOSITORY}/actions/runs/{self.run_id}": {
                "id": self.run_id, "workflow_id": target.WORKFLOW_ID,
                "path": target.WORKFLOW_PATH, "event": "pull_request",
                "status": "completed", "conclusion": "success",
                "head_repository": {"full_name": target.REPOSITORY}, "head_sha": self.sha,
                "run_attempt": 1, "pull_requests": [{"number": self.pr, "head": {"sha": self.sha}}],
                "referenced_workflows": [{"path": target.SCANNER_REF, "sha": target.SCANNER_SHA}]},
            f"repos/{target.REPOSITORY}/pulls/{self.pr}": {
                "number": self.pr, "state": "open", "head": {"sha": self.sha, "repo": {"full_name": target.REPOSITORY}},
                "base": {"ref": "main", "repo": {"full_name": target.REPOSITORY}}},
            f"repos/{target.REPOSITORY}/contents/{target.WORKFLOW_PATH}?ref={self.sha}": {
                "sha": target.CALLER_BLOB},
            f"repos/{target.REPOSITORY}/actions/runs/{self.run_id}/artifacts": {
                "artifacts": [{"id": 123, "name": f"secdepth-pr-{self.pr}-{self.run_id}-1",
                               "expired": False, "expires_at": "2099-01-01T00:00:00Z",
                               "size_in_bytes": len(self.data),
                               "digest": "sha256:" + hashlib.sha256(self.data).hexdigest()}]},
        }

    def fake_run(self, argv, **kwargs):
        path = argv[2]
        if path.endswith("/zip"):
            output = self.data
        else:
            output = json.dumps(self.responses[path]).encode()
        class Result:
            stdout = output
            stderr = b""
        return Result()

    def test_fetch_writes_only_normalized_outputs(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"GH_TOKEN": "test"}), \
             patch.object(target.subprocess, "run", side_effect=self.fake_run):
            target.fetch(str(self.run_id), Path(directory))
            self.assertEqual(sorted(os.listdir(directory)), ["checks.json", "report.json", "source.json"])
            source = json.loads(Path(directory, "source.json").read_text())
            self.assertEqual(source["head_sha"], self.sha)
            self.assertEqual(source["scanner_workflow"], target.SCANNER_REF)

    def test_rejects_provenance_mismatch(self):
        self.responses[next(k for k in self.responses if "/runs/" in k)]["head_sha"] = "b" * 40
        with patch.dict(os.environ, {"GH_TOKEN": "test"}), patch.object(target.subprocess, "run", side_effect=self.fake_run):
            with self.assertRaises(target.InputError):
                target.fetch(str(self.run_id), Path(tempfile.mkdtemp()))

    def test_rejects_an_unapproved_reusable_workflow(self):
        run_path = f"repos/{target.REPOSITORY}/actions/runs/{self.run_id}"
        self.responses[run_path]["referenced_workflows"][0]["sha"] = "0" * 40
        with tempfile.TemporaryDirectory() as directory, patch.object(target.subprocess, "run", side_effect=self.fake_run):
            with self.assertRaisesRegex(target.InputError, "trusted scanner"):
                target.fetch(str(self.run_id), Path(directory))

    def test_rejects_expired_artifact(self):
        artifact_path = next(k for k in self.responses if k.endswith("/artifacts"))
        self.responses[artifact_path]["artifacts"][0]["expired"] = True
        with patch.dict(os.environ, {"GH_TOKEN": "test"}), patch.object(target.subprocess, "run", side_effect=self.fake_run):
            with self.assertRaisesRegex(target.InputError, "expired"):
                target.fetch(str(self.run_id), Path(tempfile.mkdtemp()))

    def test_rejects_corrupt_artifact_digest(self):
        artifact_path = next(k for k in self.responses if k.endswith("/artifacts"))
        self.responses[artifact_path]["artifacts"][0]["digest"] = "sha256:" + "0" * 64
        with patch.dict(os.environ, {"GH_TOKEN": "test"}), patch.object(target.subprocess, "run", side_effect=self.fake_run):
            with self.assertRaisesRegex(target.InputError, "SHA256"):
                target.fetch(str(self.run_id), Path(tempfile.mkdtemp()))

    def test_opt_in_is_rechecked_before_import_and_receipt(self):
        pr = self.responses[f"repos/{target.REPOSITORY}/pulls/{self.pr}"]
        with tempfile.TemporaryDirectory() as directory, patch.object(target.subprocess, "run", side_effect=self.fake_run):
            root = Path(directory)
            output = root / "github-output"
            with self.assertRaisesRegex(target.InputError, "not opted in"):
                target.fetch(str(self.run_id), root / "handoff", require_opt_in=True, github_output=output)
            self.assertFalse(output.exists())
            self.assertFalse((root / "handoff").exists())

            pr["labels"] = [{"name": target.OPT_IN_LABEL}]
            target.fetch(str(self.run_id), root / "handoff", require_opt_in=True, github_output=output)
            self.assertEqual(f"receipt_name=triage-pr-{self.pr}-{self.sha}\n", output.read_text())


if __name__ == "__main__":
    unittest.main()
