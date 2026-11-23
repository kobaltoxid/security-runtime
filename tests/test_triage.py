import contextlib
import io
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from security_runtime import triage, triage_model


INTERRUPTED_WORKER = """
import signal
import sys
from pathlib import Path

from security_runtime import triage

ready = Path(sys.argv[1])
calls = 0

def choose(model, request):
    global calls
    calls += 1
    if calls == 1:
        return {"action": "inspect_checks"}
    ready.touch()
    signal.pause()
    raise AssertionError("worker should have been interrupted")

triage.triage_model.choose = choose
raise SystemExit(triage.main(sys.argv[2:]))
"""


def finish(verdict, refs):
    return {
        "action": "finish",
        "verdict": verdict,
        "evidence_refs": refs,
        "reason": "The recorded check supports the reported status.",
    }


class TriageTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.artifact = root / "artifact"
        self.artifact.mkdir()
        self.db = root / "triage.sqlite3"
        self.ready = root / "ready-to-interrupt"
        self.args = [str(self.artifact), "--db", str(self.db)]
        self.write_json("report.json", {
            "report": {"target": {"coverage_complete": True}},
            "components": [
                {"id": "example@1", "name": "example package", "version": "1"},
                {"id": "unrelated@2", "name": "unrelated package", "version": "2"},
            ],
            "vulnerabilities": [
                {
                    "id": "selected-advisory",
                    "summary": "Selected finding",
                    "review": {"needed": True},
                    "affected_component_ids": ["example@1"],
                    "exploitability": {"reachability": "conditional"},
                },
                {
                    "id": "unrelated-advisory",
                    "summary": "Unrelated finding",
                    "review": {"needed": True},
                    "affected_component_ids": ["unrelated@2"],
                    "exploitability": {"reachability": "conditional"},
                },
            ],
        })
        self.write_json("checks.json", {
            "results": [
                {
                    "advisory_id": "selected-advisory",
                    "component_id": "example@1",
                    "proposed_reachability": "conditional",
                    "evidence": ["selected check evidence"],
                },
                {
                    "advisory_id": "unrelated-advisory",
                    "component_id": "example@1",
                    "evidence": ["unrelated advisory evidence"],
                },
                {
                    "advisory_id": "selected-advisory",
                    "component_id": "unrelated@2",
                    "evidence": ["unrelated component evidence"],
                },
            ],
        })

    def write_json(self, name, contents):
        (self.artifact / name).write_text(json.dumps(contents), encoding="utf-8")

    def invoke(self, chooser, *options):
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.object(triage.triage_model, "choose", side_effect=chooser) as choose,
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            try:
                code = triage.main([*self.args, *options])
            except SystemExit as exc:
                code = exc.code
        value = json.loads(stdout.getvalue()) if stdout.getvalue() else None
        return code, value, choose.call_count

    def test_interruption_resumes_with_one_final_verdict(self):
        command = [sys.executable, "-B", "-c", INTERRUPTED_WORKER, str(self.ready), *self.args]
        with subprocess.Popen(
            command, cwd=Path(__file__).resolve().parent.parent,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ) as worker:
            try:
                deadline = time.monotonic() + 8
                while not self.ready.exists() and worker.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                if not self.ready.exists():
                    worker.kill()
                    self.fail(worker.communicate(timeout=3))
                worker.send_signal(signal.SIGINT)
                stdout, stderr = worker.communicate(timeout=5)
                self.assertEqual(130, worker.returncode, (stdout, stderr))
            finally:
                if worker.poll() is None:
                    worker.kill()

        def resumed_choice(model, request):
            self.assertIn("selected check evidence", json.dumps(request))
            return finish("evidence_supports_report", ["checks"])

        code, final, calls = self.invoke(resumed_choice)
        self.assertEqual((0, 1), (code, calls))
        self.assertEqual("evidence_supports_report", final["final"]["verdict"])
        self.assertEqual(["checks"], final["final"]["evidence_refs"])
        code, replay, calls = self.invoke(AssertionError("completed run called the model"))
        self.assertEqual((0, 0), (code, calls))
        self.assertEqual(final, replay)
        with contextlib.closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(
                [(1, "inspect_checks"), (2, "finish")],
                db.execute("SELECT sequence, action FROM trace ORDER BY sequence").fetchall(),
            )

    def test_unobserved_evidence_cannot_support_a_verdict(self):
        code, result, calls = self.invoke([
            {"action": "inspect_checks"},
            finish("evidence_supports_report", ["checks", "components"]),
        ])
        self.assertEqual((0, 2), (code, calls))
        self.assertEqual("insufficient_evidence", result["final"]["verdict"])

    def test_tools_only_expose_records_for_the_selected_finding(self):
        proposals = iter([
            {"action": "inspect_checks"},
            {"action": "inspect_components"},
            finish("evidence_supports_report", ["checks", "components"]),
        ])

        observed = []

        def choose(model, request):
            payload = json.dumps(request)
            self.assertNotIn("unrelated-advisory", payload)
            self.assertNotIn("unrelated@2", payload)
            self.assertNotIn("unrelated advisory evidence", payload)
            self.assertNotIn("unrelated component evidence", payload)
            observed.append(payload)
            return next(proposals)

        code, final, calls = self.invoke(choose)
        self.assertEqual((0, 3), (code, calls))
        self.assertEqual("evidence_supports_report", final["final"]["verdict"])
        self.assertIn("selected check evidence", observed[1])
        self.assertIn("example package", observed[2])

    def test_tool_request_cannot_override_its_scope(self):
        code, result, calls = self.invoke([{"action": "inspect_checks", "advisory_id": "unrelated-advisory"}])
        self.assertEqual((0, 1), (code, calls))
        self.assertEqual("insufficient_evidence", result["final"]["verdict"])
        code, replay, calls = self.invoke(AssertionError("replayed an invalid model proposal"))
        self.assertEqual((0, 0), (code, calls))
        self.assertEqual(result, replay)

    def test_provider_is_part_of_run_identity_and_output(self):
        def choose(model, request, **kwargs):
            return finish("insufficient_evidence", [])

        code, local, _calls = self.invoke(choose)
        self.assertEqual(0, code)
        code, hosted, _calls = self.invoke(choose, "--provider", "claude-oauth")
        self.assertEqual(0, code)
        self.assertEqual("claude2", local["provider"])
        self.assertEqual("claude-oauth", hosted["provider"])
        self.assertNotEqual(local["run_id"], hosted["run_id"])

    def test_gate_rejection_is_resumed_with_one_finish_only_correction(self):
        code, paused, calls = self.invoke(lambda model, request: {"action": "inspect_checks"}, "--step")
        self.assertEqual((0, 1), (code, calls))
        self.assertEqual("paused", paused["status"])

        code, rejected, calls = self.invoke(lambda model, request: finish("evidence_conflicts_with_report", ["checks"]), "--step")
        self.assertEqual((0, 1), (code, calls))
        self.assertEqual("paused", rejected["status"])

        def correction(model, request):
            self.assertEqual(["finish"], request["available_actions"])
            self.assertIn("acceptance gate", request["gate_feedback"])
            return finish("evidence_supports_report", ["checks"])

        code, final, calls = self.invoke(correction)
        self.assertEqual((0, 1), (code, calls))
        self.assertEqual("final", final["status"])
        self.assertEqual("evidence_supports_report", final["final"]["verdict"])
        code, replay, calls = self.invoke(AssertionError("replayed completed run"))
        self.assertEqual((0, 0), (code, calls))
        self.assertEqual(final, replay)
        with contextlib.closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(
                [(1, "inspect_checks"), (2, "gate_rejection"), (3, "finish")],
                db.execute("SELECT sequence, action FROM trace ORDER BY sequence").fetchall(),
            )

    def test_repeated_gate_mismatch_becomes_inconclusive_and_replays(self):
        self.invoke(lambda model, request: {"action": "inspect_checks"}, "--step")
        self.invoke(lambda model, request: finish("evidence_conflicts_with_report", ["checks"]), "--step")
        code, final, calls = self.invoke(lambda model, request: finish("evidence_conflicts_with_report", ["checks"]))
        self.assertEqual((0, 1), (code, calls))
        self.assertEqual("insufficient_evidence", final["final"]["verdict"])
        self.assertIn("acceptance gate", final["final"]["reason"])
        code, replay, calls = self.invoke(AssertionError("replayed completed run"))
        self.assertEqual((0, 0), (code, calls))
        self.assertEqual(final, replay)

    def test_empty_checks_are_inconclusive_without_correction(self):
        self.write_json("checks.json", {"results": []})
        self.invoke(lambda model, request: {"action": "inspect_checks"}, "--step")
        code, result, calls = self.invoke(lambda model, request: finish("evidence_supports_report", ["checks"]))
        self.assertEqual((0, 1), (code, calls))
        self.assertEqual("insufficient_evidence", result["final"]["verdict"])


class TransportTest(unittest.TestCase):
    def test_shell_profile_never_falls_back_to_plain_claude(self):
        proposal = {"action": "inspect_checks"}
        response = json.dumps({"is_error": False, "structured_output": proposal})
        with (
            patch.object(triage_model.shutil, "which", side_effect=lambda name: "/bin/zsh" if name == "zsh" else None),
            patch.object(triage_model.subprocess, "Popen") as popen,
        ):
            process = popen.return_value.__enter__.return_value
            process.communicate.return_value = (response, None)
            process.returncode = 0
            self.assertEqual(proposal, triage_model.choose("haiku", {}))
            self.assertEqual(["/bin/zsh", "-ic", 'claude2 "$@"'], popen.call_args.args[0][:3])

    def test_oauth_requires_token_before_subprocess(self):
        with (
            patch.dict(os.environ, {"CLAUDE_CODE_OAUTH_TOKEN": ""}, clear=False),
            patch.object(triage_model.subprocess, "Popen") as popen,
        ):
            with self.assertRaisesRegex(triage_model.ModelError, "CLAUDE_CODE_OAUTH_TOKEN"):
                triage_model.choose("haiku", {}, provider="claude-oauth")
            popen.assert_not_called()

    def test_oauth_uses_isolated_config_and_strips_api_overrides(self):
        response = json.dumps({"is_error": False, "structured_output": {"action": "inspect_checks"}})
        with (
            patch.dict(os.environ, {
                "CLAUDE_CODE_OAUTH_TOKEN": "oauth-token",
                "ANTHROPIC_API_KEY": "bad-key",
                "ANTHROPIC_AUTH_TOKEN": "bad-auth",
                "ANTHROPIC_BASE_URL": "https://bad.example",
                "CLAUDE_CODE_USE_BEDROCK": "1",
                "CLAUDE_CONFIG_DIR": "/inherited/config",
            }, clear=False),
            patch.object(triage_model.shutil, "which", side_effect=lambda name: "/usr/local/bin/claude" if name == "claude" else None),
            patch.object(triage_model.subprocess, "Popen") as popen,
        ):
            process = popen.return_value.__enter__.return_value
            process.communicate.return_value = (response, None)
            process.returncode = 0
            self.assertEqual({"action": "inspect_checks"}, triage_model.choose("haiku", {}, provider="claude-oauth"))
            command = popen.call_args.args[0]
            self.assertEqual("/usr/local/bin/claude", command[0])
            self.assertNotIn("claude2", command)
            env = popen.call_args.kwargs["env"]
            self.assertEqual("oauth-token", env["CLAUDE_CODE_OAUTH_TOKEN"])
            self.assertTrue(env["CLAUDE_CONFIG_DIR"].endswith("/claude-config"))
            for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "CLAUDE_CODE_USE_BEDROCK"):
                self.assertNotIn(key, env)


if __name__ == "__main__":
    unittest.main()
