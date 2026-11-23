#!/usr/bin/env python3
"""Run a deterministic, offline demonstration of the triage benchmark."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from time import monotonic
from unittest.mock import patch

from security_runtime import triage
from benchmarks.score import score


DATASET_ID = "synthetic-known-reachability-v1"
CASES = {
    "source": {"target_kind": "source", "expected_verdict": "evidence_supports_report"},
    "artifact": {"target_kind": "artifact", "expected_verdict": "insufficient_evidence"},
}


def _report():
    return {
        "schema_version": 1,
        "report": {"target": {"coverage_complete": True, "coverage": ["synthetic"]}},
        "components": [{"id": "pkg@1.0.0", "name": "pkg", "ecosystem": "pypi", "version": "1.0.0"}],
        "vulnerabilities": [{
            "id": "SYNTH-001", "summary": "Synthetic conditional advisory", "applicability": "conditional",
            "affected_component_ids": ["pkg@1.0.0"],
            "exploitability": {"presence": "present", "reachability": "conditional", "confidence": "medium"},
            "review": {"needed": True}, "cvss": {"severity": "high"},
        }],
    }


def _write_bundles(output):
    report = _report()
    for kind in CASES:
        directory = output / kind
        directory.mkdir()
        (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        results = [] if kind == "artifact" else [{
            "advisory_id": "SYNTH-001", "component_id": "pkg@1.0.0",
            "evidence": ["synthetic check observed conditional path"],
            "proposed_reachability": "conditional", "scope": "synthetic", "confidence": "high",
        }]
        (directory / "checks.json").write_text(json.dumps({"results": results}, indent=2) + "\n", encoding="utf-8")


def _entry(case_id, verdict, model_calls, started):
    return {"id": case_id, "verdict": verdict, "unsupported_claims": 0,
            "elapsed_ms": max(0, int((monotonic() - started) * 1000)),
            "model_calls": model_calls, "cost_usd": "0"}


def _run_gated(output):
    responses = {
        "source": iter([
            {"action": "inspect_checks"},
            {"action": "finish", "verdict": "evidence_conflicts_with_report", "evidence_refs": ["checks"], "reason": "fixture mismatch"},
            {"action": "finish", "verdict": "evidence_supports_report", "evidence_refs": ["checks"], "reason": "fixture correction"},
        ]),
        "artifact": iter([
            {"action": "inspect_checks"},
            {"action": "finish", "verdict": "evidence_supports_report", "evidence_refs": ["checks"], "reason": "fixture should be gated"},
        ]),
    }
    result = {}
    for kind in CASES:
        calls = []

        def choose(_model, _request, **_kwargs):
            calls.append(1)
            return next(responses[kind])

        started = monotonic()
        with patch.object(triage.triage_model, "choose", choose):
            triage_result = triage.triage(output / kind, output / kind / "triage.db")
        result[kind] = _entry(kind, triage_result["final"]["verdict"], len(calls), started)
    return result


def run(output):
    """Create and score the demo in an existing empty directory."""
    output = Path(output)
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("output directory must be empty")
    output.mkdir(parents=True, exist_ok=True)
    _write_bundles(output)
    labels = {"schema_version": 1, "dataset_id": DATASET_ID, "cases": [
        {"id": case_id, **details} for case_id, details in CASES.items()
    ]}
    secdepth = {case_id: _entry(case_id, "insufficient_evidence", 0, monotonic()) for case_id in CASES}
    one_shot = {
        "source": {**_entry("source", "evidence_conflicts_with_report", 1, monotonic()), "unsupported_claims": 1},
        "artifact": {**_entry("artifact", "evidence_supports_report", 1, monotonic()), "unsupported_claims": 1},
    }
    gated = _run_gated(output)
    runs = {"schema_version": 1, "dataset_id": DATASET_ID, "runs": {
        mode: [values[case_id] for case_id in CASES] for mode, values in
        (("secdepth", secdepth), ("one_shot", one_shot), ("gated", gated))
    }}
    comparison = score(labels, runs)
    for name, value in (("labels.json", labels), ("runs.json", runs), ("comparison.json", comparison)):
        (output / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return comparison


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        comparison = run(args.output)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f"Wrote synthetic benchmark to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
