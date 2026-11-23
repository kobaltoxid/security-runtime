#!/usr/bin/env python3
"""Run SecDepth alone, a one-shot review, and the gated review over labeled cases."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from time import monotonic

from security_runtime import triage, triage_evidence, triage_gate, triage_model

MODES = ("secdepth", "one_shot", "gated")
ONE_SHOT_POLICY = "one-shot-policy-1"


def _observations(review):
    observations = {"components": triage_evidence.observation_for("inspect_components", review)}
    if review.checks is not None:
        observations["checks"] = triage_evidence.observation_for("inspect_checks", review)
    return observations


def _unsupported(verdict, review, observations):
    """Count a substantive verdict the acceptance gate cannot verify from the observed checks."""
    if verdict == "insufficient_evidence":
        return 0
    proposal = {"verdict": verdict, "evidence_refs": sorted(observations), "reason": "benchmark check"}
    return 0 if triage_gate.assess(proposal, review, observations)["accepted"] else 1


def _counting_choose(calls):
    original = triage_model.choose

    def choose(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)
    return original, choose


def run_one_shot(scan_dir, finding_id, model, provider):
    review = triage_evidence.load_review(scan_dir, finding_id, model, provider, ONE_SHOT_POLICY)
    observations = _observations(review)
    request = {**triage_evidence.request_for(review, observations), "available_actions": ["finish"]}
    started = monotonic()
    try:
        proposal = triage_model.choose(model, request, provider=provider)
        proposal = triage_evidence.validate_action(proposal, review, observations)
        verdict = proposal["verdict"] if proposal.get("action") == "finish" else "insufficient_evidence"
    except (TypeError, ValueError):
        verdict = "insufficient_evidence"
    return {"verdict": verdict, "unsupported_claims": _unsupported(verdict, review, observations),
            "elapsed_ms": int((monotonic() - started) * 1000), "model_calls": 1, "cost_usd": None}


def run_gated(scan_dir, finding_id, model, provider, db_path):
    calls = []
    original, choose = _counting_choose(calls)
    started = monotonic()
    triage.triage_model.choose = choose
    try:
        result = triage.triage(scan_dir, db_path, finding_id, model, provider=provider)
    finally:
        triage.triage_model.choose = original
    verdict = result["final"]["verdict"]
    review = triage_evidence.load_review(scan_dir, finding_id, model, provider, triage.POLICY_VERSION)
    return {"verdict": verdict, "unsupported_claims": _unsupported(verdict, review, _observations(review)),
            "elapsed_ms": int((monotonic() - started) * 1000), "model_calls": len(calls), "cost_usd": None}


def run(labels_path, cases_root, output, model, provider, modes=MODES, limit=None):
    """Run each mode once per case, reusing results saved by an earlier, interrupted run."""
    labels = json.loads(Path(labels_path).read_text(encoding="utf-8"))
    cases = labels["cases"][:limit] if limit else labels["cases"]
    output = Path(output)
    saved = output / "cases"
    saved.mkdir(parents=True, exist_ok=True)
    runs = {mode: [] for mode in MODES}
    for case in cases:
        scan_dir = Path(cases_root) / case["scan_dir"]
        for mode in modes:
            path = saved / f"{case['id']}.{mode}.json"
            if path.is_file():
                entry = json.loads(path.read_text(encoding="utf-8"))
            else:
                if mode == "secdepth":
                    entry = {"verdict": "insufficient_evidence", "unsupported_claims": 0,
                             "elapsed_ms": 0, "model_calls": 0, "cost_usd": "0"}
                elif mode == "one_shot":
                    entry = run_one_shot(scan_dir, case["advisory"], model, provider)
                else:
                    entry = run_gated(scan_dir, case["advisory"], model, provider,
                                      output / "gated" / f"{case['id']}.sqlite3")
                entry = {"id": case["id"], **entry}
                path.write_text(json.dumps(entry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            runs[mode].append(entry)
            print(f"{case['id']} {mode}: {entry['verdict']}", flush=True)
    result = {"schema_version": 1, "dataset_id": labels["dataset_id"], "model": model, "provider": provider,
              "runs": runs}
    (output / "runs.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("labels", type=Path)
    parser.add_argument("--cases-root", type=Path, help="directory holding each case's scan_dir (default: next to labels)")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--model", default="haiku")
    parser.add_argument("--provider", choices=sorted(triage.PROVIDERS), default=triage.DEFAULT_PROVIDER)
    parser.add_argument("--limit", type=int, help="run only the first N cases (for a smoke test)")
    args = parser.parse_args(argv)
    try:
        run(args.labels, args.cases_root or args.labels.parent, args.output, args.model, args.provider,
            limit=args.limit)
    except (OSError, ValueError, KeyError, RuntimeError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(f"Wrote {args.output / 'runs.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
