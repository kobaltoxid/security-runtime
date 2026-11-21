#!/usr/bin/env python3
"""Bounded, resumable model triage for one SecDepth finding."""

import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3

from runtime_support import exclusive_lock, utc_timestamp
import triage_evidence
import triage_model
import triage_store
import triage_gate

DEFAULT_PROVIDER = "claude2"
PROVIDERS = {DEFAULT_PROVIDER, "claude-oauth"}
POLICY_VERSION = "triage-policy-2"  # Bump when evidence or verdict policy changes.


def choose_action(review, observations, model, provider, feedback=None):
    request = triage_evidence.request_for(review, observations)
    if feedback:
        request["available_actions"] = ["finish"]
        request["gate_feedback"] = feedback
    try:
        if provider == DEFAULT_PROVIDER:
            proposal = triage_model.choose(model, request)
        else:
            proposal = triage_model.choose(model, request, provider=provider)
        return triage_evidence.validate_action(proposal, review, observations)
    except (TypeError, ValueError) as exc:
        reason = f"The model action was rejected by the runtime: {str(exc)[:300]}."
        return triage_evidence.rejected_action(observations, reason)


def review_step(review, db_path, lock_path, model, provider):
    with exclusive_lock(lock_path), closing(sqlite3.connect(db_path)) as db:
        triage_store.init_db(db)
        run = triage_store.load_or_create_run(db, review.digest, review.finding["id"], model, utc_timestamp())
        traces = triage_store.load_traces(db, run["run_id"])
        if run["status"] == "final":
            return triage_store.output(run, traces, provider, POLICY_VERSION)

        observations = triage_store.observations_from(traces)
        feedback = None
        if traces and traces[-1]["action"] == "gate_rejection":
            rejection = json.loads(traces[-1]["proposal_json"])
            feedback = (rejection["gate"]["reason"]
                        + " Provide a corrected finish verdict using the checks already observed.")

        proposal = choose_action(review, observations, model, provider, feedback)
        if feedback and proposal["action"] != "finish":
            proposal = triage_evidence.rejected_action(
                observations, "The correction requested another inspection after the gate rejected the verdict.")

        sequence = len(traces) + 1
        now = utc_timestamp()
        if proposal["action"] != "finish":
            evidence = triage_evidence.observation_for(proposal["action"], review)
            trace = triage_store.save_observation(db, run["run_id"], sequence, proposal, evidence, now)
        else:
            assessment = triage_gate.assess(proposal, review, observations)
            if assessment["actionable"] and feedback is None:
                trace = triage_store.save_rejection(db, run["run_id"], sequence, proposal, assessment, now)
            else:
                final_proposal = assessment.get("proposal", proposal)
                if not assessment["accepted"]:
                    final_proposal = triage_evidence.rejected_action(observations, assessment["reason"])
                final, trace = triage_store.save_final(db, run["run_id"], sequence, final_proposal, now)
                run["status"], run["final_json"] = "final", final

        traces.append(trace)
        return triage_store.output(run, traces, provider, POLICY_VERSION)


def triage(directory, db_path, finding_id=None, model="haiku", one_step=False, provider=DEFAULT_PROVIDER):
    if provider not in PROVIDERS:
        raise ValueError("unsupported model provider")
    review = triage_evidence.load_review(Path(directory).resolve(), finding_id, model, provider, POLICY_VERSION)
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = db_path.with_suffix(db_path.suffix + ".lock")

    while True:
        result = review_step(review, db_path, lock_path, model, provider)
        if one_step or result["status"] == "final":
            return result


def add_arguments(parser):
    parser.add_argument("artifact_dir")
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--finding")
    parser.add_argument("--model", default="haiku")
    parser.add_argument("--provider", choices=sorted(PROVIDERS), default=DEFAULT_PROVIDER)
    parser.add_argument("--step", action="store_true")
    return parser


def run_command(args, parser):
    try:
        result = triage(args.artifact_dir, args.db, args.finding, args.model, args.step, args.provider)
    except KeyboardInterrupt:
        print(json.dumps({"status": "paused", "reason": "interrupted"}))
        return 130
    except (RuntimeError, ValueError, OSError, sqlite3.Error) as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))
    return 0


def main(argv=None):
    parser = add_arguments(argparse.ArgumentParser(description=__doc__))
    return run_command(parser.parse_args(argv), parser)


if __name__ == "__main__":
    raise SystemExit(main())
