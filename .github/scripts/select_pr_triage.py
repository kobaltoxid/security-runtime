#!/usr/bin/env python3
"""Select one opted-in Go pull request whose trusted scan is ready for triage."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlencode

from pr_scan_input import (
    OPT_IN_LABEL,
    REPOSITORY,
    WORKFLOW_ID,
    WORKFLOW_PATH,
    InputError,
    _artifact,
    _validate_pr,
    _validate_run,
    _validate_workflow_blob,
    gh_api,
    receipt_name,
    write_github_output,
)

TRIAGE_REPOSITORY = "kobaltoxid/security-runtime"
MAX_CANDIDATES = 50
MAX_PAGES = 2


def _live_receipt(name: str) -> bool:
    query = urlencode({"name": name, "per_page": "100"})
    result = gh_api(f"repos/{TRIAGE_REPOSITORY}/actions/artifacts?{query}")
    if not isinstance(result, dict):
        raise InputError("triage receipt API response is invalid")
    return any(
        isinstance(artifact, dict)
        and artifact.get("name") == name
        and artifact.get("expired") is not True
        and bool(artifact.get("expires_at"))
        for artifact in result.get("artifacts", [])
    )


def _candidate_issues() -> list[dict]:
    issues: list[dict] = []
    for page in range(1, MAX_PAGES + 1):
        query = urlencode({"state": "open", "labels": OPT_IN_LABEL, "per_page": "50", "page": str(page)})
        result = gh_api(f"repos/{REPOSITORY}/issues?{query}")
        if not isinstance(result, list):
            raise InputError("pull request selection API response is invalid")
        issues.extend(
            item for item in result
            if isinstance(item, dict) and item.get("pull_request") and isinstance(item.get("number"), int)
        )
        if len(result) < 50 or len(issues) >= MAX_CANDIDATES:
            break
    return sorted(issues[:MAX_CANDIDATES], key=lambda item: item.get("number", 0))


def _latest_scan(number: int, head_sha: str) -> int | None:
    query = urlencode({"event": "pull_request", "status": "success", "head_sha": head_sha, "per_page": "20"})
    result = gh_api(f"repos/{REPOSITORY}/actions/workflows/{WORKFLOW_ID}/runs?{query}")
    if not isinstance(result, dict) or not isinstance(result.get("workflow_runs"), list):
        raise InputError("workflow runs API response is invalid")
    runs = sorted(
        (run for run in result["workflow_runs"] if isinstance(run, dict)),
        key=lambda run: run.get("id", 0),
        reverse=True,
    )
    for run in runs:
        run_id = run.get("id")
        if not isinstance(run_id, int):
            continue
        try:
            pr_number, attempt, validated_sha = _validate_run(run, run_id)
        except InputError:
            continue
        if pr_number != number or validated_sha != head_sha:
            continue
        artifacts = gh_api(f"repos/{REPOSITORY}/actions/runs/{run_id}/artifacts")
        if not isinstance(artifacts, dict):
            raise InputError("scan artifact API response is invalid")
        try:
            _artifact(artifacts, f"secdepth-pr-{number}-{run_id}-{attempt}")
        except InputError:
            continue
        blob = gh_api(f"repos/{REPOSITORY}/contents/{WORKFLOW_PATH}?ref={head_sha}")
        if not isinstance(blob, dict):
            raise InputError("caller workflow API response is invalid")
        try:
            _validate_workflow_blob(blob)
        except InputError:
            return None
        return run_id
    return None


def select() -> int | None:
    for issue in _candidate_issues():
        number = issue.get("number")
        if not isinstance(number, int) or number < 1:
            continue
        pr = gh_api(f"repos/{REPOSITORY}/pulls/{number}")
        if not isinstance(pr, dict):
            continue
        head_sha = pr.get("head", {}).get("sha")
        if not isinstance(head_sha, str):
            continue
        try:
            _validate_pr(pr, number, head_sha, require_opt_in=True)
        except InputError:
            continue
        if _live_receipt(receipt_name(number, head_sha)):
            continue
        scan = _latest_scan(number, head_sha)
        if scan is not None:
            return scan
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--github-output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        run_id = select()
        write_github_output(args.github_output, "scan_run_id", "" if run_id is None else str(run_id))
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
