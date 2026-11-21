#!/usr/bin/env python3
"""Fetch and validate the trusted PR scan artifact for the Go pilot.

This deliberately uses ``gh api`` rather than the Actions download URL so the
caller can supply a least-privilege token in ``GH_TOKEN``.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

REPOSITORY = "kobaltoxid/bg-cars-discord-bot"
OPT_IN_LABEL = "secdepth-triage"
WORKFLOW_PATH = ".github/workflows/secdepth.yml"
WORKFLOW_ID = 425513024
CALLER_BLOB = "bd27fe9d4f652e598115a7b4fc59caa92e986268"
SCANNER_SHA = "ff5d669b7b639d5339eb40eb100ceff3a098c293"
SCANNER_REF = f"kobaltoxid/security-runtime/.github/workflows/scan.yml@{SCANNER_SHA}"
MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
MAX_ENTRY_BYTES = 5 * 1024 * 1024
TARGET_ENTRIES = frozenset(("report.json", "checks.json", "run.json"))


class InputError(ValueError):
    pass


def gh_api(path: str, *, binary: bool = False) -> bytes | dict[str, Any]:
    argv = ["gh", "api", path]
    try:
        result = subprocess.run(argv, check=True, capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise InputError(
            f"GitHub API request failed ({path}); verify Actions read access to {REPOSITORY}"
        ) from exc
    data = result.stdout
    if binary:
        return data
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InputError("gh api returned invalid JSON") from exc


def _string(obj: Any, field: str) -> str:
    if not isinstance(obj, str) or not obj:
        raise InputError(f"missing or invalid {field}")
    return obj


def _run_id(value: str) -> int:
    if not re.fullmatch(r"[0-9]+", value):
        raise InputError("run id must contain digits only")
    return int(value)


def _validate_run(run: dict[str, Any], run_id: int) -> tuple[int, int, str]:
    if run.get("id") != run_id or run.get("workflow_id") != WORKFLOW_ID:
        raise InputError("run is not the approved pilot workflow")
    if run.get("path") != WORKFLOW_PATH or run.get("event") != "pull_request":
        raise InputError("run provenance is not an approved pull_request workflow")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise InputError("run did not complete successfully")
    if run.get("head_repository", {}).get("full_name") != REPOSITORY:
        raise InputError("run head repository is not the approved repository")
    prs = run.get("pull_requests")
    if not isinstance(prs, list) or len(prs) != 1 or not isinstance(prs[0], dict):
        raise InputError("run must have exactly one associated pull request")
    pr_number = prs[0].get("number")
    if not isinstance(pr_number, int) or isinstance(pr_number, bool):
        raise InputError("associated pull request number is invalid")
    head_sha = _string(run.get("head_sha"), "run head SHA")
    if not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise InputError("run head SHA is not canonical")
    referenced = run.get("referenced_workflows")
    if not isinstance(referenced, list) or len(referenced) != 1:
        raise InputError("run must reference exactly one approved scanner workflow")
    ref = referenced[0]
    if not isinstance(ref, dict) or (ref.get("path"), ref.get("sha")) != (SCANNER_REF, SCANNER_SHA):
        raise InputError("run does not reference the trusted scanner workflow")
    if prs[0].get("head", {}).get("sha") != head_sha:
        raise InputError("run and pull request association disagree on head SHA")
    attempt = run.get("run_attempt")
    if not isinstance(attempt, int) or attempt < 1:
        raise InputError("run attempt is invalid")
    return pr_number, attempt, head_sha


def _validate_pr(pr: dict[str, Any], number: int, head_sha: str, *, require_opt_in: bool = False) -> None:
    if pr.get("number") != number or pr.get("state") != "open":
        raise InputError("associated pull request is not open")
    if not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise InputError("pull request head SHA is not canonical")
    if pr.get("head", {}).get("sha") != head_sha or pr.get("head", {}).get("repo", {}).get("full_name") != REPOSITORY:
        raise InputError("current pull request head does not match the completed run")
    if pr.get("base", {}).get("ref") != "main" or pr.get("base", {}).get("repo", {}).get("full_name") != REPOSITORY:
        raise InputError("pull request base is not the approved main branch")
    if require_opt_in:
        labels = pr.get("labels")
        if not isinstance(labels, list) or not any(
            isinstance(label, dict) and label.get("name") == OPT_IN_LABEL for label in labels
        ):
            raise InputError(f"pull request is not opted in with the {OPT_IN_LABEL} label")


def _validate_workflow_blob(blob: dict[str, Any]) -> None:
    if blob.get("sha") != CALLER_BLOB:
        raise InputError("caller workflow blob is not approved")


def _artifact(artifacts: dict[str, Any], name: str) -> dict[str, Any]:
    values = [a for a in artifacts.get("artifacts", []) if isinstance(a, dict) and a.get("name") == name]
    if len(values) != 1:
        raise InputError("expected exactly one matching scan artifact")
    artifact = values[0]
    if artifact.get("expired") is True or not artifact.get("expires_at"):
        raise InputError("scan artifact is expired or has no expiry")
    size = artifact.get("size_in_bytes")
    if not isinstance(size, int) or size < 1 or size > MAX_ARCHIVE_BYTES:
        raise InputError("scan artifact size is missing or exceeds the safety limit")
    digest = artifact.get("digest")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise InputError("scan artifact has no valid SHA256 metadata")
    return artifact


def _read_archive(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_ARCHIVE_BYTES:
        raise InputError("downloaded artifact exceeds the safety limit")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise InputError("downloaded artifact is not a valid ZIP") from exc
    found: dict[str, bytes] = {}
    try:
        for info in archive.infolist():
            if info.filename not in TARGET_ENTRIES:
                continue
            if info.filename in found or info.is_dir() or stat.S_ISLNK(info.external_attr >> 16):
                raise InputError("artifact contains duplicate or non-regular required entries")
            if info.file_size > MAX_ENTRY_BYTES:
                raise InputError("artifact entry exceeds the safety limit")
            found[info.filename] = archive.read(info)
    finally:
        archive.close()
    if set(found) != TARGET_ENTRIES:
        raise InputError("artifact is missing a required JSON entry")
    result: dict[str, Any] = {}
    try:
        for name, content in found.items():
            result[name] = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InputError("artifact required entry is invalid JSON") from exc
    return result


def _validate_payload(payload: dict[str, Any], pr_number: int, run_id: int, attempt: int, head_sha: str) -> None:
    receipt = payload["run.json"]
    if not isinstance(receipt, dict) or any(receipt.get(k) != v for k, v in {
        "ecosystem": "go", "pull_request": pr_number, "head_sha": head_sha,
        "run_id": run_id, "run_attempt": attempt,
    }.items()):
        raise InputError("artifact receipt does not match trusted run provenance")
    report, checks = payload["report.json"], payload["checks.json"]
    if not isinstance(report, dict):
        raise InputError("report JSON is not a secdepth report")
    if not isinstance(report.get("vulnerabilities"), list) or not isinstance(report.get("components"), list):
        raise InputError("report JSON lacks triage collections")
    if not isinstance(checks, dict) or not isinstance(checks.get("results"), list):
        raise InputError("checks JSON lacks results")


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def receipt_name(pr_number: int, head_sha: str) -> str:
    return f"triage-pr-{pr_number}-{head_sha}"


def write_github_output(path: Path, name: str, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{name}={value}\n")


def fetch(
    run_id_text: str,
    output_dir: Path,
    *,
    require_opt_in: bool = False,
    github_output: Path | None = None,
) -> None:
    run_id = _run_id(run_id_text)
    run = gh_api(f"repos/{REPOSITORY}/actions/runs/{run_id}")
    if not isinstance(run, dict):
        raise InputError("run API response is invalid")
    pr_number, attempt, head_sha = _validate_run(run, run_id)
    pr = gh_api(f"repos/{REPOSITORY}/pulls/{pr_number}")
    if not isinstance(pr, dict):
        raise InputError("pull request API response is invalid")
    _validate_pr(pr, pr_number, head_sha, require_opt_in=require_opt_in)
    blob = gh_api(f"repos/{REPOSITORY}/contents/{WORKFLOW_PATH}?ref={head_sha}")
    if not isinstance(blob, dict):
        raise InputError("workflow API response is invalid")
    _validate_workflow_blob(blob)
    name = f"secdepth-pr-{pr_number}-{run_id}-{attempt}"
    artifact = _artifact(gh_api(f"repos/{REPOSITORY}/actions/runs/{run_id}/artifacts"), name)
    data = gh_api(f"repos/{REPOSITORY}/actions/artifacts/{artifact['id']}/zip", binary=True)
    expected = artifact["digest"].split(":", 1)[1]
    if hashlib.sha256(data).hexdigest() != expected:
        raise InputError("downloaded artifact SHA256 does not match metadata")
    payload = _read_archive(data)
    _validate_payload(payload, pr_number, run_id, attempt, head_sha)
    source = {
        "schema": "security-runtime-pr-input", "schema_version": 1,
        "repository": REPOSITORY, "workflow": WORKFLOW_PATH, "workflow_id": WORKFLOW_ID,
        "run_id": run_id, "run_attempt": attempt,
        "run_url": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}",
        "artifact_id": artifact.get("id"), "artifact_name": name, "artifact_digest": artifact["digest"],
        "pull_request": pr_number, "pull_request_url": f"https://github.com/{REPOSITORY}/pull/{pr_number}",
        "base_ref": "main", "head_sha": head_sha, "ecosystem": "go",
        "source_workflow_blob": CALLER_BLOB, "scanner_workflow": SCANNER_REF,
    }
    _write_json(output_dir / "report.json", payload["report.json"])
    _write_json(output_dir / "checks.json", payload["checks.json"])
    _write_json(output_dir / "source.json", source)
    if require_opt_in and github_output is not None:
        write_github_output(github_output, "receipt_name", receipt_name(pr_number, head_sha))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--require-opt-in", action="store_true")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.github_output is not None and not args.require_opt_in:
            raise InputError("--github-output requires --require-opt-in")
        fetch(
            args.run_id,
            args.output_dir,
            require_opt_in=args.require_opt_in,
            github_output=args.github_output,
        )
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
