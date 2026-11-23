#!/usr/bin/env python3
"""Resolve and summarize push, scheduled, manual, and release scans in CI.

The reusable workflow calls ``resolve`` after it prepares the target and
``summarize`` after ``main.py scan`` prints its run summary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

SOURCE_TRIGGERS = {"push": "push", "schedule": "scheduled", "workflow_dispatch": "manual"}
RELEASE_EVENTS = frozenset(("push", "release", "workflow_dispatch"))
ECOSYSTEMS = frozenset(("npm", "go"))
STREAM = re.compile(r"[a-z0-9][a-z0-9_.-]{0,127}")


class InputError(ValueError):
    pass


def stream_name(prefix: str, name: str) -> str:
    slug = re.sub(r"[^a-z0-9_.-]+", "-", name.lower()).strip("-.")
    return f"{prefix}-{slug}"[:128].rstrip("-.")


def valid_stream(value: str) -> str:
    if not STREAM.fullmatch(value):
        raise InputError("stream must be 1-128 lowercase letters, digits, '.', '_' or '-' and start alphanumeric")
    return value


def _regular_file(path: Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError:
        raise InputError(f"{label} is missing") from None
    if not stat.S_ISREG(mode):
        raise InputError(f"{label} is not a regular file")


def _check_ecosystem(source: Path, ecosystem: str) -> None:
    if ecosystem not in ECOSYSTEMS:
        raise InputError(f"unsupported ecosystem: {ecosystem or '(empty)'}")
    if ecosystem == "go":
        _regular_file(source / "go.mod", "go.mod")
        _regular_file(source / "go.sum", "go.sum")
        return
    _regular_file(source / "package.json", "package.json")
    for lockfile in ("npm-shrinkwrap.json", "package-lock.json"):
        path = source / lockfile
        if path.exists() or path.is_symlink():
            _regular_file(path, lockfile)
            return
    raise InputError("no usable npm lockfile found")


def _head(source: Path) -> str:
    try:
        result = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                                check=True, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        raise InputError("could not read the target revision") from None
    return result.stdout.strip()


def resolve_source(event: str, ref_name: str, sha: str, source: Path, ecosystem: str) -> dict[str, str]:
    if event not in SOURCE_TRIGGERS:
        raise InputError(f"source scans do not support the {event} event")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise InputError("sha must be a full lowercase commit SHA")
    if _head(source) != sha:
        raise InputError("target HEAD did not match the workflow commit")
    _check_ecosystem(source, ecosystem)
    return {"stream": stream_name("branch", ref_name), "trigger": SOURCE_TRIGGERS[event],
            "revision": sha, "target": str(source.resolve())}


def resolve_release(event: str, release_dir: Path, release_file: str) -> dict[str, str]:
    if event not in RELEASE_EVENTS:
        raise InputError(f"release scans do not support the {event} event")
    if any(ord(char) < 32 or ord(char) == 127 for char in release_file):
        raise InputError("release-file must not contain control characters")
    relative = Path(release_file)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise InputError("release-file must be a relative path inside the artifact")
    path = release_dir / relative
    _regular_file(path, "release-file")
    if release_dir.resolve() not in path.resolve().parents:
        raise InputError("release-file must be a relative path inside the artifact")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return {"stream": stream_name("release", relative.name), "trigger": "release",
            "revision": f"sha256:{digest.hexdigest()}", "target": str(path.resolve())}


def summarize(summary: dict[str, Any], state: Path) -> tuple[dict[str, str], str]:
    stream, run_id = summary.get("stream"), summary.get("run_id")
    if not isinstance(stream, str) or not isinstance(run_id, str) or not run_id.isdecimal():
        raise InputError("runtime summary has no stream or run id")
    diff = summary.get("diff") or {}
    lines = [
        f"### SecDepth {summary.get('trigger')} scan: {summary.get('status')}",
        "",
        f"- Stream: `{stream}`, run `{run_id}`",
        f"- Revision: `{summary.get('revision')}`",
    ]
    if summary.get("status") == "deduplicated":
        lines.append("- Reused the complete scan already recorded for this trigger and revision.")
    elif diff:
        lines.append(f"- New findings: {len(diff.get('new', []))}, changed: {len(diff.get('changed', []))}, "
                     f"missing from baseline: {len(diff.get('missing', []))}")
        if diff.get("missing_suppressed"):
            lines.append("- Missing findings were not reported because this scan is partial.")
    else:
        lines.append(f"- Reason: `{summary.get('reason')}`")
    outputs = {"run_id": run_id, "run_dir": str(state / stream / "runs" / run_id)}
    return outputs, "\n".join(lines) + "\n"


def _append(path: str | None, text: str) -> None:
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    resolve = commands.add_parser("resolve")
    resolve.add_argument("--event", required=True)
    resolve.add_argument("--ref-name", default="")
    resolve.add_argument("--sha", default="")
    resolve.add_argument("--ecosystem", default="")
    resolve.add_argument("--source", type=Path)
    resolve.add_argument("--release-dir", type=Path)
    resolve.add_argument("--release-file", default="")
    resolve.add_argument("--stream", default="")
    resolve.add_argument("--github-output")
    report = commands.add_parser("summarize")
    report.add_argument("summary", type=Path)
    report.add_argument("--state", type=Path, required=True)
    report.add_argument("--github-output")
    report.add_argument("--step-summary")
    args = parser.parse_args(argv)

    try:
        if args.command == "resolve":
            if args.release_file:
                if args.release_dir is None:
                    raise InputError("--release-dir is required with --release-file")
                outputs = resolve_release(args.event, args.release_dir, args.release_file)
            else:
                if args.source is None or not args.sha or not args.ref_name:
                    raise InputError("--source, --sha, and --ref-name are required for source scans")
                outputs = resolve_source(args.event, args.ref_name, args.sha, args.source, args.ecosystem)
            outputs["stream"] = valid_stream(args.stream or outputs["stream"])
        else:
            summary = json.loads(args.summary.read_text(encoding="utf-8").strip().splitlines()[-1])
            outputs, text = summarize(summary, args.state)
            _append(args.step_summary, text)
    except (InputError, OSError, json.JSONDecodeError, IndexError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    _append(args.github_output, "".join(f"{key}={value}\n" for key, value in outputs.items()))
    print(json.dumps(outputs, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
