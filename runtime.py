#!/usr/bin/env python3
"""Small local runner for periodic, event-labelled secdepth/secpeel scans.

This process accepts trusted local paths. It does not fetch repositories, expose
an HTTP endpoint, or send notifications. A CI/webhook adapter can invoke it.
"""
import argparse
import contextlib
import datetime as dt
import fcntl
import json
import math
import os
import pathlib
import re
import signal
import subprocess
import sys
import tempfile
import time

TRIGGERS = ("push", "merge-request", "release", "scheduled", "manual")


def valid_stream(value):
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,127}", value):
        raise argparse.ArgumentTypeError("use 1–128 lowercase letters, digits, '.', '_' or '-' and start alphanumeric")
    return value


def report_signature(report):
    result = {}
    for finding in report.get("vulnerabilities", []):
        result[finding["id"]] = {
            "applicability": finding.get("applicability"),
            "components": sorted(finding["affected_component_ids"]),
            "reachability": finding["exploitability"].get("reachability"),
            "review": finding["review"].get("needed"),
            "severity": (finding.get("cvss") or {}).get("severity"),
            "update_status": finding.get("update_status"),
            "recommended_target_version": finding.get("recommended_target_version"),
        }
    return result


def compare(observed, baseline, current, partial):
    complete = report_signature(baseline or {})
    old = {**complete, **report_signature(observed or {})}
    new = report_signature(current or {})
    added = sorted(set(new) - set(old))
    changed = sorted(k for k in set(new) & set(old) if new[k] != old[k])
    missing = sorted(set(complete) - set(new))
    return {"new": added, "changed": changed, "missing": [] if partial else missing,
            "missing_suppressed": bool(partial and missing)}


@contextlib.contextmanager
def exclusive(path):
    with path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def signal_group(process, sig):
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, sig)


def stop_scan(process):
    signal_group(process, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    signal_group(process, signal.SIGKILL)
    process.wait()


def run_scan(scanner, target, output, timeout, offline, osv_data, cache_dir):
    command = [sys.executable, str(scanner), str(target), "--output", str(output)]
    if offline:
        command.append("--offline")
    if osv_data:
        command.extend(["--osv-data", str(osv_data)])
    log_path = output / "scan.log"
    environment = os.environ.copy()
    environment["SECDEPTH_CACHE"] = str(cache_dir)
    with log_path.open("w", encoding="utf-8") as log:
        log.write("$ %s\n" % " ".join(command))
        log.flush()
        try:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True, env=environment)
        except OSError as exc:
            return False, "spawn-failed: %s" % exc
        try:
            code = process.wait(timeout=timeout)
        except KeyboardInterrupt:
            stop_scan(process)
            raise
        except subprocess.TimeoutExpired:
            stop_scan(process)
            return False, "timeout"
    return code == 0, "exit-%d" % code


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def scan_history(runs):
    published = sorted((p for p in runs.iterdir() if p.name.isascii() and p.name.isdecimal()), reverse=True)
    observed = None
    complete = None
    for run in published:
        summary = read_json(run / "summary.json")
        if summary["status"] in {"complete", "partial"} and observed is None:
            observed = summary, read_json(run / "report.json")
        if summary["status"] == "complete":
            complete = observed if observed[0] == summary else (summary, read_json(run / "report.json"))
            break
    next_sequence = int(published[0].name) + 1 if published else 1
    return f"{next_sequence:012d}", observed, complete


def validated_report(directory):
    report = read_json(directory / "report.json")
    if not (directory / "report.html").is_file():
        raise ValueError("missing HTML report")
    target = report["report"]["target"]
    findings = report["vulnerabilities"]
    if (
        not isinstance(target["coverage_complete"], bool)
        or any(not isinstance(target[key], list) for key in ("lookup_failures", "not_queried"))
        or not isinstance(findings, list)
    ):
        raise ValueError("invalid report structure")
    signature = report_signature(report)
    if len(signature) != len(findings) or any(not isinstance(key, str) or not key for key in signature):
        raise ValueError("advisory IDs must be unique nonempty strings")
    return report


def attempt(args, scanner, state):
    stream = args.stream
    stream_dir = state / stream
    runs = stream_dir / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    with exclusive(stream_dir / ".lock"):
        run_id, observed, baseline = scan_history(runs)
        if args.trigger != "scheduled" and args.revision and observed and observed == baseline:
            previous, _ = observed
            if previous["trigger"] == args.trigger and previous["revision"] == args.revision:
                return {"status": "deduplicated", "run_id": previous["run_id"], "stream": stream,
                        "revision": args.revision, "trigger": args.trigger}
        temporary = pathlib.Path(tempfile.mkdtemp(prefix=".run-", dir=runs))
        started = dt.datetime.now(dt.timezone.utc).isoformat()
        cache_dir = stream_dir / "cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        report = None
        try:
            snapshot_lock = exclusive(args.osv_data / ".security-runtime.lock") if args.osv_data else contextlib.nullcontext()
            with snapshot_lock:
                ok, reason = run_scan(scanner, args.target, temporary, args.timeout, args.offline, args.osv_data, cache_dir)
        except KeyboardInterrupt:
            ok, reason = False, "interrupted"
        except OSError as exc:
            ok, reason = False, f"setup-failed: {exc}"
        if ok:
            try:
                report = validated_report(temporary)
            except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
                reason = f"invalid-report: {exc}"
        target_report = (report or {}).get("report", {}).get("target", {})
        partial = (not ok or report is None or not target_report.get("coverage_complete", False)
                   or bool(target_report.get("lookup_failures")) or bool(target_report.get("not_queried"))
                   or bool(target_report.get("offline")))
        if report is not None:
            diff = compare(observed[1] if observed else None, baseline[1] if baseline else None, report, partial)
            summary = {"status": "partial" if partial else "complete", "reason": reason, "stream": stream,
                       "trigger": args.trigger, "revision": args.revision,
                       "started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                       "assessment_complete": not partial, "diff": diff, "coverage_complete": target_report.get("coverage_complete"),
                       "coverage": target_report.get("coverage"), "lookup_failures": target_report.get("lookup_failures", []),
                       "unqueried": target_report.get("not_queried", []),
                       "offline": bool(target_report.get("offline")),
                       "review_needed": sum(1 for f in report.get("vulnerabilities", []) if (f.get("review") or {}).get("needed"))}
        else:
            log_path = temporary / "scan.log"
            with log_path.open("a", encoding="utf-8") as log:
                log.write(f"Runtime stopped: {reason}\n")
            summary = {"status": "failed", "reason": reason, "stream": stream, "trigger": args.trigger,
                       "revision": args.revision, "started_at": started,
                       "finished_at": dt.datetime.now(dt.timezone.utc).isoformat()}
        summary["observed_run_id"] = observed[0]["run_id"] if observed else None
        summary["baseline_run_id"] = baseline[0]["run_id"] if baseline else None
        summary["run_id"] = run_id
        (temporary / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        temporary.rename(runs / run_id)
        return summary


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state", default=None, help="state directory (default .security-runtime in cwd)")
    p.add_argument("--scanner", default=None, help="path to secdepth scan.py")
    p.add_argument("--timeout", type=int, default=1800)
    sub = p.add_subparsers(dest="command", required=True)
    def add_common(q):
        q.add_argument("--stream", required=True, type=valid_stream)
        q.add_argument("--offline", action="store_true")
        q.add_argument("--osv-data", type=pathlib.Path)

    def add_run(q):
        q.add_argument("target")
        add_common(q)
        q.add_argument("--revision")
        q.add_argument("--trigger", choices=TRIGGERS, default="manual")
    add_run(sub.add_parser("run"))
    w = sub.add_parser("watch")
    w.add_argument("target")
    add_common(w)
    w.add_argument("--revision")
    w.add_argument("--interval", type=float, required=True)
    w.add_argument("--once", action="store_true")
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    if args.timeout <= 0:
        raise SystemExit("--timeout must be positive")
    if args.command == "watch" and (not math.isfinite(args.interval) or args.interval <= 0):
        raise SystemExit("--interval must be a positive finite number")
    state = pathlib.Path(args.state or (pathlib.Path.cwd() / ".security-runtime")).resolve()
    state.mkdir(parents=True, exist_ok=True)
    scanner = pathlib.Path(args.scanner or (pathlib.Path(__file__).resolve().parent.parent / "secdepth/skills/secdepth/scripts/scan.py"))
    if not scanner.is_file():
        raise SystemExit("scanner not found: %s" % scanner)
    if args.command == "watch":
        args.trigger = "scheduled"
    try:
        while True:
            result = attempt(args, scanner, state)
            print(json.dumps(result, sort_keys=True), flush=True)
            if result.get("reason") == "interrupted":
                return 130
            if args.command != "watch" or args.once:
                return 1 if result["status"] == "failed" else 0
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
