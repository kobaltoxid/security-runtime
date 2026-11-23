#!/usr/bin/env python3
"""Small local runner for periodic, event-labelled secdepth/secpeel scans.

This process accepts trusted local paths. It does not fetch repositories, expose
an HTTP endpoint, or send notifications. A CI/webhook adapter can invoke it.
"""
import argparse
import contextlib
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

from .runtime_support import exclusive_lock, utc_timestamp
from .scan_reports import scan_history, summarize_scan, validated_report

TRIGGERS = ("push", "merge-request", "release", "scheduled", "manual")


def valid_stream(value):
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,127}", value):
        raise argparse.ArgumentTypeError("use 1–128 lowercase letters, digits, '.', '_' or '-' and start alphanumeric")
    return value


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


def scan_target(args, scanner, output, cache):
    try:
        snapshot_lock = (
            exclusive_lock(args.osv_data / ".security-runtime.lock") if args.osv_data
            else contextlib.nullcontext()
        )
        with snapshot_lock:
            ok, reason = run_scan(scanner, args.target, output, args.timeout, args.offline, args.osv_data, cache)
    except KeyboardInterrupt:
        return None, "interrupted"
    except OSError as exc:
        return None, f"setup-failed: {exc}"

    if not ok:
        return None, reason
    try:
        return validated_report(output), reason
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        return None, f"invalid-report: {exc}"


def attempt(args, scanner, state):
    stream = args.stream
    stream_dir = state / stream
    runs = stream_dir / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    with exclusive_lock(stream_dir / ".lock"):
        run_id, observed, baseline = scan_history(runs)
        if args.trigger != "scheduled" and args.revision and observed and observed == baseline:
            previous, _ = observed
            if previous["trigger"] == args.trigger and previous["revision"] == args.revision:
                return {"status": "deduplicated", "run_id": previous["run_id"], "stream": stream,
                        "revision": args.revision, "trigger": args.trigger}
        temporary = pathlib.Path(tempfile.mkdtemp(prefix=".run-", dir=runs))
        started = utc_timestamp()
        cache_dir = stream_dir / "cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        report, reason = scan_target(args, scanner, temporary, cache_dir)
        if report is None:
            with (temporary / "scan.log").open("a", encoding="utf-8") as log:
                log.write(f"Runtime stopped: {reason}\n")

        summary = {
            **summarize_scan(report, reason, observed, baseline),
            "stream": stream,
            "trigger": args.trigger,
            "revision": args.revision,
            "started_at": started,
            "finished_at": utc_timestamp(),
            "observed_run_id": observed[0]["run_id"] if observed else None,
            "baseline_run_id": baseline[0]["run_id"] if baseline else None,
            "run_id": run_id,
        }
        (temporary / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        temporary.rename(runs / run_id)
        return summary


def add_runtime_options(parser):
    parser.add_argument("--state", default=None, help="state directory (default .security-runtime in cwd)")
    parser.add_argument("--scanner", default=None, help="path to secdepth scan.py")
    parser.add_argument("--timeout", type=int, default=1800)


def add_scan_arguments(parser, *, watch=False):
    parser.add_argument("target")
    parser.add_argument("--stream", required=True, type=valid_stream)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--osv-data", type=pathlib.Path)
    parser.add_argument("--revision")
    if watch:
        parser.add_argument("--interval", type=float, required=True)
        parser.add_argument("--once", action="store_true")
    else:
        parser.add_argument("--trigger", choices=TRIGGERS, default="manual")


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    add_runtime_options(p)
    sub = p.add_subparsers(dest="command", required=True)
    add_scan_arguments(sub.add_parser("run"))
    add_scan_arguments(sub.add_parser("watch"), watch=True)
    return p


def run_command(args):
    if args.timeout <= 0:
        raise SystemExit("--timeout must be positive")
    if args.command == "watch" and (not math.isfinite(args.interval) or args.interval <= 0):
        raise SystemExit("--interval must be a positive finite number")
    state = pathlib.Path(args.state or (pathlib.Path.cwd() / ".security-runtime")).resolve()
    state.mkdir(parents=True, exist_ok=True)
    # Preserve the launcher-relative default used before this module moved into
    # the package: security-runtime/../secdepth/... from the repository root.
    scanner = pathlib.Path(args.scanner or (pathlib.Path(__file__).resolve().parent.parent.parent / "secdepth/skills/secdepth/scripts/scan.py"))
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


def main(argv=None):
    return run_command(parser().parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
