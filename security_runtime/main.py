#!/usr/bin/env python3
"""Run a SecDepth scan, watch a target, or review a flagged finding."""

import argparse

from . import runtime, triage


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="scan a source checkout or artifact once")
    runtime.add_runtime_options(scan)
    runtime.add_scan_arguments(scan)

    watch = commands.add_parser("watch", help="scan a source checkout or artifact periodically")
    runtime.add_runtime_options(watch)
    runtime.add_scan_arguments(watch, watch=True)

    review = commands.add_parser("triage", help="review one flagged finding or resume its review")
    triage.add_arguments(review)

    args = parser.parse_args(argv)
    if args.command == "triage":
        return triage.run_command(args, review)
    return runtime.run_command(args)
