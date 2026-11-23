#!/usr/bin/env python3
"""Compatibility launcher for the triage CLI."""

from security_runtime.triage import main


if __name__ == "__main__":
    raise SystemExit(main())
