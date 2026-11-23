#!/usr/bin/env python3
"""Compatibility launcher for the security-runtime CLI."""

from security_runtime.main import main


if __name__ == "__main__":
    raise SystemExit(main())
