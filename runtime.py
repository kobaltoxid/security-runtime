#!/usr/bin/env python3
"""Compatibility launcher for the runtime CLI."""

from security_runtime.runtime import main


if __name__ == "__main__":
    raise SystemExit(main())
