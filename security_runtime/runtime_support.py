"""Shared file and time operations for scan and triage runs."""

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl


@contextmanager
def exclusive_lock(path):
    with path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def utc_timestamp():
    return datetime.now(timezone.utc).isoformat()
