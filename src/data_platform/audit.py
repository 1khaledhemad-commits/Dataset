"""Append-only, privacy-minimal operator audit events."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX fallback keeps thread-local protection
    fcntl = None  # type: ignore[assignment]
from pathlib import Path
from typing import Any

_LOCK = threading.Lock()


def append_audit_event(project_root: str | Path, event: dict[str, Any], *,
                       max_bytes: int = 16 * 1024 * 1024) -> Path:
    """Append one compact event; never record response bodies, credentials, or full URLs."""
    if max_bytes <= 0:
        raise OSError("audit-log byte limit must be positive")
    root = Path(project_root)
    directory = root / "logs"
    if directory.is_symlink():
        raise OSError("audit directory must not be a symbolic link")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        directory.chmod(0o700)
    except OSError:
        pass
    path = directory / "audit.jsonl"
    record = {"timestamp_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), **event}
    encoded = (json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > 64 * 1024:
        raise OSError("audit event exceeds its 64 KiB event limit")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if path.is_symlink():
        raise OSError("audit file must not be a symbolic link")
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with _LOCK:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                if os.fstat(fd).st_size + len(encoded) > max_bytes:
                    raise OSError("append-only audit log reached its configured byte quota")
                view = memoryview(encoded)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError("short append to audit log")
                    view = view[written:]
                os.fsync(fd)
            finally:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path
