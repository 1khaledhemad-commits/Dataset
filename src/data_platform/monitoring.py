"""Read-only host resource observations used by `doctor` and run reports."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any


def memory_bytes() -> dict[str, int | None]:
    result: dict[str, int | None] = {"total": None, "available": None}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
            key, raw = line.split(":", 1)
            if key in {"MemTotal", "MemAvailable"}:
                result["total" if key == "MemTotal" else "available"] = int(raw.strip().split()[0]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return result


def doctor(root: str | Path) -> dict[str, Any]:
    root = Path(root)
    disk = shutil.disk_usage(root if root.exists() else root.parent)
    try:
        gpu = shutil.which("nvidia-smi") is not None
    except OSError:
        gpu = False
    limits: dict[str, str] = {}
    for name in ("memory.max", "cpu.max", "pids.max"):
        path = Path("/sys/fs/cgroup") / name
        try:
            limits[name] = path.read_text(encoding="ascii").strip()
        except OSError:
            pass
    return {
        "python": __import__("sys").version.split()[0],
        "platform": __import__("platform").platform(),
        "logical_cpus": os.cpu_count(),
        "memory": memory_bytes(),
        "disk": {"total": disk.total, "used": disk.used, "free": disk.free},
        "gpu_detected": gpu,
        "cgroup_limits": limits,
        "dependency_policy": "standard library only",
    }
