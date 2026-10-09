"""Deterministic group-aware splits; all members of one protected group stay together."""

from __future__ import annotations

import hashlib
import math
from collections import defaultdict
from typing import Iterable

from .models import NormalizedRecord


def split_records(
    records: Iterable[NormalizedRecord],
    *,
    seed: int,
    proportions: dict[str, float] | None = None,
    group_by_source: bool = False,
    cluster_by_record: dict[str, str] | None = None,
) -> tuple[list[NormalizedRecord], dict[str, object]]:
    if proportions is None:
        proportions = {"train": 0.90, "validation": 0.05, "test": 0.05}
    if not isinstance(proportions, dict) or not proportions:
        raise ValueError("split proportions must be a nonempty object")
    if any(not isinstance(v, (int, float)) or isinstance(v, bool) or not math.isfinite(v) or v < 0
           for v in proportions.values()):
        raise ValueError("split proportions must be finite nonnegative numbers")
    if abs(sum(proportions.values()) - 1.0) > 1e-9:
        raise ValueError("split proportions must sum to 1.0")
    if any(not isinstance(name, str) or not name for name in proportions):
        raise ValueError("split names must be nonempty strings")
    if set(proportions) - {"train", "validation", "test", "evaluation"}:
        raise ValueError("unsupported split name")
    if sum(proportions.values()) <= 0:
        raise ValueError("split proportions must have a positive total")
    records = list(records)
    clusters = cluster_by_record or {}
    group_for: dict[str, str] = {}
    for record in records:
        if group_by_source:
            group = "source:" + record.source_id
        else:
            group = "cluster:" + clusters.get(record.record_id, record.record_id)
        group_for[record.record_id] = group
    assignment: dict[str, str] = {}
    sorted_splits = sorted(proportions)
    for group in sorted(set(group_for.values())):
        digest = hashlib.sha256(f"{seed}\0{group}".encode("utf-8")).digest()
        value = int.from_bytes(digest[:8], "big") / 2**64
        boundary = 0.0
        selected = sorted_splits[-1]
        for split in sorted_splits:
            boundary += proportions[split]
            if value < boundary:
                selected = split
                break
        assignment[group] = selected
    out: list[NormalizedRecord] = []
    for record in records:
        record.split_assignment = assignment[group_for[record.record_id]]
        out.append(record)
    counts: dict[str, int] = defaultdict(int)
    for record in out:
        counts[record.split_assignment or "unassigned"] += 1
    manifest = {
        "seed": seed,
        "proportions": dict(sorted(proportions.items())),
        "group_policy": "source_id" if group_by_source else "duplicate_cluster_or_record_id",
        "group_assignments": dict(sorted(assignment.items())),
        "counts": dict(sorted(counts.items())),
        "record_count": len(out),
        "limitations": [
            "Hash-threshold assignment is deterministic but small groups may produce empty splits or proportions far from targets.",
            "Only supplied duplicate clusters are protected; unobserved near-duplicates can still leak.",
        ],
    }
    return out, manifest


def assert_no_group_leakage(records: Iterable[NormalizedRecord], *, cluster_by_record: dict[str, str] | None = None,
                            group_by_source: bool = False) -> None:
    clusters = cluster_by_record or {}
    seen: dict[str, str] = {}
    for record in records:
        group = "source:" + record.source_id if group_by_source else "cluster:" + clusters.get(record.record_id, record.record_id)
        split = record.split_assignment
        if group in seen and seen[group] != split:
            raise ValueError(f"Protected group spans splits: {group}")
        seen[group] = split or ""
