"""Observed run reports. Fields are measurements, not source-size estimates."""

from __future__ import annotations

import json
import os
import resource
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import NormalizedRecord, QualityAssessment
from .storage import sha256_file, write_json_atomic, write_text_atomic


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def current_peak_rss_bytes() -> int | None:
    try:
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # Linux reports KiB; macOS reports bytes.
        return int(value if os.uname().sysname == "Darwin" else value * 1024)
    except (AttributeError, OSError, ValueError):
        return None


def build_run_report(
    *, run_id: str, start_time: str, finish_time: str, source_ids_attempted: list[str],
    downloaded_bytes: int, acquired_artifacts: list[dict[str, Any]], extracted_count: int,
    records: list[NormalizedRecord], structural_valid_count: int, assessments: list[QualityAssessment],
    duplicate_decisions: list[dict[str, Any]], release_manifest: dict[str, Any] | None,
    failure_counts: dict[str, int] | None = None, fixture_only: bool = False,
    input_paths: list[str] | None = None, output_paths: list[str] | None = None,
    peak_memory_bytes: int | None = None, elapsed_seconds: float | None = None,
) -> dict[str, Any]:
    outcomes = Counter(a.outcome for a in assessments)
    language_counts = Counter(r.language for r in records)
    domain_counts = Counter(r.domain for r in records)
    task_counts = Counter(r.task_type for r in records)
    duplicate_count = sum(not bool(d.get("retained")) for d in duplicate_decisions)
    near_count = sum(d.get("method") == "near_duplicate_word_shingle_jaccard" for d in duplicate_decisions if not d.get("retained"))
    unique_records = sum(bool(d.get("retained")) for d in duplicate_decisions) if duplicate_decisions else len(records)
    accepted = outcomes.get("ACCEPT", 0) + outcomes.get("ACCEPT_WITH_WARNINGS", 0)
    usable = max(0, min(unique_records, accepted))
    elapsed = elapsed_seconds if elapsed_seconds is not None else 0.0
    report = {
        "report_version": "1.0.0",
        "run_id": run_id,
        "start_time_utc": start_time,
        "finish_time_utc": finish_time,
        "source_ids_attempted": source_ids_attempted,
        "fixture_only": fixture_only,
        "input_paths": input_paths or [],
        "output_paths": output_paths or [],
        "measurements": {
            "downloaded_bytes": downloaded_bytes,
            "successful_artifacts": len(acquired_artifacts),
            "artifact_hashes": [a.get("sha256") for a in acquired_artifacts],
            "extracted_records": extracted_count,
            "structurally_valid_records": structural_valid_count,
            "normalized_records": len(records),
            "quality_outcomes": dict(sorted(outcomes.items())),
            "rejected_records": outcomes.get("REJECT", 0),
            "quarantined_records": outcomes.get("QUARANTINE", 0),
            "exact_duplicate_records": sum(d.get("method") == "exact" and not d.get("retained") for d in duplicate_decisions),
            "near_duplicate_records": near_count,
            "unique_records": unique_records,
            "usable_records": usable,
            "published_records": (release_manifest or {}).get("counts", {}).get("published_records", 0),
            "language_counts": dict(sorted(language_counts.items())),
            "domain_counts": dict(sorted(domain_counts.items())),
            "task_counts": dict(sorted(task_counts.items())),
            "throughput_records_per_second": round(extracted_count / elapsed, 3) if elapsed > 0 else None,
            "elapsed_seconds": round(elapsed, 3),
            "peak_process_rss_bytes": peak_memory_bytes,
            "storage_bytes_in_release": (release_manifest or {}).get("byte_size", 0),
        },
        "failures_by_category": dict(sorted((failure_counts or {}).items())),
        "release_id": (release_manifest or {}).get("release_id"),
        "limitations": [
            "Language labels and several content-quality gates use deterministic script/text heuristics, not validated language or semantic models.",
            "Near-duplicate detection is word-shingle Jaccard, not semantic deduplication; it only detects overlap above the recorded threshold.",
            "A successful quality gate does not establish legal, ethical, or factual correctness beyond source-registry decisions.",
        ],
    }
    return report


def write_report(report: dict[str, Any], output_dir: str | Path) -> tuple[Path, Path]:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "run_report.json"
    write_json_atomic(json_path, report)
    md_path = output_dir / "run_report.md"
    measurements = report["measurements"]
    lines = [
        f"# Run report: {report['run_id']}", "",
        f"- Start (UTC): {report['start_time_utc']}",
        f"- Finish (UTC): {report['finish_time_utc']}",
        f"- Fixture-only: **{report['fixture_only']}**",
        f"- Source IDs attempted: {', '.join(report['source_ids_attempted']) or 'none'}", "",
        "## Observed counts", "",
        "| Metric | Value |", "|---|---:|",
    ]
    for key in ("downloaded_bytes", "successful_artifacts", "extracted_records", "structurally_valid_records",
                "normalized_records", "exact_duplicate_records", "near_duplicate_records", "unique_records",
                "usable_records", "published_records", "elapsed_seconds", "peak_process_rss_bytes"):
        lines.append(f"| {key} | {measurements.get(key)} |")
    lines.extend(["", "## Quality outcomes", "", "```json",
                  json.dumps(measurements.get("quality_outcomes", {}), ensure_ascii=False, indent=2), "```", "",
                  "## Language counts", "", "```json",
                  json.dumps(measurements.get("language_counts", {}), ensure_ascii=False, indent=2), "```", "",
                  "## Limitations", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    lines.append("")
    write_text_atomic(md_path, "\n".join(lines))
    return json_path, md_path
