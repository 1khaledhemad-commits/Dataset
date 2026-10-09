"""Composable bounded end-to-end pipelines with explicit fixture labeling."""

from __future__ import annotations

import hashlib
import json
import resource
import shutil
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .acquisition import DownloadPolicy, acquire_fixture, acquire_http
from .audit import append_audit_event
from .config import load_json_yaml, source_by_id, validate_pipeline_config, validate_registry
from .deduplication import benchmark_near_duplicate_detector, deduplicate
from .errors import PipelineError
from .extraction import extract_artifact
from .models import NormalizedRecord
from .normalization import normalize_record
from .quality import assess_quality
from .releases import create_release, verify_release
from .reporting import build_run_report, current_peak_rss_bytes, utc_now, write_report
from .splitting import assert_no_group_leakage, split_records
from .storage import read_jsonl, sha256_file, write_json_atomic, write_jsonl_atomic
from .validation import validate_record


def _read_registry(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    registry = load_json_yaml(root / "config" / "source_registry.yaml")
    config = load_json_yaml(root / "config" / "pipeline.json")
    registry_errors = validate_registry(registry)
    config_errors = validate_pipeline_config(config)
    if registry_errors or config_errors:
        errors = registry_errors + config_errors
        raise PipelineError("Project configuration invalid: " + "; ".join(errors[:10]), code="config_invalid")
    return registry, config


def _dedup_benchmark(root: Path, threshold: float) -> dict[str, Any]:
    labels_path = root / "tests" / "fixtures" / "near_duplicate_labels.jsonl"
    labels = [(row["left"], row["right"], bool(row["is_duplicate"])) for row in read_jsonl(labels_path)]
    return benchmark_near_duplicate_detector(labels, threshold=threshold)


def _tree_bytes(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    for item in path.rglob("*"):
        if item.is_file() and not item.is_symlink():
            total += item.stat().st_size
    return total


def _current_rss_bytes() -> int | None:
    try:
        for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def _usage_snapshot() -> tuple[float, float]:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return usage.ru_utime, usage.ru_stime


def _check_runtime_limits(root: Path, config: dict[str, Any], start_clock: float) -> None:
    resources = config["resources"]
    max_duration = int(resources.get("max_processing_duration_seconds", 900))
    if time.monotonic() - start_clock > max_duration:
        raise PipelineError("Configured processing duration was exceeded", code="processing_time_limit")
    rss = _current_rss_bytes()
    memory_limit = int(resources.get("max_memory_worker_bytes", 0))
    if rss is not None and memory_limit > 0 and rss > memory_limit:
        raise PipelineError("Observed process RSS exceeded the configured stage memory budget", code="memory_budget_exceeded")
    if _tree_bytes(root / "data" / "staging") > int(resources.get("max_staging_storage_bytes", 64 * 1024 * 1024)):
        raise PipelineError("Staging storage quota exceeded", code="staging_quota_exceeded")


def _load_notice(root: Path, source: dict[str, Any]) -> tuple[str | None, str | None]:
    license_info = source.get("license", {})
    relative_path = license_info.get("license_text_path")
    if not relative_path:
        return None, None
    path = (root / str(relative_path)).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise PipelineError("License notice path escapes the project root", code="unsafe_notice_path") from exc
    if not path.is_file():
        raise PipelineError("Required source license notice file is missing", code="license_notice_missing")
    text = path.read_text(encoding="utf-8")
    return text, hashlib.sha256(text.encode("utf-8")).hexdigest()


def _run_stages_impl(
    root: Path,
    *,
    source: dict[str, Any],
    asset: dict[str, Any],
    artifact: dict[str, Any],
    artifact_path: Path,
    run_id: str,
    fixture_only: bool,
    started_at: str,
    start_clock: float,
    start_cpu: tuple[float, float],
    download_attempts: int = 0,
    network_bytes: int = 0,
    acquisition_skipped_existing: bool = False,
) -> dict[str, Any]:
    config = load_json_yaml(root / "config" / "pipeline.json")
    config_errors = validate_pipeline_config(config)
    if config_errors:
        raise PipelineError("Pipeline configuration invalid: " + "; ".join(config_errors[:10]), code="config_invalid")
    data_root = root / "data"
    staging_root = data_root / "staging"
    runs_root = staging_root / "runs"
    if any(path.is_symlink() for path in (data_root, staging_root, runs_root)):
        raise PipelineError("Pipeline staging paths must not be symbolic links", code="unsafe_storage_path")
    run_dir = runs_root / run_id
    run_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    resource_policy = config["resources"]
    _check_runtime_limits(root, config, start_clock)

    extraction_stats: dict[str, int] = {}
    record_limit = min(int(resource_policy.get("max_records_per_job", 10_000)),
                       int(asset.get("max_records", resource_policy.get("max_records_per_job", 10_000))))
    extracted = list(extract_artifact(
        artifact_path, source=source, asset=asset, artifact_manifest=artifact,
        text_field=asset.get("text_field"), max_records=record_limit,
        max_expanded_bytes=int(resource_policy.get("max_archive_expansion_bytes", 32 * 1024 * 1024)),
        stats=extraction_stats,
    ))
    extracted_path = run_dir / "extracted.jsonl"
    write_jsonl_atomic(extracted_path, (record.__dict__ for record in extracted))
    _check_runtime_limits(root, config, start_clock)

    normalized = [normalize_record(record) for record in extracted]
    normalized_path = run_dir / "normalized.jsonl"
    write_jsonl_atomic(normalized_path, (record.to_dict() for record in normalized))
    validation_results = [validate_record(record) for record in normalized]
    structurally_valid = sum(result.valid for result in validation_results)
    purpose = "fixture_validation" if fixture_only else str(asset.get("dataset_purpose", "pretraining"))
    quality_policy = config.get("quality_profiles", {})
    quality_source = dict(source)
    if fixture_only:
        quality_source["eligibility"] = "APPROVED"
        quality_source["trust_level"] = "high"
        quality_source["trust_justification"] = "local test fixture; explicitly excluded from training"
    assessments = [assess_quality(record, result, quality_source, purpose=purpose, policy=quality_policy)
                   for record, result in zip(normalized, validation_results)]
    outcome_by_id = {assessment.record_id: assessment.outcome for assessment in assessments}
    assessment_path = run_dir / "quality_assessments.jsonl"
    write_jsonl_atomic(assessment_path, (assessment.to_dict() for assessment in assessments))
    rejected = [record for record in normalized if outcome_by_id[record.record_id] == "REJECT"]
    quarantined = [record for record in normalized if outcome_by_id[record.record_id] in {"QUARANTINE", "NEEDS_HUMAN_REVIEW"}]
    quarantine_path = root / "data" / "quarantine" / source["source_id"] / f"{run_id}.jsonl"
    if quarantined:
        quarantine_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            quarantine_path.parent.chmod(0o700)
        except OSError:
            pass
        write_jsonl_atomic(quarantine_path, (record.to_dict() for record in quarantined))
    rejected_path = run_dir / "rejected.jsonl"
    if rejected:
        write_jsonl_atomic(rejected_path, (record.to_dict() for record in rejected))
    keepable = [record for record in normalized if outcome_by_id[record.record_id] in {"ACCEPT", "ACCEPT_WITH_WARNINGS"}]
    _check_runtime_limits(root, config, start_clock)

    dedup_config = config.get("deduplication", {})
    threshold = float(dedup_config.get("near_duplicate_jaccard_threshold", 0.75))
    shingle_size = int(dedup_config.get("shingle_size", 5))
    pairwise_cap = int(dedup_config.get("max_records_for_pairwise", 2000))
    if len(keepable) > pairwise_cap:
        raise PipelineError(f"Pairwise deduplication is capped at {pairwise_cap} records", code="dedup_record_limit")
    deduped, decisions = deduplicate(keepable, threshold=threshold, shingle_size=shingle_size, qualities=outcome_by_id)
    decisions_json = [decision.to_dict() for decision in decisions]
    cluster_by_record = {decision.record_id: decision.cluster_id for decision in decisions}
    dedup_path = run_dir / "dedup_decisions.jsonl"
    write_jsonl_atomic(dedup_path, decisions_json)
    for record in deduped:
        record.provenance["duplicate_cluster_id"] = cluster_by_record.get(record.record_id, "")
    deduped_path = run_dir / "deduplicated.jsonl"
    write_jsonl_atomic(deduped_path, (record.to_dict() for record in deduped))
    if not deduped:
        raise PipelineError("No records passed the configured quality and source gates", code="no_usable_records")
    _check_runtime_limits(root, config, start_clock)

    split_config = config.get("splits", {})
    split_by_source = bool(asset.get("group_by_source", False))
    held_out_evaluation = not fixture_only and (purpose == "evaluation" or bool(source.get("evaluation_only", False)))
    proportions = ({"evaluation": 1.0} if held_out_evaluation else
                   split_config.get("proportions", {"train": 0.8, "validation": 0.1, "test": 0.1}))
    split_seed = int(asset.get("split_seed", split_config.get("seed", 20261009)))
    split_records_out, split_manifest = split_records(
        deduped, seed=split_seed, proportions=proportions, group_by_source=split_by_source,
        cluster_by_record=cluster_by_record,
    )
    assert_no_group_leakage(split_records_out, cluster_by_record=cluster_by_record, group_by_source=split_by_source)
    split_path = run_dir / "split_records.jsonl"
    _, split_bytes, split_sha = write_jsonl_atomic(split_path, (record.to_dict() for record in split_records_out))
    split_manifest.update({"output_sha256": split_sha, "output_bytes": split_bytes})
    split_manifest_path = run_dir / "split_manifest.json"
    write_json_atomic(split_manifest_path, split_manifest)
    _check_runtime_limits(root, config, start_clock)

    license_text, license_text_sha = _load_notice(root, source)
    source_manifest_ref = [{
        "source_id": source["source_id"], "source_revision": source.get("source_revision"),
        "asset_id": asset["asset_id"], "artifact_sha256": artifact.get("sha256"),
        "source_git_blob_sha1": asset.get("source_git_blob_sha1"),
        "license_id": source.get("license", {}).get("spdx_id") or source.get("license", {}).get("name"),
        "license_url": source.get("license", {}).get("url"),
        "eligibility": source.get("eligibility"),
        "evaluation_only": bool(source.get("evaluation_only", False)),
    }]
    outcome_counts = Counter(assessment.outcome for assessment in assessments)
    release_id = ("fixture-smoke-" if fixture_only else "candidate-") + run_id
    release_purpose = "fixture_validation" if fixture_only else purpose
    license_decision = {
        "eligibility": source.get("eligibility"),
        "evaluation_only": bool(source.get("evaluation_only", False)),
        "license": source.get("license", {}).get("name"),
        "license_id": source.get("license", {}).get("spdx_id"),
        "license_url": source.get("license", {}).get("url"),
        "training_use": source.get("license", {}).get("training_use", "unknown"),
        "evaluation_use": source.get("license", {}).get("evaluation_use", "unknown"),
        "redistribution": source.get("redistribution", "unknown"),
        "restrictions": source.get("restrictions", []),
        "license_text_sha256": license_text_sha,
        "license_text": license_text,
        "attribution": source.get("attribution", []),
    }
    metadata = {
        "pipeline_version": "0.1.0",
        "configuration_sha256": hashlib.sha256((root / "config" / "pipeline.json").read_bytes()).hexdigest(),
        "dataset_purpose": release_purpose,
        "source_manifest": source_manifest_ref,
        "source_license_decisions": {source["source_id"]: license_decision},
        "input_artifact_hashes": [artifact.get("sha256", "")],
        "transformations": ["UTF-8 strict source decoding", "Unicode NFC / LF normalization v1.0.0", "stable source-record ID v1.0.0"],
        "deduplication": {
            "method": "exact SHA-256 on NFC/LF-normalized content + word-shingle Jaccard near-dedup (not semantic)",
            "threshold": threshold, "shingle_size": shingle_size,
            "labeled_benchmark": _dedup_benchmark(root, threshold),
        },
        "quality_thresholds": quality_policy,
        "rejection_quarantine_statistics": {
            "quality_outcomes": dict(outcome_counts),
            "structurally_invalid": len(normalized) - structurally_valid,
            "duplicate_decisions": len(decisions),
            "records_deduplicated": sum(not decision.retained for decision in decisions),
        },
        "split_policy": split_manifest,
        "human_approval_status": "fixture_only_not_for_training" if fixture_only else "pending_owner_review",
        "max_release_storage_bytes": int(resource_policy.get("max_release_storage_bytes", 64 * 1024 * 1024)),
        "limitations": [
            "Source-level permission is not legal advice or owner approval; obey the recorded conditions.",
            "Quality classifiers are deterministic heuristics; sample review is not corpus-wide verification.",
            "Near-duplicate detection measures word-shingle overlap, not semantic equivalence.",
        ],
    }
    releases_root = root / "data" / "releases"
    release_manifest = create_release(
        split_records_out, releases_root=releases_root, release_id=release_id, metadata=metadata,
        manifest_only=not fixture_only,
    )
    release_verification = verify_release(
        releases_root / release_id,
        max_records=int(resource_policy.get("max_records_per_job", 10_000)),
        max_total_bytes=int(resource_policy.get("max_release_storage_bytes", 64 * 1024 * 1024)),
    )
    if not release_verification["valid"]:
        raise PipelineError("Created release failed verification", code="release_verification_failed")
    _check_runtime_limits(root, config, start_clock)

    finish = utc_now()
    elapsed = time.monotonic() - start_clock
    finish_cpu = _usage_snapshot()
    cpu_seconds = max(0.0, finish_cpu[0] - start_cpu[0]) + max(0.0, finish_cpu[1] - start_cpu[1])
    report = build_run_report(
        run_id=run_id, start_time=started_at, finish_time=finish,
        source_ids_attempted=[source["source_id"]],
        downloaded_bytes=0 if fixture_only else int(artifact.get("byte_count", 0)),
        acquired_artifacts=[artifact], extracted_count=len(extracted), records=normalized,
        structural_valid_count=structurally_valid, assessments=assessments,
        duplicate_decisions=decisions_json, release_manifest=release_manifest,
        fixture_only=fixture_only, input_paths=[str(artifact_path)],
        output_paths=[str(run_dir), str(releases_root / release_id)],
        peak_memory_bytes=current_peak_rss_bytes(), elapsed_seconds=elapsed,
    )
    report["measurements"].update({
        "source_records_scanned": extraction_stats.get("source_records_scanned", len(extracted)),
        "selected_records_emitted": extraction_stats.get("records_emitted", len(extracted)),
        "rejected_records": len(rejected),
        "needs_human_review_records": outcome_counts.get("NEEDS_HUMAN_REVIEW", 0),
        "quarantined_records": outcome_counts.get("QUARANTINE", 0),
        "rejection_reason_counts": dict(Counter(reason for assessment in assessments for reason in assessment.reasons)),
        "quality_distributions": _quality_distributions(assessments),
        "split_counts": split_manifest["counts"],
        "release_verification": release_verification,
        "raw_artifact_bytes": int(artifact.get("byte_count", 0)),
        "network_bytes_transferred": network_bytes,
        "download_attempts": download_attempts,
        "acquisition_skipped_existing": acquisition_skipped_existing,
        "cpu_time_seconds": round(cpu_seconds, 6),
        "peak_process_rss_bytes": current_peak_rss_bytes(),
        "quarantine_path": str(quarantine_path) if quarantined else None,
        "rejected_path": str(rejected_path) if rejected else None,
        "dedup_benchmark": metadata["deduplication"]["labeled_benchmark"],
        "source_sample_policy": {
            "sample_records": asset.get("sample_records"), "sample_seed": asset.get("sample_seed"),
            "sample_strategy": "stable SHA-256 priority sample; scan limit enforced" if asset.get("sample_records") else "all emitted records",
        },
    })
    reports_dir = root / "reports" / "runs" / run_id
    report_json, report_md = reports_dir / "run_report.json", reports_dir / "run_report.md"
    run_manifest_path = run_dir / "run_manifest.json"
    report["end_to_end_valid"] = release_verification["valid"] and all(validate_record(record).valid for record in deduped)
    report["promotion_status"] = "fixture_only_not_for_training" if fixture_only else "candidate_waiting_for_explicit_human_approval"
    report["release_manifest_only"] = bool(release_manifest.get("manifest_only"))
    report["run_manifest_path"] = str(run_manifest_path)
    report["release_path"] = str(releases_root / release_id)
    run_manifest = {
        "run_id": run_id, "start_time_utc": started_at, "finish_time_utc": finish,
        "source_id": source["source_id"], "asset_id": asset["asset_id"], "fixture_only": fixture_only,
        "artifact_manifest": artifact, "extraction_statistics": extraction_stats,
        "extracted_path": str(extracted_path), "normalized_path": str(normalized_path),
        "quality_assessments_path": str(assessment_path), "quarantine_path": str(quarantine_path) if quarantined else None,
        "rejected_path": str(rejected_path) if rejected else None, "dedup_decisions_path": str(dedup_path),
        "deduplicated_path": str(deduped_path), "split_records_path": str(split_path),
        "split_manifest_path": str(split_manifest_path), "release_id": release_id,
        "release_verification": release_verification, "report_json": str(report_json),
        "report_markdown": str(report_md), "measurements": report["measurements"],
    }
    write_json_atomic(run_manifest_path, run_manifest)
    write_report(report, reports_dir)
    return report


def _run_stages(root: str | Path, **kwargs: Any) -> dict[str, Any]:
    """Wrap stage execution with append-only, privacy-minimal run events."""
    root = Path(root).resolve()
    source = kwargs["source"]
    asset = kwargs["asset"]
    run_id = str(kwargs["run_id"])
    fixture_only = bool(kwargs["fixture_only"])
    event_base = {
        "run_id": run_id,
        "source_id": str(source.get("source_id", ""))[:80],
        "asset_id": str(asset.get("asset_id", ""))[:120],
        "fixture_only": fixture_only,
    }
    try:
        append_audit_event(root, {"event": "pipeline_run_started", **event_base})
    except OSError as exc:
        raise PipelineError("Unable to persist pipeline run audit event", code="audit_write_failed") from exc
    try:
        report = _run_stages_impl(root, **kwargs)
    except Exception as exc:
        error_code = exc.code if isinstance(exc, PipelineError) else type(exc).__name__
        try:
            append_audit_event(root, {"event": "pipeline_run_failed", **event_base, "error_code": error_code})
        except OSError as audit_exc:
            raise PipelineError("Pipeline failed and its audit event could not be persisted", code="audit_write_failed") from audit_exc
        raise
    measurements = report.get("measurements", {})
    try:
        append_audit_event(root, {
            "event": "pipeline_run_completed", **event_base,
            "end_to_end_valid": bool(report.get("end_to_end_valid")),
            "release_id": report.get("release_id"),
            "extracted_records": measurements.get("extracted_records"),
            "usable_records": measurements.get("usable_records"),
            "published_records": measurements.get("published_records"),
            "downloaded_bytes": measurements.get("downloaded_bytes"),
            "network_bytes_transferred": measurements.get("network_bytes_transferred"),
        })
    except OSError as exc:
        raise PipelineError("Pipeline completed but its audit event could not be persisted", code="audit_write_failed") from exc
    return report


def _quality_distributions(assessments: list[Any]) -> dict[str, list[float]]:
    keys = ("structural_validity", "language_confidence", "content_completeness",
            "information_density", "formatting_integrity", "source_trust", "license_eligibility",
            "privacy_safety", "task_suitability")
    return {key: [float(assessment.dimensions[key]) for assessment in assessments
                  if assessment.dimensions.get(key) is not None] for key in keys}


def run_fixture_smoke(root: str | Path) -> dict[str, Any]:
    root = Path(root).resolve()
    started_at = utc_now()
    start_clock = time.monotonic()
    start_cpu = _usage_snapshot()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    fixture_source = {
        "source_id": "local-fixture", "name": "Local pipeline validation fixtures", "source_type": "local_fixture",
        "eligibility": "APPROVED", "trust_level": "high", "trust_justification": "versioned in-repository fixtures, test-only",
        "license": {"name": "Project test fixture; not training corpus", "spdx_id": "CC0-1.0", "training_use": "permitted"},
        "redistribution": "permitted", "attribution": [], "personal_data_risk": "low",
        "restrictions": ["test-only", "not for model training"],
    }
    asset = {"asset_id": "smoke-fixtures", "format": "jsonl", "domain": "general", "task_type": "language_modeling",
             "dataset_purpose": "fixture_validation", "url": "fixture://tests/fixtures/smoke_records.jsonl",
             "text_field": "text", "max_records": 100}
    acquisition = acquire_fixture(
        fixture_source, asset, fixture_path=root / "tests" / "fixtures" / "smoke_records.jsonl",
        raw_root=root / "data" / "raw", max_bytes=1024 * 1024,
    )
    return _run_stages(
        root, source=fixture_source, asset=asset, artifact=acquisition.manifest.to_dict(),
        artifact_path=Path(acquisition.manifest.path), run_id=run_id, fixture_only=True,
        started_at=started_at, start_clock=start_clock, start_cpu=start_cpu,
        download_attempts=0, network_bytes=0, acquisition_skipped_existing=acquisition.skipped_existing,
    )


def run_http_asset(root: str | Path, *, source_id: str, asset_id: str, dry_run: bool = False) -> dict[str, Any]:
    root = Path(root).resolve()
    registry, config = _read_registry(root)
    source = source_by_id(registry, source_id)
    asset = next((candidate for candidate in source.get("assets", []) if candidate.get("asset_id") == asset_id), None)
    if asset is None:
        raise PipelineError("Requested asset is not present in the source registry", code="asset_not_found")
    if dry_run:
        policy = _download_policy(config)
        plan = acquire_http(source, asset, raw_root=root / "data" / "raw", policy=policy,
                            per_source_quota_bytes=int(config["resources"]["max_per_source_bytes"]),
                            source_revision=source.get("source_revision"), dry_run=True)
        return {"dry_run": True, "acquisition_plan": plan}

    started_at = utc_now()
    start_clock = time.monotonic()
    start_cpu = _usage_snapshot()
    result = acquire_http(
        source, asset, raw_root=root / "data" / "raw", policy=_download_policy(config),
        per_source_quota_bytes=int(config["resources"]["max_per_source_bytes"]),
        source_revision=source.get("source_revision"),
    )
    manifest = result.manifest.to_dict()
    if result.skipped_existing:
        runs_root = root / "data" / "staging" / "runs"
        for run_manifest_path in sorted(runs_root.glob("*/run_manifest.json")) if runs_root.exists() else []:
            previous = json.loads(run_manifest_path.read_text(encoding="utf-8"))
            if (previous.get("artifact_manifest", {}).get("sha256") == manifest["sha256"] and
                    previous.get("source_id") == source_id and previous.get("asset_id") == asset_id):
                report_path = Path(previous["report_json"])
                report = json.loads(report_path.read_text(encoding="utf-8"))
                report["acquisition_skipped_existing"] = True
                report["download_attempts"] = 0
                return report
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    report = _run_stages(
        root, source=source, asset=asset, artifact=manifest, artifact_path=Path(manifest["path"]),
        run_id=run_id, fixture_only=False, started_at=started_at, start_clock=start_clock,
        start_cpu=start_cpu, download_attempts=result.attempts,
        network_bytes=result.network_bytes_downloaded, acquisition_skipped_existing=result.skipped_existing,
    )
    return report


def _download_policy(config: dict[str, Any]) -> DownloadPolicy:
    resources = config["resources"]
    acquisition = config["acquisition"]
    rate = float(acquisition.get("requests_per_host_per_second", 0.5))
    return DownloadPolicy(
        max_total_bytes=int(resources["max_total_download_bytes"]),
        max_raw_storage_bytes=int(resources["max_raw_storage_bytes"]),
        max_single_file_bytes=int(resources["max_single_file_bytes"]),
        max_expanded_bytes=int(resources["max_archive_expansion_bytes"]),
        free_disk_reserve_bytes=int(resources["free_disk_safety_reserve_bytes"]),
        timeout_seconds=float(acquisition["timeout_seconds"]),
        max_retries=int(acquisition["max_retries"]),
        backoff_seconds=float(acquisition["backoff_seconds"]),
        jitter_seconds=float(acquisition["jitter_seconds"]),
        allowed_hosts=tuple(config["allowed_download_hosts"]),
        min_request_interval_seconds=1.0 / rate,
        max_redirects=int(acquisition.get("redirect_limit", 5)),
        resume_partial_downloads=bool(acquisition.get("resume_partial_downloads", True)),
    )
