"""Validated command line interface for acquisition, curation and releases."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from . import __version__
from .acquisition import DownloadPolicy, acquire_fixture, acquire_http
from .config import load_json_yaml, source_by_id, validate_pipeline_config, validate_registry
from .deduplication import benchmark_near_duplicate_detector, deduplicate
from .errors import PipelineError
from .extraction import extract_artifact
from .models import ExtractedRecord, NormalizedRecord
from .monitoring import doctor
from .normalization import classify_language, normalize_record
from .pipeline import run_fixture_smoke, run_http_asset
from .quality import assess_quality
from .releases import create_release, verify_release
from .reporting import utc_now, write_report
from .sources import eligibility_for_training
from .splitting import assert_no_group_leakage, split_records
from .storage import read_jsonl, sha256_file, write_json_atomic, write_jsonl_atomic, write_text_atomic
from .validation import validate_record, validate_jsonl_file


def _policy(root: Path, raw: dict[str, Any]) -> DownloadPolicy:
    res = raw.get("resources", {})
    net = raw.get("acquisition", {})
    return DownloadPolicy(
        max_total_bytes=int(res.get("max_total_download_bytes", 128 * 1024 * 1024)),
        max_raw_storage_bytes=int(res.get("max_raw_storage_bytes", 256 * 1024 * 1024)),
        max_single_file_bytes=int(res.get("max_single_file_bytes", 16 * 1024 * 1024)),
        max_expanded_bytes=int(res.get("max_archive_expansion_bytes", 64 * 1024 * 1024)),
        free_disk_reserve_bytes=int(res.get("free_disk_safety_reserve_bytes", 512 * 1024 * 1024)),
        timeout_seconds=float(net.get("timeout_seconds", 20)),
        max_retries=int(net.get("max_retries", 3)),
        backoff_seconds=float(net.get("backoff_seconds", 0.25)),
        jitter_seconds=float(net.get("jitter_seconds", 0.10)),
        allowed_hosts=tuple(raw.get("allowed_download_hosts", ["github.com", "api.github.com", "codeload.github.com"])),
        min_request_interval_seconds=1.0 / float(net["requests_per_host_per_second"]),
        max_redirects=int(net.get("redirect_limit", 5)),
        resume_partial_downloads=bool(net.get("resume_partial_downloads", True)),
    )


def _load_records(path: str | Path, *, max_records: int = 100_000,
                  max_bytes: int = 64 * 1024 * 1024) -> list[NormalizedRecord]:
    records: list[NormalizedRecord] = []
    for row in read_jsonl(path, max_records=max_records, max_bytes=max_bytes):
        try:
            records.append(NormalizedRecord.from_dict(row))
        except (TypeError, ValueError) as exc:
            raise PipelineError(f"Invalid normalized record in {path}", code="invalid_record") from exc
    return records


def _write_json(path: str | Path, value: Any) -> None:
    if isinstance(value, dict):
        write_json_atomic(path, value)
    else:
        write_text_atomic(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def _resolve_artifact(root: Path, source: dict[str, Any], asset: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    fmt = asset["format"]
    path = root / "data" / "raw" / source["source_id"] / f"{asset['asset_id']}.{fmt}"
    manifest_path = path.parent / f"{asset['asset_id']}.manifest.json"
    if any(item.is_symlink() for item in (root / "data", root / "data" / "raw", path.parent, path, manifest_path)):
        raise PipelineError("Raw artifact paths must not be symbolic links", code="unsafe_storage_path")
    if not path.is_file() or not manifest_path.is_file():
        raise PipelineError("Raw artifact or its manifest is missing; run `data-platform acquire` first", code="artifact_missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("source_id") != source.get("source_id") or manifest.get("asset_id") != asset.get("asset_id"):
        raise PipelineError("Raw artifact manifest identity does not match the registry request", code="artifact_manifest_mismatch")
    if manifest.get("sha256") != sha256_file(path):
        raise PipelineError("Raw artifact hash does not match its manifest", code="artifact_hash_mismatch")
    return path, manifest


def _make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="data-platform", description="Auditable, bounded AI-FOUNDATION data pipeline")
    parser.add_argument("--root", default=".", help="project root (default: current directory)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="inspect current resource boundaries without network activity")

    sources = sub.add_parser("sources", help="source registry governance")
    ssub = sources.add_subparsers(dest="sources_command", required=True)
    ssub.add_parser("list", help="list registered sources and eligibility")
    ssub.add_parser("validate", help="validate every registered source field")
    discover = ssub.add_parser("discover", help="rank governed registry candidates without live network calls")
    discover.add_argument("--language", action="append", help="filter by language label; repeat to match any")
    discover.add_argument("--domain", action="append", help="filter by domain; repeat to match any")
    discover.add_argument("--task", action="append", help="filter by asset task type; repeat to match any")
    discover.add_argument("--include-unverified", action=argparse.BooleanOptionalAction, default=True)
    discover.add_argument("--include-blocked", action=argparse.BooleanOptionalAction, default=True)

    plan = sub.add_parser("plan", help="show bounded eligible acquisition plan; no downloads")
    plan.add_argument("--dry-run", action="store_true", default=True)

    acquire = sub.add_parser("acquire", help="acquire one explicitly registered, approved asset")
    acquire.add_argument("source_id")
    acquire.add_argument("asset_id")
    acquire.add_argument("--dry-run", action="store_true")
    acquire.add_argument("--refresh", action="store_true", help="explicitly re-fetch; never overwrite a verified artifact silently")

    for name, help_text in (("extract", "extract records from a verified raw artifact"),
                            ("normalize", "normalize extracted JSONL records"),
                            ("validate", "validate normalized JSONL records"),
                            ("deduplicate", "remove exact and near-duplicate records"),
                            ("classify", "measure script-based language labels"),
                            ("evaluate", "apply language/task/source-aware quality gates"),
                            ("split", "assign reproducible group-aware splits"),
                            ("release", "atomically publish an immutable dataset release"),
                            ("report", "summarize an observed run report")):
        item = sub.add_parser(name, help=help_text)
        if name in {"normalize", "validate", "deduplicate", "classify", "evaluate", "split", "release", "report"}:
            item.add_argument("--input", required=True)
        if name in {"normalize", "deduplicate", "split"}:
            item.add_argument("--output", required=True)
        if name == "extract":
            item.add_argument("source_id")
            item.add_argument("asset_id")
            item.add_argument("--output", required=True)
            item.add_argument("--text-field")
            item.add_argument("--max-records", type=int, default=100_000)
        if name == "validate":
            item.add_argument("--output")
        if name == "deduplicate":
            item.add_argument("--threshold", type=float, default=0.75)
            item.add_argument("--decisions", required=True)
        if name == "classify":
            item.add_argument("--output", required=True)
        if name == "evaluate":
            item.add_argument("--output", required=True)
            item.add_argument("--purpose", choices=("pretraining", "sft", "preference", "evaluation", "expert"), default="pretraining")
        if name == "split":
            item.add_argument("--seed", type=int, required=True)
            item.add_argument("--proportions", default='{"train":0.90,"validation":0.05,"test":0.05}')
            item.add_argument("--group-by-source", action="store_true")
            item.add_argument("--output-manifest", required=True)
            item.add_argument("--dedup-decisions", help="deduplication decision JSONL used to protect duplicate clusters")
        if name == "release":
            item.add_argument("--release-id", required=True)
            item.add_argument("--purpose", choices=("pretraining", "sft", "preference", "evaluation", "expert"), default="pretraining")
            item.add_argument("--manifest-only", action="store_true")
            item.add_argument("--metadata", help="JSON metadata file")
        if name == "report":
            item.add_argument("--output", required=True)
    run = sub.add_parser("run", help="acquire, curate, split and release one approved registered asset")
    run.add_argument("source_id")
    run.add_argument("asset_id")
    run.add_argument("--dry-run", action="store_true", help="show an acquisition plan only; do not download or write pipeline outputs")
    sub.add_parser("smoke", help="run the bounded, offline fixture-only end-to-end path")
    verify = sub.add_parser("verify-release", help="verify a release manifest, record schema and file hashes")
    verify.add_argument("release_path")
    return parser


def _run(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    config_path = root / "config" / "pipeline.json"
    registry_path = root / "config" / "source_registry.yaml"
    if args.command == "doctor":
        print(json.dumps(doctor(root), indent=2, sort_keys=True))
        return 0
    if args.command == "run":
        report = run_http_asset(root, source_id=args.source_id, asset_id=args.asset_id, dry_run=args.dry_run)
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
        if args.dry_run:
            return 0
        return 0 if report.get("end_to_end_valid") else 1
    if args.command == "smoke":
        report = run_fixture_smoke(root)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report.get("end_to_end_valid") else 1
    if args.command == "verify-release":
        verify_config = load_json_yaml(config_path)
        verify_errors = validate_pipeline_config(verify_config)
        if verify_errors:
            raise PipelineError("Pipeline configuration invalid: " + "; ".join(verify_errors[:10]), code="config_invalid")
        resources = verify_config["resources"]
        result = verify_release(
            root / args.release_path if not Path(args.release_path).is_absolute() else args.release_path,
            max_records=int(resources["max_records_per_job"]),
            max_total_bytes=int(resources["max_release_storage_bytes"]),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["valid"] else 1
    if args.command == "report":
        report_path = Path(args.input)
        if report_path.is_symlink() or not report_path.is_file() or report_path.stat().st_size > 2 * 1024 * 1024:
            raise PipelineError("Report input must be a regular file no larger than 2 MiB", code="report_input_limit")
        value = json.loads(report_path.read_text(encoding="utf-8"))
        paths = write_report(value, args.output)
        print(json.dumps({"json": str(paths[0]), "markdown": str(paths[1])}, indent=2))
        return 0
    registry = load_json_yaml(registry_path)
    registry_errors = validate_registry(registry)
    if registry_errors:
        raise PipelineError("Source registry invalid: " + "; ".join(registry_errors[:10]), code="registry_invalid")
    config = load_json_yaml(config_path)
    config_errors = validate_pipeline_config(config)
    if config_errors:
        raise PipelineError("Pipeline configuration invalid: " + "; ".join(config_errors[:10]), code="config_invalid")
    if args.command == "sources":
        if args.sources_command == "validate":
            print(json.dumps({"valid": True, "source_count": len(registry["sources"]), "registry_version": registry["registry_version"]}, indent=2))
            return 0
        if args.sources_command == "discover":
            requested_languages = {value.casefold() for value in (args.language or [])}
            requested_domains = {value.casefold() for value in (args.domain or [])}
            requested_tasks = {value.casefold() for value in (args.task or [])}
            candidates = []
            for source in registry["sources"]:
                if not args.include_unverified and source["eligibility"] not in {"APPROVED", "APPROVED_WITH_RESTRICTIONS"}:
                    continue
                if not args.include_blocked and source["eligibility"] in {"NEEDS_REVIEW", "REJECTED", "TEMPORARILY_UNAVAILABLE"}:
                    continue
                languages = {str(value).casefold() for value in source.get("languages", [])}
                domains = {str(value).casefold() for value in source.get("domains", [])}
                asset_domains = {str(asset.get("domain", "")).casefold() for asset in source.get("assets", [])}
                tasks = {str(asset.get("task_type", "")).casefold() for asset in source.get("assets", [])}
                if requested_languages and not languages.intersection(requested_languages):
                    continue
                if requested_domains and not (domains | asset_domains).intersection(requested_domains):
                    continue
                if requested_tasks and not tasks.intersection(requested_tasks):
                    continue
                score = 2 * len(languages.intersection(requested_languages)) + len((domains | asset_domains).intersection(requested_domains)) + len(tasks.intersection(requested_tasks))
                candidates.append({
                    "source_id": source["source_id"], "name": source["name"],
                    "eligibility": source["eligibility"], "eligibility_reason": source["eligibility_reason"],
                    "languages": sorted(source.get("languages", [])), "domains": sorted(source.get("domains", [])),
                    "license": source["license"].get("name"),
                    "training_use": source["license"].get("training_use", "unknown"),
                    "evaluation_use": source["license"].get("evaluation_use", "unknown"),
                    "evaluation_only": bool(source.get("evaluation_only", False)),
                    "asset_count": len(source.get("assets", [])), "candidate_match_score": score,
                })
            candidates.sort(key=lambda row: (-row["candidate_match_score"], row["source_id"]))
            print(json.dumps({"candidates": candidates, "live_network_checks_performed": False,
                              "note": "Ranking uses registered metadata only. Confirm scope, permissions, and current provider terms before acquisition."}, indent=2, ensure_ascii=False))
            return 0
        rows = [{"source_id": s["source_id"], "name": s["name"], "eligibility": s["eligibility"],
                 "trust_level": s["trust_level"], "license": s["license"].get("name"),
                 "connector_status": s["connector_status"]} for s in registry["sources"]]
        print(json.dumps({"sources": rows, "live_network_checks_performed": False,
                          "note": "Use the source assessment report for timestamps and evidence; listing is not source verification."}, indent=2, ensure_ascii=False))
        return 0
    if args.command == "plan":
        items = []
        eligible_bytes = 0
        for source in registry["sources"]:
            for asset in source["assets"]:
                allowed, reason = eligibility_for_training(source, str(asset.get("dataset_purpose", "pretraining")))
                max_bytes = asset.get("max_bytes")
                if allowed and isinstance(max_bytes, int):
                    eligible_bytes += max_bytes
                items.append({"source_id": source["source_id"], "asset_id": asset["asset_id"],
                              "format": asset["format"], "max_bytes": max_bytes,
                              "url_host": urlparse(asset["url"]).hostname,
                              "status": "PLANNED_NOT_ACQUIRED" if allowed else "BLOCKED",
                              "eligibility_reason": reason})
        print(json.dumps({"dry_run": True, "assets": items,
                          "eligible_asset_count": sum(item["status"] == "PLANNED_NOT_ACQUIRED" for item in items),
                          "blocked_asset_count": sum(item["status"] == "BLOCKED" for item in items),
                          "resources": config["resources"], "plan_bytes_known": eligible_bytes}, indent=2, ensure_ascii=False))
        return 0
    if args.command == "acquire":
        source = source_by_id(registry, args.source_id)
        asset = next((a for a in source["assets"] if a["asset_id"] == args.asset_id), None)
        if asset is None:
            raise PipelineError(f"Unknown asset_id {args.asset_id} for source {args.source_id}", code="asset_not_found")
        result = acquire_http(source, asset, raw_root=root / "data" / "raw", policy=_policy(root, config),
                              per_source_quota_bytes=int(config["resources"].get("max_per_source_bytes", 64 * 1024 * 1024)),
                              source_revision=source.get("source_revision"), refresh=args.refresh, dry_run=args.dry_run)
        print(json.dumps(result.to_dict() if hasattr(result, "to_dict") else result, indent=2, ensure_ascii=False))
        return 0
    if args.command == "extract":
        source = source_by_id(registry, args.source_id)
        asset = next((a for a in source["assets"] if a["asset_id"] == args.asset_id), None)
        if asset is None:
            raise PipelineError(f"Unknown asset_id {args.asset_id}", code="asset_not_found")
        eligible, reason = eligibility_for_training(source, str(asset.get("dataset_purpose", "pretraining")))
        if not eligible:
            raise PipelineError(f"Source {source['source_id']} is not eligible for extraction/use: {reason}", code="source_not_eligible")
        raw_path, artifact_manifest = _resolve_artifact(root, source, asset)
        extraction_cap = min(args.max_records,
                             int(config["resources"]["max_records_per_job"]),
                             int(asset.get("max_records", config["resources"]["max_records_per_job"])))
        records = extract_artifact(raw_path, source=source, asset=asset, artifact_manifest=artifact_manifest,
                                   text_field=args.text_field, max_records=extraction_cap,
                                   max_expanded_bytes=int(config["resources"]["max_archive_expansion_bytes"]))
        count, byte_count, digest = write_jsonl_atomic(args.output, (r.__dict__ for r in records))
        print(json.dumps({"records": count, "bytes": byte_count, "sha256": digest, "output": args.output}, indent=2))
        return 0
    if args.command == "normalize":
        def rows():
            for raw in read_jsonl(args.input, max_records=int(config["resources"]["max_records_per_job"]),
                                  max_bytes=int(config["resources"]["max_staging_storage_bytes"])):
                try:
                    extracted = ExtractedRecord(**raw)
                except TypeError as exc:
                    raise PipelineError("Input row does not match extraction contract", code="invalid_extracted_record") from exc
                yield normalize_record(extracted).to_dict()
        count, size, digest = write_jsonl_atomic(args.output, rows())
        print(json.dumps({"normalized_records": count, "bytes": size, "sha256": digest}, indent=2))
        return 0
    if args.command == "validate":
        result = validate_jsonl_file(args.input, max_records=int(config["resources"]["max_records_per_job"]),
                                     max_bytes=int(config["resources"]["max_staging_storage_bytes"]))
        if args.output:
            _write_json(args.output, result)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result["valid"] else 1
    if args.command == "classify":
        records = _load_records(args.input, max_records=int(config["resources"]["max_records_per_job"]), max_bytes=int(config["resources"]["max_staging_storage_bytes"]))
        counts: Counter[str] = Counter()
        def rows():
            for record in records:
                language, confidence, composition = classify_language(record.text)
                record.language, record.language_confidence, record.script_composition = language, confidence, composition
                if language == "unknown" and "language_uncertain_script_heuristic" not in record.quality_flags:
                    record.quality_flags.append("language_uncertain_script_heuristic")
                counts[language] += 1
                yield record.to_dict()
        count, size, digest = write_jsonl_atomic(args.output, rows())
        print(json.dumps({"records": count, "language_counts": dict(counts), "bytes": size, "sha256": digest,
                          "method": "Unicode script heuristic; short-text uncertainty retained"}, indent=2))
        return 0
    if args.command == "evaluate":
        records = _load_records(args.input, max_records=int(config["resources"]["max_records_per_job"]), max_bytes=int(config["resources"]["max_staging_storage_bytes"]))
        sources = {s["source_id"]: s for s in registry["sources"]}
        assessments = []
        for record in records:
            assessment = assess_quality(record, validate_record(record), sources.get(record.source_id),
                                        purpose=args.purpose, policy=config.get("quality_profiles", {}))
            assessments.append(assessment.to_dict())
        count, size, digest = write_jsonl_atomic(args.output, assessments)
        print(json.dumps({"records": count, "outcomes": dict(Counter(a["outcome"] for a in assessments)),
                          "bytes": size, "sha256": digest}, indent=2))
        return 0
    if args.command == "deduplicate":
        if Path(args.output).exists() or Path(args.decisions).exists():
            raise PipelineError("Refusing to overwrite either deduplication output", code="output_exists")
        records = _load_records(args.input, max_records=int(config["resources"]["max_records_per_job"]), max_bytes=int(config["resources"]["max_staging_storage_bytes"]))
        pairwise_cap = int(config["deduplication"]["max_records_for_pairwise"])
        if len(records) > pairwise_cap:
            raise PipelineError(f"Pairwise deduplication is capped at {pairwise_cap} records", code="dedup_record_limit")
        kept, decisions = deduplicate(records, threshold=args.threshold,
                                      shingle_size=int(config["deduplication"]["shingle_size"]))
        count, size, digest = write_jsonl_atomic(args.output, (r.to_dict() for r in kept))
        write_jsonl_atomic(args.decisions, (d.to_dict() for d in decisions))
        print(json.dumps({"input_records": len(records), "unique_records": count,
                          "duplicate_records": sum(not d.retained for d in decisions), "threshold": args.threshold,
                          "method": "exact SHA-256 on NFC/LF-normalized content + word-shingle Jaccard near-dedup (not semantic)",
                          "output_bytes": size, "output_sha256": digest}, indent=2))
        return 0
    if args.command == "split":
        if Path(args.output).exists() or Path(args.output_manifest).exists():
            raise PipelineError("Refusing to overwrite split output or manifest", code="output_exists")
        records = _load_records(args.input, max_records=int(config["resources"]["max_records_per_job"]), max_bytes=int(config["resources"]["max_staging_storage_bytes"]))
        try:
            proportions = json.loads(args.proportions)
        except json.JSONDecodeError as exc:
            raise PipelineError("--proportions must be a JSON object", code="invalid_split_config") from exc
        if not isinstance(proportions, dict):
            raise PipelineError("--proportions must be a JSON object", code="invalid_split_config")
        cluster_by_record = {}
        if args.dedup_decisions:
            for decision in read_jsonl(args.dedup_decisions, max_records=int(config["resources"]["max_records_per_job"]),
                                       max_bytes=int(config["resources"]["max_staging_storage_bytes"])):
                cluster_by_record[decision["record_id"]] = decision["cluster_id"]
                cluster_by_record.setdefault(decision["retained_record_id"], decision["cluster_id"])
        evaluation_only_sources = {source["source_id"] for source in registry["sources"] if source.get("evaluation_only")}
        if any(record.source_id in evaluation_only_sources for record in records) and proportions.get("train", 0) > 0:
            raise PipelineError("Evaluation-only source records cannot be assigned to a training-capable split; use proportions with evaluation: 1.0",
                                code="evaluation_leakage_blocked")
        split_records_out, manifest = split_records(records, seed=args.seed, proportions=proportions,
                                                    group_by_source=args.group_by_source,
                                                    cluster_by_record=cluster_by_record)
        assert_no_group_leakage(split_records_out, cluster_by_record=cluster_by_record,
                                group_by_source=args.group_by_source)
        count, size, digest = write_jsonl_atomic(args.output, (r.to_dict() for r in split_records_out))
        manifest.update({"output_sha256": digest, "output_bytes": size})
        write_json_atomic(args.output_manifest, manifest)
        print(json.dumps(manifest, indent=2))
        return 0
    if args.command == "release":
        records = _load_records(args.input, max_records=int(config["resources"]["max_records_per_job"]), max_bytes=int(config["resources"]["max_staging_storage_bytes"]))
        if args.metadata:
            metadata_path = Path(args.metadata)
            if metadata_path.is_symlink() or not metadata_path.is_file() or metadata_path.stat().st_size > 1024 * 1024:
                raise PipelineError("Release metadata must be a regular file no larger than 1 MiB", code="invalid_release_metadata")
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        else:
            metadata = {}
        if not isinstance(metadata, dict):
            raise PipelineError("Release metadata root must be an object", code="invalid_release_metadata")
        if metadata.get("dataset_purpose", args.purpose) != args.purpose:
            raise PipelineError("CLI --purpose conflicts with release metadata", code="invalid_release_metadata")
        metadata["dataset_purpose"] = args.purpose
        provided_decisions = metadata.get("source_license_decisions", {})
        if provided_decisions and not isinstance(provided_decisions, dict):
            raise PipelineError("source_license_decisions must be an object", code="invalid_release_metadata")
        derived_decisions = {}
        derived_source_manifest = []
        for source_id in sorted({record.source_id for record in records}):
            source = source_by_id(registry, source_id)
            eligible, reason = eligibility_for_training(source, args.purpose)
            if not eligible:
                raise PipelineError(f"Source {source_id} is not eligible for release: {reason}", code="release_license_gate")
            license_info = source.get("license", {})
            license_text = None
            license_text_sha256 = None
            relative_notice = license_info.get("license_text_path")
            if relative_notice:
                notice_path = (root / str(relative_notice)).resolve()
                try:
                    notice_path.relative_to(root)
                except ValueError as exc:
                    raise PipelineError("License notice path escapes the project root", code="unsafe_notice_path") from exc
                if not notice_path.is_file():
                    raise PipelineError(f"License text is missing for source {source_id}", code="license_notice_missing")
                license_text = notice_path.read_text(encoding="utf-8")
                license_text_sha256 = hashlib.sha256(license_text.encode("utf-8")).hexdigest()
            decision = {
                "eligibility": source.get("eligibility"),
                "evaluation_only": bool(source.get("evaluation_only", False)),
                "license": license_info.get("name"), "license_id": license_info.get("spdx_id"),
                "license_url": license_info.get("url"),
                "training_use": license_info.get("training_use", "unknown"),
                "evaluation_use": license_info.get("evaluation_use", "unknown"),
                "redistribution": source.get("redistribution", "unknown"),
                "restrictions": source.get("restrictions", []), "attribution": source.get("attribution", []),
                "license_text": license_text, "license_text_sha256": license_text_sha256,
            }
            provided = provided_decisions.get(source_id) if isinstance(provided_decisions, dict) else None
            if isinstance(provided, dict):
                for field in ("eligibility", "evaluation_only", "training_use", "evaluation_use", "redistribution", "license_id"):
                    if field in provided and provided[field] != decision.get(field):
                        raise PipelineError(f"Caller metadata contradicts registry field {field} for {source_id}", code="release_license_gate")
            derived_decisions[source_id] = decision
            provenance_values = [record.provenance for record in records if record.source_id == source_id]
            derived_source_manifest.append({
                "source_id": source_id, "source_revision": source.get("source_revision"),
                "asset_ids": sorted({str(p.get("asset_id", "")) for p in provenance_values if p.get("asset_id")}),
                "artifact_sha256": sorted({str(p.get("artifact_sha256", "")) for p in provenance_values if p.get("artifact_sha256")}),
                "license_id": license_info.get("spdx_id") or license_info.get("name"),
                "license_url": license_info.get("url"), "eligibility": source.get("eligibility"),
                "evaluation_only": bool(source.get("evaluation_only", False)),
            })
        metadata["source_license_decisions"] = derived_decisions
        metadata["source_manifest"] = derived_source_manifest
        dedup_config = config["deduplication"]
        pairwise_cap = int(dedup_config["max_records_for_pairwise"])
        if len(records) > pairwise_cap:
            raise PipelineError(f"Release recheck pairwise deduplication is capped at {pairwise_cap} records", code="dedup_record_limit")
        _, duplicate_recheck = deduplicate(
            records, threshold=float(dedup_config["near_duplicate_jaccard_threshold"]),
            shingle_size=int(dedup_config["shingle_size"]),
        )
        if any(not decision.retained for decision in duplicate_recheck):
            raise PipelineError("Release input contains exact or near-duplicate records; curate, split, then retry",
                                code="release_duplicate_gate")
        quality_outcomes = Counter()
        source_lookup = {source["source_id"]: source for source in registry["sources"]}
        for record in records:
            assessment = assess_quality(
                record, validate_record(record), source_lookup.get(record.source_id),
                purpose=args.purpose, policy=config.get("quality_profiles", {}),
            )
            quality_outcomes[assessment.outcome] += 1
            if assessment.outcome not in {"ACCEPT", "ACCEPT_WITH_WARNINGS"}:
                raise PipelineError(f"Release quality/safety recheck blocked record {record.record_id}: {assessment.outcome}",
                                    code="release_quality_gate")
        metadata["quality_thresholds"] = config.get("quality_profiles", {})
        metadata["deduplication"] = {
            "method": "exact SHA-256 on NFC/LF-normalized content + word-shingle Jaccard near-dedup (not semantic)",
            "threshold": float(dedup_config["near_duplicate_jaccard_threshold"]),
            "shingle_size": int(dedup_config["shingle_size"]),
            "release_recheck_pairs": len(duplicate_recheck),
            "release_recheck_duplicates": 0,
        }
        metadata["rejection_quarantine_statistics"] = {"release_quality_recheck_outcomes": dict(quality_outcomes)}
        metadata["input_artifact_hashes"] = sorted({str(record.provenance["artifact_sha256"]) for record in records
                                                     if record.provenance.get("artifact_sha256")})
        metadata["configuration_sha256"] = hashlib.sha256(config_path.read_bytes()).hexdigest()
        metadata["max_release_storage_bytes"] = int(config["resources"]["max_release_storage_bytes"])
        manifest = create_release(records, releases_root=root / "data" / "releases", release_id=args.release_id,
                                  metadata=metadata, manifest_only=args.manifest_only)
        print(json.dumps(manifest, indent=2, ensure_ascii=False))
        return 0
    raise PipelineError(f"Unsupported command: {args.command}", code="unsupported_command")


def main(argv: list[str] | None = None) -> None:
    parser = _make_parser()
    args = parser.parse_args(argv)
    try:
        code = _run(args)
    except PipelineError as exc:
        print(json.dumps({"error": exc.as_dict()}, ensure_ascii=False), file=sys.stderr)
        code = 2
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        # Avoid exception reprs that may include sensitive source or content values.
        print(json.dumps({"error": {"code": "input_or_io_error", "message": type(exc).__name__, "retryable": False}}), file=sys.stderr)
        code = 2
    raise SystemExit(code)
