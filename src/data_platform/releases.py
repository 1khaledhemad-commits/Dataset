"""Atomic, immutable dataset releases with reproducibility manifests."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import PipelineError
from .models import NormalizedRecord
from .storage import read_jsonl, sha256_file, write_json_atomic, write_jsonl_atomic, write_text_atomic
from .validation import validate_record

_RELEASE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,95}")


def _path_has_symlink_component(path: Path) -> bool:
    current = path.absolute()
    while True:
        if current.is_symlink():
            return True
        if current.parent == current:
            return False
        current = current.parent


def _tree_bytes(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file() and not item.is_symlink())


def _make_notices(decisions: dict[str, Any], *, fixture_only: bool) -> tuple[str | None, dict[str, dict[str, Any]]]:
    rendered: list[str] = []
    safe_decisions: dict[str, dict[str, Any]] = {}
    for source_id, raw_decision in sorted(decisions.items()):
        if not isinstance(raw_decision, dict):
            raise PipelineError("Each source license decision must be an object", code="invalid_release_metadata")
        decision = dict(raw_decision)
        license_text = decision.pop("license_text", None)
        attribution = decision.get("attribution", [])
        if not isinstance(attribution, list) or not all(isinstance(line, str) and line.strip() for line in attribution):
            raise PipelineError("Source attribution must be a list of nonempty strings", code="invalid_release_metadata")
        requires_notice = decision.get("redistribution") == "permitted_with_attribution"
        if not fixture_only and requires_notice and not (isinstance(license_text, str) and license_text.strip()):
            raise PipelineError(f"Source {source_id} requires a full license notice in the release", code="license_notice_missing")
        if isinstance(license_text, str) and license_text.strip():
            actual_license_hash = hashlib.sha256(license_text.encode("utf-8")).hexdigest()
            supplied_license_hash = decision.get("license_text_sha256")
            if supplied_license_hash and supplied_license_hash != actual_license_hash:
                raise PipelineError(f"Source {source_id} license-text hash mismatch", code="license_notice_hash_mismatch")
            license_hash = actual_license_hash
            rendered.extend([
                f"Source: {source_id}",
                f"License: {decision.get('license', 'Unknown')} ({decision.get('license_id', 'NOASSERTION')})",
                f"License URL: {decision.get('license_url', 'not recorded')}",
                "Attribution:",
                *[f"  - {line}" for line in attribution],
                f"Full license text SHA-256: {license_hash}",
                "Full license text:",
                license_text.rstrip(),
                "",
            ])
            decision["license_text_sha256"] = license_hash
        elif attribution:
            rendered.extend([f"Source: {source_id}", "Attribution:", *[f"  - {line}" for line in attribution], ""])
        safe_decisions[source_id] = decision
    return ("\n".join(rendered).rstrip() + "\n" if rendered else None), safe_decisions


def create_release(
    records: list[NormalizedRecord],
    *,
    releases_root: str | Path,
    release_id: str,
    metadata: dict[str, Any],
    manifest_only: bool = False,
) -> dict[str, Any]:
    if not _RELEASE_ID_RE.fullmatch(release_id):
        raise PipelineError("release_id must be a 3-96 character safe identifier", code="invalid_release_id")
    root = Path(releases_root)
    if _path_has_symlink_component(root):
        raise PipelineError("Release storage path must not contain symbolic links", code="unsafe_release_path")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        root.chmod(0o700)
    except OSError:
        pass
    target = root / release_id
    if target.is_symlink() or target.exists():
        raise PipelineError(f"Immutable release already exists: {release_id}", code="release_exists")
    fixture_flags = [bool(record.provenance.get("fixture_only")) for record in records]
    if fixture_flags and any(fixture_flags) and not all(fixture_flags):
        raise PipelineError("Fixture and non-fixture records cannot be mixed in one release", code="mixed_fixture_release_blocked")
    fixture_only = bool(fixture_flags) and all(fixture_flags)
    if fixture_only and metadata.get("dataset_purpose") not in {"fixture_validation", "test_only"}:
        raise PipelineError("Fixture-only records cannot be released for a training purpose", code="fixture_release_blocked")
    if not fixture_only and metadata.get("dataset_purpose") in {"fixture_validation", "test_only"}:
        raise PipelineError("Real records cannot be mislabeled as fixture-only", code="release_purpose_mismatch")
    purpose = metadata.get("dataset_purpose", "pretraining")
    allowed_purposes = {"pretraining", "sft", "preference", "evaluation", "expert", "fixture_validation", "test_only"}
    if purpose not in allowed_purposes:
        raise PipelineError("Release purpose is not supported", code="invalid_purpose")
    if not fixture_only and purpose in {"fixture_validation", "test_only"}:
        raise PipelineError("Real records cannot be released under a fixture-only purpose", code="release_purpose_mismatch")
    if not fixture_only and not records and not manifest_only:
        raise PipelineError("A data release cannot publish zero records", code="empty_release")
    approval_status = metadata.get("human_approval_status", "pending")
    if not fixture_only and not isinstance(approval_status, str):
        raise PipelineError("Release human_approval_status must be a string", code="missing_approval_status")
    if not fixture_only and not manifest_only:
        approver = metadata.get("approved_by")
        approval_reference = metadata.get("human_approval_reference")
        if (approval_status != "approved" or not isinstance(approver, str) or not approver.strip() or
                not isinstance(approval_reference, str) or not approval_reference.strip()):
            raise PipelineError("Publishing real records requires explicit human_approval_status=approved, approved_by, and human_approval_reference",
                                code="human_approval_required")
    allowed_splits = {"train", "validation", "test", "evaluation"}
    splits = {record.split_assignment for record in records}
    if records and (None in splits or "" in splits):
        raise PipelineError("Every record must have a split assignment before release", code="missing_split")
    if any(split not in allowed_splits for split in splits):
        raise PipelineError("Release split names must be train, validation, test, or evaluation", code="invalid_split")
    invalid = [record.record_id for record in records if not validate_record(record).valid]
    if invalid:
        raise PipelineError(f"Release contains {len(invalid)} structurally invalid record(s)", code="invalid_release_record")
    record_ids = [record.record_id for record in records]
    if len(set(record_ids)) != len(record_ids):
        raise PipelineError("Release input contains duplicate record IDs", code="duplicate_record_id")
    content_hashes = [record.content_hash for record in records]
    if len(set(content_hashes)) != len(content_hashes):
        raise PipelineError("Release contains exact duplicate content hashes", code="duplicate_release_content")

    duplicate_cluster_splits: dict[str, str] = {}
    for record in records:
        cluster = record.provenance.get("duplicate_cluster_id")
        if isinstance(cluster, str) and cluster:
            previous_split = duplicate_cluster_splits.setdefault(cluster, str(record.split_assignment))
            if previous_split != record.split_assignment:
                raise PipelineError("A duplicate cluster spans multiple release splits", code="duplicate_cluster_leakage")

    source_manifest = metadata.get("source_manifest", [])
    if not isinstance(source_manifest, list):
        raise PipelineError("source_manifest must be a list", code="invalid_release_metadata")
    decisions = metadata.get("source_license_decisions", {})
    if not isinstance(decisions, dict):
        raise PipelineError("source_license_decisions must be an object", code="invalid_release_metadata")
    if not fixture_only:
        if any(not isinstance(entry, dict) or not isinstance(entry.get("source_id"), str) or not entry.get("source_id") for entry in source_manifest):
            raise PipelineError("source_manifest entries require string source_id values", code="invalid_release_metadata")
        source_entries = {entry["source_id"]: entry for entry in source_manifest}
        if len(source_entries) != len(source_manifest):
            raise PipelineError("source_manifest entries must have unique source_id values", code="invalid_release_metadata")
        record_source_ids = {record.source_id for record in records}
        if set(source_entries) != record_source_ids or set(decisions) != record_source_ids:
            raise PipelineError("Source manifest and license decisions must exactly cover release records", code="invalid_release_metadata")
        for source_id in sorted(record_source_ids):
            decision = decisions.get(source_id)
            source_entry = source_entries.get(source_id)
            if not isinstance(decision, dict) or not isinstance(source_entry, dict):
                raise PipelineError(f"Release lacks a source manifest/license decision for {source_id}", code="release_license_gate")
            if decision.get("eligibility") not in {"APPROVED", "APPROVED_WITH_RESTRICTIONS"}:
                raise PipelineError(f"Source {source_id} is not approved for release", code="release_license_gate")
            if source_entry.get("eligibility") != decision.get("eligibility"):
                raise PipelineError(f"Source {source_id} eligibility contradicts the source manifest", code="release_license_gate")
            evaluation_only = bool(decision.get("evaluation_only", source_entry.get("evaluation_only", False)))
            if bool(source_entry.get("evaluation_only", False)) != evaluation_only:
                raise PipelineError(f"Source {source_id} evaluation-only status contradicts the source manifest", code="release_license_gate")
            if evaluation_only and purpose != "evaluation":
                raise PipelineError(f"Evaluation-only source {source_id} cannot enter a {purpose} release", code="evaluation_leakage_blocked")
            purpose_rights = decision.get("evaluation_use") if purpose == "evaluation" else decision.get("training_use")
            if purpose_rights not in {"permitted", "permitted_with_attribution"}:
                right_label = "evaluation-use" if purpose == "evaluation" else "training/use"
                raise PipelineError(f"{right_label} rights are unresolved for source {source_id}", code="release_license_gate")
            declared_license_id = decision.get("license_id") or decision.get("license")
            if source_entry.get("license_id") not in {declared_license_id, decision.get("license")}:
                raise PipelineError(f"Source {source_id} license identity contradicts its manifest", code="release_license_gate")
            entry_revision = source_entry.get("source_revision") or ""
            entry_artifacts = source_entry.get("artifact_sha256", [])
            if isinstance(entry_artifacts, str):
                entry_artifacts = [entry_artifacts]
            if not isinstance(entry_artifacts, list):
                raise PipelineError(f"Source {source_id} artifact hashes are malformed", code="invalid_release_metadata")
            entry_assets = source_entry.get("asset_ids", [])
            if source_entry.get("asset_id"):
                entry_assets = [*entry_assets, source_entry["asset_id"]]
            for record in (item for item in records if item.source_id == source_id):
                artifact_hash = record.provenance.get("artifact_sha256")
                if not isinstance(artifact_hash, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", artifact_hash) or artifact_hash not in entry_artifacts:
                    raise PipelineError(f"Record {record.record_id} is not tied to a manifest-listed artifact hash", code="missing_record_provenance")
                if (record.provenance.get("asset_id") not in entry_assets or
                        (record.source_revision or "") != entry_revision or
                        record.license_id not in {declared_license_id, decision.get("license")}):
                    raise PipelineError(f"Record {record.record_id} provenance conflicts with its source manifest", code="release_provenance_mismatch")
            if not manifest_only and decision.get("redistribution") not in {"permitted", "permitted_with_attribution"}:
                raise PipelineError(f"Redistribution rights are unresolved for source {source_id}", code="release_license_gate")
            if decision.get("eligibility") == "APPROVED_WITH_RESTRICTIONS" and not decision.get("restrictions"):
                raise PipelineError(f"Restricted source {source_id} has no release restrictions", code="release_license_gate")
            if purpose == "evaluation" and any(record.source_id == source_id and record.split_assignment in {"train", "training"} for record in records):
                raise PipelineError(f"Evaluation-purpose records from {source_id} cannot be assigned to training", code="evaluation_leakage_blocked")
    notices_text, safe_decisions = _make_notices(decisions, fixture_only=fixture_only)

    staging = Path(tempfile.mkdtemp(prefix=f".{release_id}.incomplete-", dir=root))
    try:
        files: dict[str, dict[str, Any]] = {}
        auxiliary_files: dict[str, dict[str, Any]] = {}
        if not manifest_only:
            split_names = sorted({record.split_assignment or "unassigned" for record in records})
            for split_name in split_names:
                filename = f"records-{split_name}.jsonl"
                grouped = [record.to_dict() for record in sorted(records, key=lambda item: item.record_id)
                           if record.split_assignment == split_name]
                count, byte_count, digest = write_jsonl_atomic(staging / filename, grouped)
                files[filename] = {"records": count, "bytes": byte_count, "sha256": digest}
        if notices_text:
            notice_name = "THIRD_PARTY_NOTICES.txt"
            notice_path = staging / notice_name
            write_text_atomic(notice_path, notices_text)
            auxiliary_files[notice_name] = {"bytes": notice_path.stat().st_size, "sha256": sha256_file(notice_path), "kind": "license_notice"}

        lang_counts = Counter(record.language for record in records)
        domain_counts = Counter(record.domain for record in records)
        task_counts = Counter(record.task_type for record in records)
        source_counts = Counter(record.source_id for record in records)
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        manifest: dict[str, Any] = {
            "release_manifest_version": "1.0.0",
            "release_id": release_id,
            "created_at": created_at,
            "schema_version": "1.0.0",
            "pipeline_version": metadata.get("pipeline_version", "0.1.0"),
            "configuration_sha256": metadata.get("configuration_sha256", ""),
            "dataset_purpose": metadata.get("dataset_purpose", "pretraining"),
            "source_manifest": source_manifest,
            "source_license_decisions": safe_decisions,
            "input_artifact_hashes": metadata.get("input_artifact_hashes", []),
            "transformations": metadata.get("transformations", ["unicode-nfc-line-endings-v1"]),
            "deduplication": metadata.get("deduplication", {}),
            "quality_thresholds": metadata.get("quality_thresholds", {}),
            "rejection_quarantine_statistics": metadata.get("rejection_quarantine_statistics", {}),
            "split_policy": metadata.get("split_policy", {}),
            "counts": {
                "published_records": 0 if manifest_only else len(records),
                "manifest_records": len(records),
                "unique_records": len(set(record_ids)),
                "unique_content_hashes": len(set(content_hashes)),
                "source_counts": dict(sorted(source_counts.items())),
                "language_counts": dict(sorted(lang_counts.items())),
                "domain_counts": dict(sorted(domain_counts.items())),
                "task_counts": dict(sorted(task_counts.items())),
                "split_counts": dict(sorted(Counter(record.split_assignment for record in records).items())),
            },
            "byte_size": sum(item["bytes"] for item in files.values()) + sum(item["bytes"] for item in auxiliary_files.values()),
            "files": files,
            "auxiliary_files": auxiliary_files,
            "manifest_only": manifest_only,
            "fixture_only": fixture_only,
            "human_approval_status": approval_status,
            "approved_by": metadata.get("approved_by"),
            "human_approval_reference": metadata.get("human_approval_reference"),
            "limitations": metadata.get("limitations", []),
            "release_status": "complete",
        }
        write_json_atomic(staging / "manifest.json", manifest)
        manifest_hash = sha256_file(staging / "manifest.json")
        write_text_atomic(staging / "manifest.sha256", manifest_hash + "  manifest.json\n")
        write_text_atomic(staging / "RELEASE_COMPLETE", f"manifest_sha256={manifest_hash}\n")
        size_cap = int(metadata.get("max_release_storage_bytes", 64 * 1024 * 1024))
        if size_cap <= 0:
            raise PipelineError("Release storage quota must be positive", code="invalid_quota")
        if _tree_bytes(root) > size_cap:
            raise PipelineError("Configured release storage quota would be exceeded", code="release_storage_quota_exceeded")
        if target.is_symlink() or target.exists():
            raise PipelineError(f"Immutable release already exists: {release_id}", code="release_exists")
        os.rename(staging, target)
        try:
            root_fd = os.open(root, os.O_RDONLY)
            try:
                os.fsync(root_fd)
            finally:
                os.close(root_fd)
        except OSError:
            pass
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return manifest


def verify_release(release_path: str | Path, *, max_records: int = 10_000,
                   max_total_bytes: int = 64 * 1024 * 1024,
                   max_manifest_bytes: int = 2 * 1024 * 1024) -> dict[str, Any]:
    if max_records <= 0 or max_total_bytes <= 0 or max_manifest_bytes <= 0:
        raise PipelineError("Release verification limits must be positive", code="invalid_resource_policy")
    root = Path(release_path)
    manifest_path = root / "manifest.json"
    marker_path = root / "RELEASE_COMPLETE"
    hash_path = root / "manifest.sha256"
    if (_path_has_symlink_component(root) or not root.is_dir() or manifest_path.is_symlink() or marker_path.is_symlink() or
            hash_path.is_symlink() or not manifest_path.is_file() or not marker_path.is_file() or not hash_path.is_file()):
        raise PipelineError("Release is missing required regular files or contains a symbolic link", code="incomplete_release")
    if manifest_path.stat().st_size > max_manifest_bytes or marker_path.stat().st_size > 256 or hash_path.stat().st_size > 256:
        raise PipelineError("Release manifest or integrity markers exceed verification limits", code="release_verification_limit")
    try:
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        expected_manifest_hash = hash_path.read_text(encoding="ascii").split()[0]
        marker_hash = marker_path.read_text(encoding="ascii").strip().removeprefix("manifest_sha256=")
    except (OSError, UnicodeError, json.JSONDecodeError, IndexError) as exc:
        raise PipelineError("Release manifest or integrity marker is unreadable", code="invalid_release_manifest") from exc
    if not isinstance(manifest, dict):
        raise PipelineError("Release manifest root must be an object", code="invalid_release_manifest")
    if not isinstance(manifest.get("files"), dict) or not isinstance(manifest.get("auxiliary_files", {}), dict):
        raise PipelineError("Release file metadata must be objects", code="invalid_release_manifest")
    if any(not isinstance(value, dict) for group in (manifest["files"], manifest.get("auxiliary_files", {})) for value in group.values()):
        raise PipelineError("Release file entries must be objects", code="invalid_release_manifest")
    if any(not isinstance(name, str) or Path(name).name != name for group in (manifest["files"], manifest.get("auxiliary_files", {})) for name in group):
        raise PipelineError("Release file names must be simple path components", code="invalid_release_manifest")
    if any(not re.fullmatch(r"records-(?:train|validation|test|evaluation)\.jsonl", name) for name in manifest["files"]):
        raise PipelineError("Release data file name is not a supported split", code="invalid_release_manifest")
    if any(name != "THIRD_PARTY_NOTICES.txt" for name in manifest.get("auxiliary_files", {})):
        raise PipelineError("Release auxiliary file name is not allowed", code="invalid_release_manifest")
    if not isinstance(manifest.get("counts"), dict):
        raise PipelineError("Release counts must be an object", code="invalid_release_manifest")
    if not isinstance(manifest.get("source_manifest"), list) or not isinstance(manifest.get("source_license_decisions"), dict):
        raise PipelineError("Release provenance/license metadata is invalid", code="invalid_release_manifest")
    if not isinstance(manifest.get("dataset_purpose"), str) or manifest.get("dataset_purpose") not in {"pretraining", "sft", "preference", "evaluation", "expert", "fixture_validation", "test_only"}:
        raise PipelineError("Release dataset purpose is invalid", code="invalid_release_manifest")
    if type(manifest.get("fixture_only")) is not bool or type(manifest.get("manifest_only")) is not bool:
        raise PipelineError("Release fixture/manifest flags must be boolean", code="invalid_release_manifest")
    actual_manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    if expected_manifest_hash != actual_manifest_hash or marker_hash != actual_manifest_hash:
        raise PipelineError("Release manifest SHA-256 integrity check failed", code="manifest_hash_mismatch")
    if manifest.get("release_status") != "complete" or manifest.get("release_id") != root.name:
        raise PipelineError("Release manifest identity/status mismatch", code="invalid_release_manifest")
    errors: list[str] = []
    if not manifest.get("fixture_only") and not manifest.get("manifest_only"):
        if (manifest.get("human_approval_status") != "approved" or
                not isinstance(manifest.get("approved_by"), str) or not manifest["approved_by"].strip() or
                not isinstance(manifest.get("human_approval_reference"), str) or not manifest["human_approval_reference"].strip()):
            errors.append("human_approval_missing_or_incomplete")
    decisions = manifest.get("source_license_decisions", {})
    source_entries = manifest.get("source_manifest", [])
    if any(not isinstance(entry, dict) or not isinstance(entry.get("source_id"), str) or not entry.get("source_id") for entry in source_entries):
        raise PipelineError("Release source manifest entries require string source_id values", code="invalid_release_manifest")
    sources = {entry["source_id"]: entry for entry in source_entries}
    if len(sources) != len(source_entries):
        raise PipelineError("Release source manifest contains duplicate or malformed entries", code="invalid_release_manifest")
    purpose = manifest.get("dataset_purpose", "pretraining")
    if not manifest.get("fixture_only"):
        for source_id, entry in sources.items():
            decision = decisions.get(source_id, {})
            if not isinstance(decision, dict):
                errors.append(f"missing_license_decision:{source_id}")
                continue
            if entry.get("eligibility") != decision.get("eligibility"):
                errors.append(f"eligibility_mismatch:{source_id}")
            if entry.get("license_id") not in {decision.get("license_id") or decision.get("license"), decision.get("license")}:
                errors.append(f"license_identity_mismatch:{source_id}")
            if decision.get("eligibility") not in {"APPROVED", "APPROVED_WITH_RESTRICTIONS"}:
                errors.append(f"source_not_approved:{source_id}")
            purpose_rights = decision.get("evaluation_use") if purpose == "evaluation" else decision.get("training_use")
            if purpose_rights not in {"permitted", "permitted_with_attribution"}:
                errors.append(f"purpose_use_unresolved:{source_id}")
            evaluation_only = bool(decision.get("evaluation_only", entry.get("evaluation_only", False)))
            if bool(entry.get("evaluation_only", False)) != evaluation_only:
                errors.append(f"evaluation_only_mismatch:{source_id}")
            if evaluation_only and purpose != "evaluation":
                errors.append(f"evaluation_only_in_training_release:{source_id}")
            if not manifest.get("manifest_only") and decision.get("redistribution") not in {"permitted", "permitted_with_attribution"}:
                errors.append(f"redistribution_unresolved:{source_id}")
    if not manifest.get("fixture_only"):
        expected_sources = {entry.get("source_id") for entry in source_entries}
        if expected_sources != set(decisions):
            errors.append("source_decision_manifest_set_mismatch")
    observed_records = 0
    observed_hashes: set[str] = set()
    observed_total_bytes = manifest_path.stat().st_size + marker_path.stat().st_size + hash_path.stat().st_size
    expected_files = {"manifest.json", "manifest.sha256", "RELEASE_COMPLETE"}
    for file_group in (manifest.get("files", {}), manifest.get("auxiliary_files", {})):
        for filename, expected in file_group.items():
            path = root / filename
            if path.parent != root or path.is_symlink() or not path.is_file():
                errors.append(f"missing_or_unsafe_file:{filename}")
                continue
            expected_files.add(filename)
            file_size = path.stat().st_size
            observed_total_bytes += file_size
            if observed_total_bytes > max_total_bytes:
                raise PipelineError("Release exceeds the configured verification byte budget", code="release_verification_limit")
            if file_size > max_total_bytes:
                raise PipelineError("Release file exceeds the configured verification byte budget", code="release_verification_limit")
            if sha256_file(path) != expected.get("sha256"):
                errors.append(f"sha256_mismatch:{filename}")
                continue
            if path.stat().st_size != expected.get("bytes"):
                errors.append(f"byte_count_mismatch:{filename}")
                continue
            if filename in manifest.get("auxiliary_files", {}):
                continue
            count = 0
            remaining_records = max_records - observed_records
            if remaining_records <= 0 and expected.get("records", 0):
                raise PipelineError("Release exceeds the configured record verification limit", code="release_verification_limit")
            for row in read_jsonl(path, max_records=max(1, remaining_records), max_bytes=max_total_bytes):
                count += 1
                if count + observed_records > max_records:
                    raise PipelineError("Release exceeds the configured record verification limit", code="release_verification_limit")
                record = NormalizedRecord.from_dict(row)
                result = validate_record(record)
                if not result.valid:
                    errors.append(f"invalid_record:{record.record_id}")
                if record.split_assignment != filename.removeprefix("records-").removesuffix(".jsonl"):
                    errors.append(f"split_mismatch:{record.record_id}")
                if purpose == "evaluation" and record.split_assignment in {"train", "training"}:
                    errors.append(f"evaluation_record_in_training_split:{record.record_id}")
                source_decision = decisions.get(record.source_id, {})
                source_entry = sources.get(record.source_id, {})
                if isinstance(source_decision, dict) and source_decision.get("evaluation_only") and purpose != "evaluation":
                    errors.append(f"evaluation_only_record_in_training_release:{record.record_id}")
                if not manifest.get("fixture_only"):
                    artifact_hash = record.provenance.get("artifact_sha256")
                    entry_hashes = source_entry.get("artifact_sha256", []) if isinstance(source_entry, dict) else []
                    if isinstance(entry_hashes, str):
                        entry_hashes = [entry_hashes]
                    entry_assets = source_entry.get("asset_ids", []) if isinstance(source_entry, dict) else []
                    if isinstance(source_entry, dict) and source_entry.get("asset_id"):
                        entry_assets = [*entry_assets, source_entry["asset_id"]]
                    if record.source_id not in sources or not isinstance(source_decision, dict):
                        errors.append(f"record_source_provenance_missing:{record.record_id}")
                    elif (artifact_hash not in entry_hashes or record.provenance.get("asset_id") not in entry_assets or
                          (record.source_revision or "") != (source_entry.get("source_revision") or "") or
                          record.license_id not in {source_decision.get("license_id") or source_decision.get("license"), source_decision.get("license")}):
                        errors.append(f"record_provenance_mismatch:{record.record_id}")
                if record.content_hash in observed_hashes:
                    errors.append(f"duplicate_content:{record.record_id}")
                observed_hashes.add(record.content_hash)
            if count != expected.get("records"):
                errors.append(f"record_count_mismatch:{filename}")
            observed_records += count
    if not manifest.get("manifest_only") and observed_records != manifest.get("counts", {}).get("published_records"):
        errors.append("published_record_count_mismatch")
    if manifest.get("manifest_only") and manifest.get("files"):
        errors.append("manifest_only_release_contains_data_files")
    actual_files = {item.name for item in root.iterdir()}
    if actual_files != expected_files:
        errors.append("unexpected_or_unmanifested_release_files")
    return {
        "release_id": manifest.get("release_id"),
        "valid": not errors,
        "errors": errors,
        "observed_record_files": observed_records,
        "manifest_records": manifest.get("counts", {}).get("manifest_records", 0),
        "manifest_published_records": manifest.get("counts", {}).get("published_records", 0),
        "fixture_only": bool(manifest.get("fixture_only")),
        "human_approval_status": manifest.get("human_approval_status"),
    }
