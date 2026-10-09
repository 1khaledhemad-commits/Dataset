"""Configuration loading and source-registry validation.

The registry file is JSON syntax, which is also a valid YAML 1.2 document.
Using this deliberately small YAML subset keeps the CLI dependency-free and
avoids a permissive parser accepting aliases or custom object constructors.
"""

from __future__ import annotations

import json
import math
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .errors import PipelineError

ELIGIBILITY = {
    "APPROVED", "APPROVED_WITH_RESTRICTIONS", "NEEDS_REVIEW", "REJECTED",
    "TEMPORARILY_UNAVAILABLE",
}
_LICENSE_VALUES = {"permitted", "permitted_with_attribution", "restricted", "unknown", "not_applicable"}
_REQUIRED_SOURCE_FIELDS = {
    "source_id", "name", "official_url", "landing_page", "source_type", "domains",
    "languages", "format", "license", "commercial_use", "redistribution",
    "attribution", "restrictions", "personal_data_risk", "trust_level",
    "trust_justification", "known_quality_limitations", "collection_method",
    "credentials_required", "rate_limits", "retention", "last_verified",
    "last_successful_acquisition", "source_revision", "known_checksums",
    "connector_status", "eligibility", "eligibility_reason", "evaluation_only", "assets",
}


def load_json_yaml(path: str | Path) -> dict[str, Any]:
    """Load JSON-compatible YAML with duplicate-key rejection and clear errors."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
        value = json.loads(text, object_pairs_hook=_unique_object)
    except FileNotFoundError as exc:
        raise PipelineError(f"Configuration not found: {path}", code="config_missing") from exc
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise PipelineError(f"Invalid JSON-compatible YAML at {path}: {exc}", code="config_invalid") from exc
    if not isinstance(value, dict):
        raise PipelineError(f"Configuration root must be an object: {path}", code="config_invalid")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key: {key}")
        out[key] = value
    return out


def _valid_https_url(value: Any, *, forbid_query: bool = True, forbid_fragment: bool = True) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return False
    return (parsed.scheme == "https" and bool(parsed.hostname) and not parsed.username and not parsed.password
            and port in {None, 443} and (not forbid_query or not parsed.query)
            and (not forbid_fragment or not parsed.fragment))


def validate_registry(registry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if registry.get("registry_version") != "1.0.0":
        errors.append("registry_version must be 1.0.0")
    sources = registry.get("sources")
    if not isinstance(sources, list):
        return errors + ["sources must be a list"]
    seen: set[str] = set()
    for index, source in enumerate(sources):
        prefix = f"sources[{index}]"
        if not isinstance(source, dict):
            errors.append(f"{prefix} must be an object")
            continue
        missing = sorted(_REQUIRED_SOURCE_FIELDS - source.keys())
        if missing:
            errors.append(f"{prefix} missing fields: {', '.join(missing)}")
            continue
        source_id = source.get("source_id")
        if not isinstance(source_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,63}", source_id):
            errors.append(f"{prefix}.source_id must be a 2-64 character lowercase slug")
        elif source_id in seen:
            errors.append(f"duplicate source_id: {source_id}")
        else:
            seen.add(source_id)
        if not isinstance(source.get("eligibility"), str) or source.get("eligibility") not in ELIGIBILITY:
            errors.append(f"{prefix}.eligibility is not an allowed status")
        if not isinstance(source.get("personal_data_risk"), str) or source.get("personal_data_risk") not in {"low", "medium", "high", "unassessed"}:
            errors.append(f"{prefix}.personal_data_risk must be explicitly assessed")
        if not isinstance(source.get("trust_level"), str) or source.get("trust_level") not in {"high", "medium", "low", "unknown", "unverified"}:
            errors.append(f"{prefix}.trust_level is not a supported value")
        if not isinstance(source.get("evaluation_only"), bool):
            errors.append(f"{prefix}.evaluation_only must be boolean")
        for field in ("domains", "languages", "known_quality_limitations", "known_checksums", "assets"):
            values = source.get(field)
            if not isinstance(values, list):
                errors.append(f"{prefix}.{field} must be a list")
            elif field not in {"known_checksums", "assets"} and not all(isinstance(item, str) and item.strip() for item in values):
                errors.append(f"{prefix}.{field} must contain nonempty strings")
        for field in ("attribution", "restrictions"):
            values = source.get(field)
            if not isinstance(values, list) or not all(isinstance(item, str) and item.strip() for item in values):
                errors.append(f"{prefix}.{field} must be a list of nonempty strings")
        for field in ("name", "landing_page", "source_type", "format", "trust_justification",
                      "collection_method", "retention", "connector_status", "eligibility_reason"):
            if not isinstance(source.get(field), str) or not source[field].strip():
                errors.append(f"{prefix}.{field} must be a nonempty string")
        if not isinstance(source.get("credentials_required"), bool):
            errors.append(f"{prefix}.credentials_required must be boolean")
        if not isinstance(source.get("rate_limits"), dict):
            errors.append(f"{prefix}.rate_limits must be an object")
        estimated = source.get("estimated_size_bytes")
        if estimated is not None and (not isinstance(estimated, int) or isinstance(estimated, bool) or estimated <= 0):
            errors.append(f"{prefix}.estimated_size_bytes must be a positive integer or null")
        for checksum_index, checksum in enumerate(source.get("known_checksums", []) if isinstance(source.get("known_checksums"), list) else []):
            if not isinstance(checksum, dict):
                errors.append(f"{prefix}.known_checksums[{checksum_index}] must be an object")
                continue
            for field in ("algorithm", "value", "path", "verified_against"):
                if not isinstance(checksum.get(field), str) or not checksum[field].strip():
                    errors.append(f"{prefix}.known_checksums[{checksum_index}].{field} must be a nonempty string")
        rate_limits = source.get("rate_limits")
        if isinstance(rate_limits, dict) and (not isinstance(rate_limits.get("policy"), str) or not rate_limits["policy"].strip()):
            errors.append(f"{prefix}.rate_limits.policy must be a nonempty string")
        acquired_at = source.get("last_successful_acquisition")
        if acquired_at not in (None, "", "unverified"):
            try:
                parsed_acquisition = datetime.fromisoformat(str(acquired_at).replace("Z", "+00:00"))
                if parsed_acquisition.tzinfo is None:
                    errors.append(f"{prefix}.last_successful_acquisition must include a timezone")
            except ValueError:
                errors.append(f"{prefix}.last_successful_acquisition must be an ISO-8601 timestamp")
        license_info = source.get("license")
        if not isinstance(license_info, dict):
            errors.append(f"{prefix}.license must be an object")
            license_info = {}
        else:
            if not isinstance(license_info.get("name"), str) or not license_info["name"].strip():
                errors.append(f"{prefix}.license.name is required (use Unknown if unresolved)")
            for field in ("spdx_id", "version", "scope_note"):
                if field in license_info and not isinstance(license_info[field], str):
                    errors.append(f"{prefix}.license.{field} must be a string")
            if not isinstance(license_info.get("training_use", "unknown"), str) or license_info.get("training_use", "unknown") not in _LICENSE_VALUES:
                errors.append(f"{prefix}.license.training_use has an invalid value")
            if not isinstance(license_info.get("evaluation_use", "unknown"), str) or license_info.get("evaluation_use", "unknown") not in _LICENSE_VALUES:
                errors.append(f"{prefix}.license.evaluation_use has an invalid value")
            if source.get("evaluation_only") and "evaluation_use" not in license_info:
                errors.append(f"{prefix}.license.evaluation_use is required for evaluation-only sources")
            license_url = license_info.get("url")
            if license_url:
                if not _valid_https_url(license_url, forbid_fragment=False):
                    errors.append(f"{prefix}.license.url must be HTTPS without credentials or query parameters")
            license_text_path = license_info.get("license_text_path")
            if license_text_path and (not isinstance(license_text_path, str) or Path(license_text_path).is_absolute() or ".." in Path(license_text_path).parts):
                errors.append(f"{prefix}.license.license_text_path must remain within the project")
        for field in ("commercial_use", "redistribution"):
            if not isinstance(source.get(field), str) or source.get(field) not in _LICENSE_VALUES:
                errors.append(f"{prefix}.{field} must be an explicit license status")
        verified_at = source.get("last_verified")
        if verified_at not in (None, "", "unverified"):
            try:
                parsed_time = datetime.fromisoformat(str(verified_at).replace("Z", "+00:00"))
                if parsed_time.tzinfo is None:
                    errors.append(f"{prefix}.last_verified must include a timezone")
            except ValueError:
                errors.append(f"{prefix}.last_verified must be an ISO-8601 timestamp")
        if not _valid_https_url(source.get("official_url")):
            errors.append(f"{prefix}.official_url must be HTTPS without credentials, query, or fragment")
        if not _valid_https_url(source.get("landing_page")):
            errors.append(f"{prefix}.landing_page must be HTTPS without credentials, query, or fragment")
        if isinstance(source.get("eligibility"), str) and source.get("eligibility") in {"APPROVED", "APPROVED_WITH_RESTRICTIONS"}:
            if source.get("last_verified") in (None, "", "unverified"):
                errors.append(f"{prefix} cannot be approved without a verified timestamp")
            approved_right = license_info.get("evaluation_use", "unknown") if source.get("evaluation_only") else license_info.get("training_use", "unknown")
            if approved_right not in {"permitted", "permitted_with_attribution"}:
                right_kind = "evaluation" if source.get("evaluation_only") else "training"
                errors.append(f"{prefix} cannot be approved without verified {right_kind} rights")
            if isinstance(source.get("trust_level"), str) and source.get("trust_level") in {"unverified", "unknown", "low"}:
                errors.append(f"{prefix} cannot be approved with unverified/low trust")
            if source.get("eligibility") == "APPROVED_WITH_RESTRICTIONS" and not source.get("restrictions"):
                errors.append(f"{prefix} restricted approval requires explicit restrictions")
        if not isinstance(source.get("assets"), list):
            continue
        asset_ids: set[str] = set()
        for a_index, asset in enumerate(source["assets"]):
            aprefix = f"{prefix}.assets[{a_index}]"
            if not isinstance(asset, dict):
                errors.append(f"{aprefix} must be an object")
                continue
            for field in ("asset_id", "url", "format", "domain", "task_type"):
                if not asset.get(field):
                    errors.append(f"{aprefix}.{field} is required")
            asset_id = asset.get("asset_id")
            if not isinstance(asset_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", asset_id):
                errors.append(f"{aprefix}.asset_id must be a safe filename component")
            elif asset_id in asset_ids:
                errors.append(f"{aprefix}.asset_id is duplicated")
            else:
                asset_ids.add(asset_id)
            asset_format = asset.get("format")
            if not isinstance(asset_format, str) or not re.fullmatch(r"[a-zA-Z0-9.]{1,16}", asset_format):
                errors.append(f"{aprefix}.format must be a safe extension")
            if not _valid_https_url(asset.get("url")):
                errors.append(f"{aprefix}.url must be HTTPS on port 443 without credentials, query parameters, or fragments")
            size = asset.get("max_bytes")
            if size is not None and (not isinstance(size, int) or isinstance(size, bool) or size <= 0):
                errors.append(f"{aprefix}.max_bytes must be a positive integer")
            checksum = asset.get("sha256")
            if checksum is not None and not re.fullmatch(r"[a-fA-F0-9]{64}", str(checksum)):
                errors.append(f"{aprefix}.sha256 must contain 64 hex characters")
            blob_sha1 = asset.get("source_git_blob_sha1")
            if blob_sha1 is not None and not re.fullmatch(r"[a-fA-F0-9]{40}", str(blob_sha1)):
                errors.append(f"{aprefix}.source_git_blob_sha1 must contain 40 hex characters")
            max_records = asset.get("max_records")
            if max_records is not None and (not isinstance(max_records, int) or isinstance(max_records, bool) or max_records <= 0):
                errors.append(f"{aprefix}.max_records must be a positive integer")
            for limit_name in ("max_source_records", "sample_records"):
                limit_value = asset.get(limit_name)
                if limit_value is not None and (not isinstance(limit_value, int) or isinstance(limit_value, bool) or limit_value <= 0):
                    errors.append(f"{aprefix}.{limit_name} must be a positive integer")
            if isinstance(asset.get("sample_records"), int) and isinstance(asset.get("max_records"), int) and asset["sample_records"] > asset["max_records"]:
                errors.append(f"{aprefix}.sample_records cannot exceed max_records")
            if isinstance(asset.get("sample_records"), int) and isinstance(asset.get("max_source_records"), int) and asset["sample_records"] > asset["max_source_records"]:
                errors.append(f"{aprefix}.sample_records cannot exceed max_source_records")
            source_path = asset.get("source_path")
            if source_path is not None and (not isinstance(source_path, str) or Path(source_path).is_absolute() or ".." in Path(source_path).parts):
                errors.append(f"{aprefix}.source_path must be a safe relative path")
            text_fields = asset.get("text_fields")
            if text_fields is not None and (not isinstance(text_fields, list) or not text_fields or not all(isinstance(field, str) and field for field in text_fields)):
                errors.append(f"{aprefix}.text_fields must be a nonempty list of strings")
            content_encoding = asset.get("content_encoding")
            if content_encoding is not None and (not isinstance(content_encoding, str) or content_encoding not in {"github_git_blob_base64", "github_contents_api_base64"}):
                errors.append(f"{aprefix}.content_encoding is unsupported")
            dataset_purpose = asset.get("dataset_purpose", "pretraining")
            if not isinstance(dataset_purpose, str) or dataset_purpose not in {"pretraining", "sft", "preference", "evaluation", "expert"}:
                errors.append(f"{aprefix}.dataset_purpose is invalid")
            if source.get("evaluation_only") and dataset_purpose != "evaluation":
                errors.append(f"{aprefix}.evaluation-only sources may register evaluation-purpose assets only")
    return errors


def source_by_id(registry: dict[str, Any], source_id: str) -> dict[str, Any]:
    for source in registry.get("sources", []):
        if source.get("source_id") == source_id:
            return source
    raise PipelineError(f"Unknown source_id: {source_id}", code="source_not_found")


def validate_pipeline_config(config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if config.get("config_version") != "1.0.0":
        errors.append("config_version must be 1.0.0")
    hosts = config.get("allowed_download_hosts")
    if not isinstance(hosts, list) or not hosts or not all(isinstance(host, str) and host for host in hosts):
        errors.append("allowed_download_hosts must be a nonempty list of hostnames")
    resources = config.get("resources")
    if not isinstance(resources, dict):
        errors.append("resources must be an object")
        resources = {}
    positive_resource_fields = (
        "max_total_download_bytes", "max_raw_storage_bytes", "max_staging_storage_bytes",
        "max_release_storage_bytes", "max_single_file_bytes", "max_archive_expansion_bytes",
        "max_records_per_job", "max_memory_worker_bytes", "max_processing_duration_seconds",
        "max_per_source_bytes", "free_disk_safety_reserve_bytes", "max_concurrent_jobs",
    )
    for name in positive_resource_fields:
        value = resources.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            errors.append(f"resources.{name} must be a positive integer")
    if isinstance(resources.get("max_single_file_bytes"), int):
        for name in ("max_total_download_bytes", "max_raw_storage_bytes", "max_per_source_bytes"):
            if isinstance(resources.get(name), int) and resources[name] < resources["max_single_file_bytes"]:
                errors.append(f"resources.{name} must be at least max_single_file_bytes")
    if isinstance(resources.get("max_concurrent_jobs"), int) and resources["max_concurrent_jobs"] > 1:
        errors.append("max_concurrent_jobs above 1 requires a concurrency-control implementation")
    acquisition = config.get("acquisition")
    if not isinstance(acquisition, dict):
        errors.append("acquisition must be an object")
        acquisition = {}
    for name in ("timeout_seconds", "requests_per_host_per_second"):
        value = acquisition.get(name)
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value <= 0:
            errors.append(f"acquisition.{name} must be positive and finite")
    for name in ("max_retries",):
        value = acquisition.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            errors.append(f"acquisition.{name} must be a nonnegative integer")
    if not isinstance(acquisition.get("resume_partial_downloads"), bool):
        errors.append("acquisition.resume_partial_downloads must be boolean")
    if not isinstance(acquisition.get("redirect_limit"), int) or isinstance(acquisition.get("redirect_limit"), bool) or acquisition.get("redirect_limit", 0) < 0:
        errors.append("acquisition.redirect_limit must be a nonnegative integer")
    if acquisition.get("concurrent_jobs") != 1:
        errors.append("acquisition.concurrent_jobs must remain 1 until concurrency controls are implemented")
    normalization = config.get("normalization")
    if not isinstance(normalization, dict):
        errors.append("normalization must be an object")
        normalization = {}
    if normalization.get("unicode_normalization") != "NFC" or normalization.get("line_endings") != "LF":
        errors.append("normalization must match the implemented NFC/LF policy")
    if normalization.get("preserve_arabic_diacritics") is not True:
        errors.append("normalization.preserve_arabic_diacritics must remain true")
    if normalization.get("rewrite_arabic_letter_variants") is not False or normalization.get("remove_punctuation") is not False:
        errors.append("Arabic letter rewriting and punctuation removal are not implemented/allowed")
    if normalization.get("collapse_internal_whitespace") is not False:
        errors.append("normalization.collapse_internal_whitespace must remain false")
    dedup = config.get("deduplication")
    threshold = dedup.get("near_duplicate_jaccard_threshold") if isinstance(dedup, dict) else None
    if not isinstance(threshold, (int, float)) or isinstance(threshold, bool) or not math.isfinite(threshold) or not 0 < threshold <= 1:
        errors.append("deduplication.near_duplicate_jaccard_threshold must be in (0, 1]")
    shingle_size = dedup.get("shingle_size") if isinstance(dedup, dict) else None
    if not isinstance(shingle_size, int) or isinstance(shingle_size, bool) or shingle_size <= 0:
        errors.append("deduplication.shingle_size must be a positive integer")
    pairwise_cap = dedup.get("max_records_for_pairwise") if isinstance(dedup, dict) else None
    if not isinstance(pairwise_cap, int) or isinstance(pairwise_cap, bool) or pairwise_cap <= 0:
        errors.append("deduplication.max_records_for_pairwise must be a positive integer")
    splits = config.get("splits")
    if not isinstance(splits, dict) or not isinstance(splits.get("proportions"), dict):
        errors.append("splits.proportions must be an object")
    else:
        values = list(splits["proportions"].values())
        if not values or any(not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or value < 0 for value in values) or abs(sum(values) - 1.0) > 1e-9:
            errors.append("splits.proportions must be nonnegative numbers that sum to 1.0")
    quality = config.get("quality_profiles")
    if not isinstance(quality, dict) or not isinstance(quality.get("default"), dict):
        errors.append("quality_profiles.default must be an object")
    else:
        for field in ("minimum_language_confidence", "minimum_formatting_integrity", "minimum_information_density"):
            value = quality["default"].get(field)
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or not 0 <= value <= 1:
                errors.append(f"quality_profiles.default.{field} must be in [0, 1]")
        max_chars = quality["default"].get("maximum_record_characters")
        if not isinstance(max_chars, int) or isinstance(max_chars, bool) or max_chars <= 0:
            errors.append("quality_profiles.default.maximum_record_characters must be a positive integer")
        if quality["default"].get("secret_findings") not in {"QUARANTINE", "REJECT"}:
            errors.append("quality_profiles.default.secret_findings must be QUARANTINE or REJECT")
        if quality["default"].get("possible_personal_identifiers") not in {"NEEDS_HUMAN_REVIEW", "QUARANTINE"}:
            errors.append("quality_profiles.default.possible_personal_identifiers must preserve review/quarantine gates")
        task_mins = quality.get("task_minimum_characters", {})
        if not isinstance(task_mins, dict) or any(not isinstance(v, int) or isinstance(v, bool) or v <= 0 for v in task_mins.values()):
            errors.append("quality_profiles.task_minimum_characters must contain positive integers")
        language_profiles = quality.get("language_profiles", {})
        if not isinstance(language_profiles, dict):
            errors.append("quality_profiles.language_profiles must be an object")
        else:
            for language, profile in language_profiles.items():
                threshold_value = profile.get("minimum_confidence") if isinstance(profile, dict) else None
                if not isinstance(threshold_value, (int, float)) or isinstance(threshold_value, bool) or not math.isfinite(threshold_value) or not 0 <= threshold_value <= 1:
                    errors.append(f"quality_profiles.language_profiles.{language}.minimum_confidence must be in [0, 1]")
                if language == "unknown" and isinstance(profile, dict) and profile.get("action") != "NEEDS_HUMAN_REVIEW":
                    errors.append("quality_profiles.language_profiles.unknown.action must be NEEDS_HUMAN_REVIEW")
    return errors
