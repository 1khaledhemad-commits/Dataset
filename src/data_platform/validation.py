"""Structural validation for normalized records and local artifact files."""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from datetime import datetime
from urllib.parse import urlparse
from pathlib import Path
from typing import Any

from .models import NormalizedRecord, ValidationResult


_REQUIRED_STRINGS = (
    "record_id", "text", "language", "domain", "task_type", "source_id",
    "source_record_id", "source_url", "source_revision", "license_id",
    "content_hash", "ingestion_timestamp", "schema_version", "normalization_version",
)


def validate_record(record: NormalizedRecord | dict[str, Any]) -> ValidationResult:
    value = record.to_dict() if isinstance(record, NormalizedRecord) else record
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(value, dict):
        return ValidationResult(False, ("record must be an object",))
    for field in _REQUIRED_STRINGS:
        if not isinstance(value.get(field), str):
            errors.append(f"{field} must be a string")
    if not errors:
        for field in _REQUIRED_STRINGS:
            if not value[field] and field not in {"source_url", "source_revision"}:
                errors.append(f"{field} must not be empty")
        if value["language"] not in {"ar", "en", "mixed", "other", "unknown"}:
            errors.append("language is not a supported normalized label")
        if value["schema_version"] != "1.0.0":
            errors.append("unsupported schema_version")
        if value["normalization_version"] != "1.0.0":
            errors.append("unsupported normalization_version")
        if not re.fullmatch(r"[a-fA-F0-9]{64}", value["record_id"]):
            errors.append("record_id must be a SHA-256 hex identifier")
        if not re.fullmatch(r"[a-fA-F0-9]{64}", value["content_hash"]):
            errors.append("content_hash must be a SHA-256 hex digest")
        try:
            timestamp = datetime.fromisoformat(value["ingestion_timestamp"].replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                errors.append("ingestion_timestamp must include a timezone")
        except ValueError:
            errors.append("ingestion_timestamp must be ISO-8601")
        if value["source_url"]:
            parsed_url = urlparse(value["source_url"])
            if parsed_url.query or parsed_url.username or parsed_url.password:
                errors.append("source_url must not contain query parameters or credentials")
        text = value["text"]
        if any(0xD800 <= ord(char) <= 0xDFFF for char in text):
            errors.append("text contains an invalid Unicode surrogate")
        if not text.strip():
            errors.append("text is empty")
        if "\x00" in text:
            errors.append("text contains a NUL character")
        if "\r" in text:
            errors.append("text contains non-normalized line endings")
        if unicodedata.normalize("NFC", text) != text:
            errors.append("text is not NFC normalized")
        expected = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if value["content_hash"] != expected:
            errors.append("content_hash does not match normalized text")
        if len(text) < 20:
            warnings.append("short_record")
    confidence = value.get("language_confidence")
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
        errors.append("language_confidence must be a number in [0, 1]")
    for field in ("quality_flags",):
        if not isinstance(value.get(field, []), list) or not all(isinstance(v, str) for v in value.get(field, [])):
            errors.append(f"{field} must be a list of strings")
    for field in ("attributes", "provenance", "script_composition", "language_profile"):
        if not isinstance(value.get(field, {}), dict):
            errors.append(f"{field} must be an object")
    composition = value.get("script_composition", {})
    if isinstance(composition, dict):
        for key, amount in composition.items():
            if not isinstance(key, str) or not isinstance(amount, (int, float)) or isinstance(amount, bool) or not math.isfinite(amount) or not 0 <= amount <= 1:
                errors.append("script_composition values must be finite numbers in [0, 1]")
                break
    try:
        json.dumps(value.get("attributes", {}), ensure_ascii=False, allow_nan=False)
        json.dumps(value.get("provenance", {}), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        errors.append("attributes and provenance must be JSON-serializable")
    return ValidationResult(not errors, tuple(errors), tuple(warnings))


def validate_jsonl_file(path: str | Path, *, max_records: int = 100_000,
                        max_bytes: int = 64 * 1024 * 1024) -> dict[str, Any]:
    """Bounded scan reporting observed records and parse/schema failures."""
    path = Path(path)
    total = valid = 0
    errors: list[dict[str, Any]] = []
    try:
        if max_records <= 0 or max_bytes <= 0:
            return {"path": str(path), "records_seen": 0, "valid_records": 0,
                    "errors": [{"error": "invalid_resource_policy"}], "valid": False}
        if path.stat().st_size > max_bytes:
            return {"path": str(path), "records_seen": 0, "valid_records": 0,
                    "errors": [{"error": "input_byte_limit"}], "valid": False}
        total_bytes = 0
        line_no = 0
        with path.open("rb") as handle:
            while True:
                raw_line = handle.readline(max_bytes - total_bytes + 1)
                if not raw_line:
                    break
                line_no += 1
                total_bytes += len(raw_line)
                if total_bytes > max_bytes:
                    errors.append({"error": "input_byte_limit"})
                    break
                if not raw_line.strip():
                    continue
                total += 1
                if total > max_records:
                    errors.append({"line": line_no, "error": "record_limit_exceeded"})
                    break
                try:
                    line = raw_line.decode("utf-8")
                except UnicodeDecodeError:
                    errors.append({"line": line_no, "error": "invalid_utf8"})
                    break
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    errors.append({"line": line_no, "error": "malformed_json"})
                    continue
                result = validate_record(row)
                if result.valid:
                    valid += 1
                else:
                    errors.append({"line": line_no, "error": "invalid_record", "reasons": list(result.errors)})
    except OSError:
        return {"path": str(path), "records_seen": total, "valid_records": valid,
                "errors": errors + [{"error": "input_io_error"}], "valid": False}
    return {"path": str(path), "records_seen": total, "valid_records": valid,
            "errors": errors, "valid": not errors and total > 0}
