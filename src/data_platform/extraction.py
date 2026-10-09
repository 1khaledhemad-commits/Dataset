"""Streaming extraction for text, JSON/JSONL, CSV/TSV, and safe text archives."""

from __future__ import annotations

import base64
import binascii
import csv
import hashlib
import heapq
import gzip
import html.parser
import io
import json
import re
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

from .errors import PipelineError
from .models import ExtractedRecord
from .security import scan_suspicious_archive_name


class _VisibleText(html.parser.HTMLParser):
    """Extract visible HTML text while preserving block and preformatted layout."""

    _BLOCK_TAGS = {"address", "article", "blockquote", "br", "dd", "div", "dl", "dt", "footer",
                   "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "ol",
                   "p", "section", "table", "tr", "ul"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._blocked = 0
        self._pre_depth = 0

    def _block_break(self) -> None:
        if self.parts and not self.parts[-1].endswith("\n"):
            self.parts.append("\n")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in {"script", "style", "noscript"}:
            self._blocked += 1
        if tag == "pre":
            self._block_break()
            self._pre_depth += 1
        elif tag in self._BLOCK_TAGS:
            self._block_break()

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in {"script", "style", "noscript"} and self._blocked:
            self._blocked -= 1
        if tag == "pre" and self._pre_depth:
            self._pre_depth -= 1
            self._block_break()
        elif tag in self._BLOCK_TAGS:
            self._block_break()

    def handle_data(self, data: str) -> None:
        if self._blocked or not data:
            return
        if self._pre_depth:
            self.parts.append(data.replace("\r\n", "\n").replace("\r", "\n"))
        else:
            # Source-indentation between HTML tags is layout noise; retain paragraph
            # boundaries from block elements and preserve literal preformatted blocks.
            self.parts.append(re.sub(r"[\t\r\n\f\v ]+", " ", data))

    def text(self) -> str:
        value = "".join(self.parts).replace("\r\n", "\n").replace("\r", "\n")
        value = re.sub(r"\n{3,}", "\n\n", value)
        return value.strip()


def _get_text(row: Any, text_field: str | None) -> tuple[str, dict[str, Any]]:
    if isinstance(row, str):
        return row, {}
    if not isinstance(row, dict):
        raise PipelineError("Structured record must be a string or object", code="invalid_record_shape")
    candidate: Any = row
    selected_path: list[str] = []
    if text_field:
        selected_path = text_field.split(".")
        for key in selected_path:
            if not isinstance(candidate, dict) or key not in candidate:
                raise PipelineError(f"Configured text field is absent: {text_field}", code="missing_text_field")
            candidate = candidate[key]
    else:
        for key in ("text", "content", "document", "passage", "question"):
            if isinstance(row.get(key), str):
                candidate = row[key]
                selected_path = [key]
                break
        else:
            raise PipelineError("No text field found; configure text_field explicitly", code="missing_text_field")
    if not isinstance(candidate, str):
        raise PipelineError("Selected text field must be a string", code="invalid_text_field")
    attributes = dict(row)
    if selected_path:
        current: dict[str, Any] = attributes
        for key in selected_path[:-1]:
            nested = current.get(key)
            if not isinstance(nested, dict):
                break
            nested_copy = dict(nested)
            current[key] = nested_copy
            current = nested_copy
        current.pop(selected_path[-1], None)
    return candidate, attributes


def extract_artifact(
    path: str | Path,
    *,
    source: dict[str, Any],
    asset: dict[str, Any],
    artifact_manifest: dict[str, Any],
    text_field: str | None = None,
    max_records: int = 100_000,
    max_expanded_bytes: int = 64 * 1024 * 1024,
    stats: dict[str, int] | None = None,
) -> Iterator[ExtractedRecord]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise PipelineError("Extraction input must be a regular non-symlink file", code="unsafe_artifact_path")
    try:
        artifact_size = path.stat().st_size
    except OSError as exc:
        raise PipelineError("Extraction input could not be inspected", code="input_io_error") from exc
    if artifact_size > max_expanded_bytes:
        raise PipelineError("Artifact exceeds the configured extraction byte limit", code="expanded_size_limit")
    fmt = str(asset.get("format", path.suffix.lstrip("."))).lower()
    common = {
        "source_id": source["source_id"],
        "source_url": artifact_manifest.get("final_url") or asset.get("url", ""),
        "source_revision": source.get("source_revision") or "",
        "license_id": (source.get("license") or {}).get("spdx_id") or (source.get("license") or {}).get("name", "Unknown"),
        "domain": asset.get("domain", "general"),
        "task_type": asset.get("task_type", "language_modeling"),
    }

    def make(text: str, key: str, attributes: dict[str, Any] | None = None) -> ExtractedRecord:
        provenance = {
            "artifact_sha256": artifact_manifest.get("sha256", ""),
            "artifact_byte_count": artifact_manifest.get("byte_count", 0),
            "artifact_path": artifact_manifest.get("path", str(path)),
            "asset_id": asset.get("asset_id", path.name),
            "fixture_only": bool(artifact_manifest.get("fixture_only", False)),
        }
        return ExtractedRecord(source_record_id=key, text=text, attributes=attributes or {}, provenance=provenance, **common)

    emitted = 0
    if max_records <= 0 or max_expanded_bytes <= 0:
        raise PipelineError("Extraction limits must be positive", code="invalid_resource_policy")
    try:
        if fmt in {"jsonl", "ndjson"}:
            with path.open("r", encoding="utf-8", newline="") as handle:
                for line_no, line in enumerate(handle, 1):
                    if not line.strip():
                        continue
                    if emitted >= max_records:
                        raise PipelineError("Record limit exceeded", code="record_quota_exceeded")
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise PipelineError(f"Malformed JSONL at line {line_no}", code="malformed_jsonl") from exc
                    text, attrs = _get_text(row, text_field)
                    emitted += 1
                    yield make(text, str(row.get("id", line_no)) if isinstance(row, dict) else str(line_no), attrs)
        elif fmt == "json":
            if path.stat().st_size > max_expanded_bytes:
                raise PipelineError("JSON input exceeds bounded parser size", code="expanded_size_limit")
            value = json.loads(path.read_text(encoding="utf-8"))
            encoding = asset.get("content_encoding")
            if encoding in {"github_git_blob_base64", "github_contents_api_base64"}:
                if not isinstance(value, dict) or value.get("encoding") != "base64":
                    raise PipelineError("GitHub API response is not a base64 blob/file object", code="invalid_github_api_object")
                try:
                    decoded = base64.b64decode("".join(str(value.get("content", "")).split()), validate=True)
                    if len(decoded) > max_expanded_bytes:
                        raise PipelineError("Decoded GitHub content exceeds the configured byte limit", code="expanded_size_limit")
                    decoded_text = decoded.decode("utf-8")
                except (binascii.Error, UnicodeDecodeError) as exc:
                    raise PipelineError("GitHub file content is invalid base64 or UTF-8", code="invalid_github_api_object") from exc
                reported_sha = str(value.get("sha", ""))
                if encoding == "github_git_blob_base64":
                    actual_blob_sha = hashlib.sha1(b"blob " + str(len(decoded)).encode("ascii") + b"\0" + decoded).hexdigest()
                    expected_blob_sha = str(asset.get("source_git_blob_sha1", ""))
                    if not reported_sha or reported_sha != actual_blob_sha or (expected_blob_sha and actual_blob_sha != expected_blob_sha):
                        raise PipelineError("GitHub Git blob SHA-1 verification failed", code="source_blob_checksum_mismatch")
                elif asset.get("source_git_blob_sha1") and reported_sha != asset["source_git_blob_sha1"]:
                    raise PipelineError("GitHub Contents API blob SHA does not match registry", code="source_blob_checksum_mismatch")
                decoded_format = asset.get("decoded_format", "text")
                if decoded_format in {"jsonl", "ndjson"}:
                    source_fields = asset.get("text_fields")
                    if not isinstance(source_fields, list) or not source_fields or not all(isinstance(x, str) for x in source_fields):
                        raise PipelineError("Multi-field JSONL extraction requires explicit text_fields", code="invalid_extraction_config")
                    sample_size = asset.get("sample_records")
                    sample_size = min(int(sample_size), max_records) if sample_size is not None else None
                    if sample_size is not None and sample_size <= 0:
                        raise PipelineError("sample_records must be positive", code="invalid_extraction_config")
                    sample_seed = str(asset.get("sample_seed", "0"))
                    max_source_records = int(asset.get("max_source_records", max_records))
                    if max_source_records <= 0:
                        raise PipelineError("max_source_records must be positive", code="invalid_extraction_config")
                    heap: list[tuple[int, int, ExtractedRecord]] = []
                    scanned = 0
                    for line_no, line in enumerate(decoded_text.splitlines(), 1):
                        if not line.strip():
                            continue
                        scanned += 1
                        if scanned > max_source_records:
                            raise PipelineError("Source scan record limit exceeded", code="record_quota_exceeded")
                        try:
                            row = json.loads(line)
                        except json.JSONDecodeError as exc:
                            raise PipelineError(f"Malformed decoded JSONL at line {line_no}", code="malformed_jsonl") from exc
                        if not isinstance(row, dict):
                            raise PipelineError(f"Decoded JSONL row must be an object at line {line_no}", code="invalid_record_shape")
                        chunks = []
                        for key in source_fields:
                            field_value = row.get(key)
                            if not isinstance(field_value, str) or not field_value.strip():
                                raise PipelineError(f"Required source field is absent or empty: {key}", code="missing_text_field")
                            label = {"question": "Question", "answer": "Solution"}.get(key, key.replace("_", " ").title())
                            chunks.append(f"{label}:\n{field_value}")
                        text = "\n\n".join(chunks)
                        row_id = str(row.get("id") or f"{reported_sha}:{line_no}")
                        row_attrs = {key: item for key, item in row.items() if key not in source_fields}
                        row_attrs["source_field_names"] = list(source_fields)
                        row_attrs["source_file_path"] = asset.get("source_path")
                        row_attrs["source_git_blob_sha1"] = reported_sha
                        extracted = make(text, row_id, row_attrs)
                        if sample_size is None:
                            if emitted >= max_records:
                                raise PipelineError("Record limit exceeded", code="record_quota_exceeded")
                            emitted += 1
                            yield extracted
                        else:
                            score = int.from_bytes(hashlib.sha256(f"{sample_seed}\0{row_id}".encode("utf-8")).digest(), "big")
                            candidate = (-score, -line_no, extracted)
                            if len(heap) < sample_size:
                                heapq.heappush(heap, candidate)
                            elif score < -heap[0][0]:
                                heapq.heapreplace(heap, candidate)
                    if sample_size is not None:
                        for _, negative_line, extracted in sorted(heap, key=lambda item: -item[1]):
                            emitted += 1
                            yield extracted
                    if stats is not None:
                        stats["source_records_scanned"] = scanned
                elif decoded_format in {"text", "txt", "rst", "markdown", "md"}:
                    yield make(decoded_text, str(value.get("path") or asset.get("source_path") or asset.get("asset_id")),
                               {"source_git_blob_sha1": reported_sha, "decoded_format": decoded_format})
                    emitted = 1
                    if stats is not None:
                        stats["source_records_scanned"] = 1
                else:
                    raise PipelineError(f"Unsupported decoded GitHub content format: {decoded_format}", code="unsupported_format")
            else:
                rows = value if isinstance(value, list) else value.get("data", [value]) if isinstance(value, dict) else None
                if not isinstance(rows, list):
                    raise PipelineError("JSON root must be an object or list", code="invalid_json_shape")
                for index, row in enumerate(rows):
                    if emitted >= max_records:
                        raise PipelineError("Record limit exceeded", code="record_quota_exceeded")
                    text, attrs = _get_text(row, text_field)
                    emitted += 1
                    yield make(text, str(row.get("id", index)) if isinstance(row, dict) else str(index), attrs)
                if stats is not None:
                    stats["source_records_scanned"] = len(rows)
        elif fmt in {"csv", "tsv"}:
            delimiter = "\t" if fmt == "tsv" else ","
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle, delimiter=delimiter)
                for line_no, row in enumerate(reader, 2):
                    if emitted >= max_records:
                        raise PipelineError("Record limit exceeded", code="record_quota_exceeded")
                    if None in row:
                        raise PipelineError(f"Malformed delimited row at line {line_no}", code="malformed_csv")
                    text, attrs = _get_text(row, text_field)
                    emitted += 1
                    yield make(text, str(row.get("id") or line_no), attrs)
        elif fmt in {"text", "txt", "markdown", "md", "rst", "html", "htm"}:
            raw = path.read_bytes()
            if len(raw) > max_expanded_bytes:
                raise PipelineError("Text input exceeds configured expansion limit", code="expanded_size_limit")
            text = raw.decode("utf-8-sig", errors="strict")
            if fmt in {"html", "htm"}:
                parser = _VisibleText()
                parser.feed(text)
                text = parser.text()
            if not text.strip():
                raise PipelineError("Text artifact contains no visible content", code="empty_artifact")
            emitted = 1
            yield make(text, asset.get("record_id", path.name), {})
            if stats is not None:
                stats["source_records_scanned"] = 1
        elif fmt == "gz":
            try:
                with gzip.open(path, "rb") as compressed:
                    raw = compressed.read(max_expanded_bytes + 1)
            except (OSError, EOFError) as exc:
                raise PipelineError("Corrupt gzip text artifact", code="corrupt_archive") from exc
            if len(raw) > max_expanded_bytes:
                raise PipelineError("gzip text exceeds configured expansion limit", code="expanded_size_limit")
            try:
                text = raw.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise PipelineError("gzip text is not UTF-8", code="invalid_encoding") from exc
            if not text.strip():
                raise PipelineError("gzip text contains no visible content", code="empty_artifact")
            emitted = 1
            yield make(text, asset.get("record_id", path.stem), {})
            if stats is not None:
                stats["source_records_scanned"] = 1
        elif fmt in {"zip", "tar", "tar.gz", "tgz"}:
            total = 0
            archive_declared = 0
            seen = 0
            def emit_text(name: str, handle: Any) -> Iterator[ExtractedRecord]:
                nonlocal total, seen
                safe = scan_suspicious_archive_name(name)
                if safe:
                    raise PipelineError(f"Unsafe archive member rejected ({','.join(safe)})", code="unsafe_archive")
                suffix = PurePosixPath(name.replace("\\", "/")).suffix.lower()
                if suffix in {".zip", ".tar", ".tgz", ".gz"}:
                    raise PipelineError("Nested archives are not accepted", code="nested_archive")
                if suffix not in {".txt", ".md", ".rst", ".jsonl", ".ndjson", ".csv", ".tsv"}:
                    return
                data = handle.read(max_expanded_bytes - total + 1)
                total += len(data)
                if total > max_expanded_bytes:
                    raise PipelineError("Archive expansion limit exceeded", code="expanded_size_limit")
                try:
                    text = data.decode("utf-8-sig")
                except UnicodeDecodeError as exc:
                    raise PipelineError("Archive text member is not UTF-8", code="invalid_encoding") from exc
                if suffix in {".jsonl", ".ndjson", ".csv", ".tsv"}:
                    # Expand through a bounded temporary-free in-memory parser.
                    stream = io.StringIO(text)
                    if suffix in {".jsonl", ".ndjson"}:
                        for line_no, line in enumerate(stream, 1):
                            if line.strip():
                                row = json.loads(line)
                                body, attrs = _get_text(row, text_field)
                                if seen >= max_records:
                                    raise PipelineError("Record limit exceeded", code="record_quota_exceeded")
                                seen += 1
                                yield make(body, f"{name}:{line_no}", attrs)
                    else:
                        reader = csv.DictReader(stream, delimiter="\t" if suffix == ".tsv" else ",")
                        for row_no, row in enumerate(reader, 2):
                            body, attrs = _get_text(row, text_field)
                            if seen >= max_records:
                                raise PipelineError("Record limit exceeded", code="record_quota_exceeded")
                            seen += 1
                            yield make(body, f"{name}:{row_no}", attrs)
                else:
                    if seen >= max_records:
                        raise PipelineError("Record limit exceeded", code="record_quota_exceeded")
                    seen += 1
                    yield make(text, name, {})
            if fmt == "zip":
                try:
                    with zipfile.ZipFile(path) as archive:
                        infos = archive.infolist()
                        if len(infos) > 10000:
                            raise PipelineError("ZIP contains too many members", code="archive_member_limit")
                        for info in infos:
                            if scan_suspicious_archive_name(info.filename):
                                raise PipelineError("Unsafe path in ZIP archive", code="unsafe_archive")
                            if info.file_size > max_expanded_bytes - archive_declared:
                                raise PipelineError("Archive declared expansion exceeds limit", code="expanded_size_limit")
                            archive_declared += info.file_size
                            if info.is_dir():
                                continue
                            with archive.open(info, "r") as member:
                                yield from emit_text(info.filename, member)
                except PipelineError:
                    raise
                except (zipfile.BadZipFile, RuntimeError, EOFError) as exc:
                    raise PipelineError("Corrupt or encrypted ZIP archive", code="corrupt_archive") from exc
            else:
                mode = "r:gz" if fmt in {"tar.gz", "tgz"} else "r:"
                try:
                    with tarfile.open(path, mode) as archive:
                        member_count = 0
                        for member in archive:
                            member_count += 1
                            if member_count > 10000:
                                raise PipelineError("tar contains too many members", code="archive_member_limit")
                            if scan_suspicious_archive_name(member.name) or not (member.isfile() or member.isdir()):
                                raise PipelineError("Archive contains unsafe path, link, or non-regular member", code="unsafe_archive")
                            if member.isdir():
                                continue
                            if member.size > max_expanded_bytes - archive_declared:
                                raise PipelineError("Archive declared expansion exceeds limit", code="expanded_size_limit")
                            archive_declared += member.size
                            stream = archive.extractfile(member)
                            if stream is None:
                                continue
                            with stream:
                                yield from emit_text(member.name, stream)
                except PipelineError:
                    raise
                except (tarfile.TarError, EOFError, OSError) as exc:
                    raise PipelineError("Corrupt tar archive", code="corrupt_archive") from exc
            emitted = seen
            if stats is not None:
                stats["source_records_scanned"] = seen
        else:
            raise PipelineError(f"Unsupported extraction format: {fmt}", code="unsupported_format")
    except UnicodeDecodeError as exc:
        raise PipelineError("Artifact is not valid UTF-8", code="invalid_encoding") from exc
    except json.JSONDecodeError as exc:
        raise PipelineError("Artifact contains malformed JSON", code="malformed_json") from exc
    except (zipfile.BadZipFile, tarfile.TarError, EOFError) as exc:
        raise PipelineError("Artifact archive is corrupt", code="corrupt_archive") from exc
    finally:
        if stats is not None:
            stats["records_emitted"] = emitted if "emitted" in locals() else 0
            stats.setdefault("source_records_scanned", stats["records_emitted"])
