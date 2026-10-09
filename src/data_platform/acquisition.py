"""Bounded, resumable HTTP acquisition with content-aware promotion."""

from __future__ import annotations

import base64
import codecs
import csv
import email.utils
import gzip
import hashlib
import http.client
import json
import os
import random
import re
import stat
import zlib
import shutil
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .audit import append_audit_event
from .errors import PipelineError
from .models import RAW_MANIFEST_VERSION, RawArtifactManifest
from .security import scan_suspicious_archive_name
from .sources import eligibility_for_training
from .storage import sha256_file, write_json_atomic


@dataclass(frozen=True)
class DownloadPolicy:
    max_total_bytes: int = 128 * 1024 * 1024
    max_raw_storage_bytes: int = 256 * 1024 * 1024
    max_single_file_bytes: int = 16 * 1024 * 1024
    max_expanded_bytes: int = 64 * 1024 * 1024
    free_disk_reserve_bytes: int = 512 * 1024 * 1024
    timeout_seconds: float = 20.0
    max_retries: int = 3
    backoff_seconds: float = 0.25
    jitter_seconds: float = 0.10
    allowed_hosts: tuple[str, ...] = ("github.com", "api.github.com", "codeload.github.com")
    allow_http_local_for_tests: bool = False
    chunk_bytes: int = 64 * 1024
    min_request_interval_seconds: float = 1.0
    max_redirects: int = 5
    resume_partial_downloads: bool = True


@dataclass(frozen=True)
class AcquisitionResult:
    manifest: RawArtifactManifest
    skipped_existing: bool
    attempts: int
    network_bytes_downloaded: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"manifest": self.manifest.to_dict(), "skipped_existing": self.skipped_existing,
                "attempts": self.attempts, "network_bytes_downloaded": self.network_bytes_downloaded}


_RATE_LOCK = threading.Lock()
_LAST_REQUEST_BY_HOST: dict[str, float] = {}


def _wait_for_host_rate_limit(host: str, policy: DownloadPolicy, sleep: Any) -> None:
    if policy.min_request_interval_seconds <= 0:
        return
    with _RATE_LOCK:
        now = time.monotonic()
        previous = _LAST_REQUEST_BY_HOST.get(host)
        if previous is not None:
            delay = policy.min_request_interval_seconds - (now - previous)
            if delay > 0:
                sleep(delay)
        _LAST_REQUEST_BY_HOST[host] = time.monotonic()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _promote_file_exclusive(staged: Path, target: Path) -> None:
    """Atomically publish a same-filesystem file without replacing an existing path."""
    try:
        os.link(staged, target)
    except FileExistsError as exc:
        raise PipelineError("Refusing to overwrite an existing raw artifact", code="existing_artifact_conflict") from exc
    os.unlink(staged)
    try:
        directory_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        pass


def _path_has_symlink_component(path: Path) -> bool:
    current = path.absolute()
    while True:
        if current.is_symlink():
            return True
        if current.parent == current:
            return False
        current = current.parent


def _is_local_host(host: str) -> bool:
    return host in {"localhost", "127.0.0.1", "::1"}


def _validate_url(url: str, policy: DownloadPolicy) -> None:
    if len(url.encode("utf-8")) > 2048:
        raise PipelineError("Source URL exceeds the configured metadata safety limit", code="unsafe_url")
    parsed = urllib.parse.urlparse(url)
    if parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise PipelineError("Source URL must not contain credentials, query parameters, or a fragment", code="unsafe_url")
    try:
        port = parsed.port
    except ValueError as exc:
        raise PipelineError("Source URL has an invalid port", code="unsafe_url") from exc
    if parsed.scheme == "https" and port not in {None, 443}:
        raise PipelineError("Only the standard HTTPS port is allowed", code="unsafe_url")
    if parsed.scheme != "https" and not (policy.allow_http_local_for_tests and parsed.scheme == "http" and _is_local_host(parsed.hostname or "")):
        raise PipelineError("Only HTTPS source URLs are allowed (HTTP loopback is test-only)", code="unsafe_url")
    if not parsed.hostname or parsed.hostname.lower() not in {h.lower() for h in policy.allowed_hosts} and not (
        policy.allow_http_local_for_tests and _is_local_host(parsed.hostname or "")
    ):
        raise PipelineError("Source host is outside the configured allowlist", code="host_not_allowed")


def _raw_usage(root: Path) -> tuple[int, dict[str, int]]:
    total = 0
    by_source: dict[str, int] = {}
    if not root.exists():
        return 0, by_source
    for file_path in root.rglob("*"):
        try:
            if file_path.is_symlink():
                size = file_path.lstat().st_size
            elif file_path.is_file():
                size = file_path.stat().st_size
            else:
                continue
            total += size
            try:
                source_id = file_path.relative_to(root).parts[0]
            except (ValueError, IndexError):
                source_id = "_other"
            by_source[source_id] = by_source.get(source_id, 0) + size
        except OSError:
            continue
    return total, by_source


def _validate_content(path: Path, fmt: str, max_expanded_bytes: int, content_type: str,
                      asset: dict[str, Any] | None = None) -> None:
    """Reject invalid format signatures, HTML error pages and unsafe archives."""
    if path.stat().st_size == 0:
        raise PipelineError("Downloaded artifact is empty", code="empty_artifact")
    with path.open("rb") as handle:
        prefix = handle.read(4096)
    stripped = prefix.lstrip(b"\xef\xbb\xbf\x00\t\r\n ").lower()
    if fmt not in {"html", "htm"} and (
        stripped.startswith(b"<!doctype html") or stripped.startswith(b"<html") or
        ("text/html" in content_type.lower() and fmt not in {"text", "txt", "markdown", "md", "rst"})
    ):
        raise PipelineError("Server returned HTML where a data artifact was expected", code="unexpected_html")
    if fmt in {"json", "jsonl", "ndjson"}:
        try:
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                if fmt == "json":
                    response = json.load(handle)
                    encoding = (asset or {}).get("content_encoding")
                    if encoding in {"github_git_blob_base64", "github_contents_api_base64"}:
                        if not isinstance(response, dict) or response.get("encoding") != "base64":
                            raise ValueError("GitHub response is not a base64 object")
                        try:
                            decoded = base64.b64decode("".join(str(response.get("content", "")).split()), validate=True)
                            decoded.decode("utf-8")
                        except (ValueError, UnicodeDecodeError) as exc:
                            raise ValueError("invalid base64 or UTF-8 payload") from exc
                        if encoding == "github_git_blob_base64":
                            actual_sha = hashlib.sha1(b"blob " + str(len(decoded)).encode("ascii") + b"\0" + decoded).hexdigest()
                            reported_sha = str(response.get("sha", ""))
                            expected_sha = str((asset or {}).get("source_git_blob_sha1", ""))
                            if actual_sha != reported_sha or (expected_sha and actual_sha != expected_sha):
                                raise PipelineError("GitHub Git blob SHA-1 verification failed", code="source_blob_checksum_mismatch")
                            if response.get("size") is not None and int(response["size"]) != len(decoded):
                                raise PipelineError("GitHub Git blob size metadata mismatch", code="source_blob_size_mismatch")
                        elif (asset or {}).get("source_git_blob_sha1") and response.get("sha") != asset["source_git_blob_sha1"]:
                            raise PipelineError("GitHub Contents API blob SHA does not match registry", code="source_blob_checksum_mismatch")
                        decoded_format = (asset or {}).get("decoded_format", "text")
                        if decoded_format in {"jsonl", "ndjson"}:
                            seen_rows = 0
                            for line_no, line in enumerate(decoded.decode("utf-8").splitlines(), 1):
                                if not line.strip():
                                    continue
                                value = json.loads(line)
                                if not isinstance(value, dict):
                                    raise ValueError(f"decoded JSONL row {line_no} is not an object")
                                seen_rows += 1
                            if not seen_rows:
                                raise ValueError("decoded JSONL is empty")

                else:
                    found = False
                    for line_no, line in enumerate(handle, 1):
                        if not line.strip():
                            continue
                        json.loads(line)
                        found = True
                    if not found:
                        raise ValueError("no JSONL records")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise PipelineError("Downloaded artifact is not valid UTF-8 JSON/JSONL", code="format_validation_failed") from exc
    elif fmt in {"csv", "tsv"}:
        try:
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.reader(handle, delimiter="\t" if fmt == "tsv" else ",", strict=True)
                rows = 0
                first_width: int | None = None
                for row in reader:
                    if first_width is None:
                        first_width = len(row)
                    elif len(row) != first_width:
                        raise ValueError("inconsistent row width")
                    rows += 1
                if rows < 2:
                    raise ValueError("missing header or data rows")
        except (UnicodeDecodeError, csv.Error, ValueError) as exc:
            raise PipelineError("Downloaded CSV/TSV structure is invalid", code="format_validation_failed") from exc
    elif fmt in {"text", "txt", "markdown", "md", "rst", "html", "htm"}:
        try:
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), ""):
                    if "\x00" in chunk:
                        raise ValueError("NUL bytes in text")
        except (UnicodeDecodeError, ValueError) as exc:
            raise PipelineError("Downloaded text artifact is not clean UTF-8", code="format_validation_failed") from exc
    elif fmt == "gz":
        decoder = codecs.getincrementaldecoder("utf-8-sig")()
        expanded = 0
        try:
            with gzip.open(path, "rb") as archive:
                while True:
                    chunk = archive.read(min(64 * 1024, max_expanded_bytes - expanded + 1))
                    if not chunk:
                        break
                    expanded += len(chunk)
                    if expanded > max_expanded_bytes:
                        raise PipelineError("gzip text exceeds configured expansion limit", code="expanded_size_limit")
                    decoder.decode(chunk)
                decoder.decode(b"", final=True)
        except PipelineError:
            raise
        except (OSError, EOFError, UnicodeDecodeError, zlib.error) as exc:
            raise PipelineError("Corrupt gzip text or invalid UTF-8", code="corrupt_archive") from exc
    elif fmt == "zip":
        try:
            with zipfile.ZipFile(path) as archive:
                infos = archive.infolist()
                if len(infos) > 10000:
                    raise PipelineError("ZIP contains too many members", code="archive_member_limit")
                expanded = 0
                for info in infos:
                    if scan_suspicious_archive_name(info.filename):
                        raise PipelineError("Unsafe path in ZIP archive", code="unsafe_archive")
                    if info.is_dir():
                        continue
                    file_mode = (info.external_attr >> 16) & 0o170000
                    if file_mode == stat.S_IFLNK:
                        raise PipelineError("ZIP contains a symbolic link", code="unsafe_archive")
                    if info.filename.lower().endswith((".zip", ".tar", ".tar.gz", ".tgz", ".gz")):
                        raise PipelineError("Nested archives are not accepted", code="nested_archive")
                    if info.file_size > max_expanded_bytes - expanded:
                        raise PipelineError("ZIP exceeds configured expansion limit", code="expanded_size_limit")
                    actual = 0
                    with archive.open(info, "r") as member:
                        while True:
                            chunk = member.read(min(64 * 1024, max_expanded_bytes - expanded - actual + 1))
                            if not chunk:
                                break
                            actual += len(chunk)
                            if expanded + actual > max_expanded_bytes:
                                raise PipelineError("ZIP expanded bytes exceed configured limit", code="expanded_size_limit")
                    if actual != info.file_size:
                        raise PipelineError("ZIP member size does not match its header", code="corrupt_archive")
                    expanded += actual
        except PipelineError:
            raise
        except (zipfile.BadZipFile, RuntimeError, EOFError, zlib.error) as exc:
            raise PipelineError("Corrupt or encrypted ZIP archive", code="corrupt_archive") from exc
    elif fmt in {"tar", "tar.gz", "tgz"}:
        mode = "r:gz" if fmt in {"tar.gz", "tgz"} else "r:"
        try:
            expanded = 0
            with tarfile.open(path, mode) as archive:
                members = 0
                for member in archive:
                    members += 1
                    if members > 10000:
                        raise PipelineError("tar contains too many members", code="archive_member_limit")
                    if scan_suspicious_archive_name(member.name) or not (member.isfile() or member.isdir()):
                        raise PipelineError("Unsafe member type or path in tar archive", code="unsafe_archive")
                    if member.isdir():
                        continue
                    if member.name.lower().endswith((".zip", ".tar", ".tar.gz", ".tgz", ".gz")):
                        raise PipelineError("Nested archives are not accepted", code="nested_archive")
                    if member.size > max_expanded_bytes - expanded:
                        raise PipelineError("tar exceeds configured expansion limit", code="expanded_size_limit")
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise PipelineError("tar member could not be read", code="corrupt_archive")
                    actual = 0
                    with stream:
                        while True:
                            chunk = stream.read(min(64 * 1024, max_expanded_bytes - expanded - actual + 1))
                            if not chunk:
                                break
                            actual += len(chunk)
                            if expanded + actual > max_expanded_bytes:
                                raise PipelineError("tar expanded bytes exceed configured limit", code="expanded_size_limit")
                    if actual != member.size:
                        raise PipelineError("tar member size does not match its header", code="corrupt_archive")
                    expanded += actual
        except PipelineError:
            raise
        except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
            raise PipelineError("Corrupt tar archive", code="corrupt_archive") from exc
    else:
        raise PipelineError(f"Unsupported expected format: {fmt}", code="unsupported_format")


def acquire_http(
    source: dict[str, Any],
    asset: dict[str, Any],
    *,
    raw_root: str | Path,
    policy: DownloadPolicy,
    per_source_quota_bytes: int | None = None,
    expected_sha256: str | None = None,
    source_revision: str | None = None,
    refresh: bool = False,
    dry_run: bool = False,
    opener: Any | None = None,
    sleep: Any = time.sleep,
    random_uniform: Any = random.uniform,
) -> AcquisitionResult | dict[str, Any]:
    """Acquire one governed asset and append privacy-minimal audit events."""
    if dry_run:
        return _acquire_http_impl(
            source, asset, raw_root=raw_root, policy=policy,
            per_source_quota_bytes=per_source_quota_bytes, expected_sha256=expected_sha256,
            source_revision=source_revision, refresh=refresh, dry_run=True,
            opener=opener, sleep=sleep, random_uniform=random_uniform,
        )
    raw_path = Path(raw_root)
    project_root = raw_path.parent.parent if raw_path.parent.name == "data" else raw_path.parent
    source_id = str(source.get("source_id", ""))
    asset_id = str(asset.get("asset_id", ""))
    url = str(asset.get("url", ""))
    try:
        parsed = urllib.parse.urlparse(url)
        url_fingerprint = hashlib.sha256(url.encode("utf-8")).hexdigest() if url else None
        append_audit_event(project_root, {
            "event": "acquisition_started", "source_id": source_id[:80], "asset_id": asset_id[:120],
            "url_host": parsed.hostname, "url_sha256": url_fingerprint,
            "fixture_only": False,
        })
    except OSError as exc:
        raise PipelineError("Unable to persist acquisition audit start event", code="audit_write_failed") from exc
    try:
        result = _acquire_http_impl(
            source, asset, raw_root=raw_root, policy=policy,
            per_source_quota_bytes=per_source_quota_bytes, expected_sha256=expected_sha256,
            source_revision=source_revision, refresh=refresh, dry_run=False,
            opener=opener, sleep=sleep, random_uniform=random_uniform,
        )
    except Exception as exc:
        error_code = exc.code if isinstance(exc, PipelineError) else type(exc).__name__
        try:
            append_audit_event(project_root, {
                "event": "acquisition_failed", "source_id": source_id[:80], "asset_id": asset_id[:120],
                "url_host": parsed.hostname, "url_sha256": url_fingerprint,
                "error_code": error_code, "fixture_only": False,
            })
        except OSError as audit_exc:
            raise PipelineError("Acquisition failed and its audit event could not be persisted", code="audit_write_failed") from audit_exc
        raise
    if isinstance(result, AcquisitionResult):
        try:
            append_audit_event(project_root, {
                "event": "acquisition_reused" if result.skipped_existing else "acquisition_completed",
                "source_id": result.manifest.source_id, "asset_id": result.manifest.asset_id,
                "url_host": parsed.hostname, "url_sha256": url_fingerprint,
                "attempts": result.attempts, "network_bytes_downloaded": result.network_bytes_downloaded,
                "artifact_bytes": result.manifest.byte_count, "artifact_sha256": result.manifest.sha256,
                "fixture_only": False,
            })
        except OSError as exc:
            raise PipelineError("Acquisition succeeded but its audit event could not be persisted", code="audit_write_failed") from exc
    return result


def _acquire_http_impl(
    source: dict[str, Any],
    asset: dict[str, Any],
    *,
    raw_root: str | Path,
    policy: DownloadPolicy,
    per_source_quota_bytes: int | None = None,
    expected_sha256: str | None = None,
    source_revision: str | None = None,
    refresh: bool = False,
    dry_run: bool = False,
    opener: Any | None = None,
    sleep: Any = time.sleep,
    random_uniform: Any = random.uniform,
) -> AcquisitionResult | dict[str, Any]:
    """Acquire one registered asset; partial downloads remain resumable.

    A complete artifact and sidecar manifest are promoted only after HTTP length,
    checksum (when trusted), encoding, and expected-format checks pass.
    """
    purpose = str(asset.get("dataset_purpose", "pretraining"))
    purpose_eligible, purpose_reason = eligibility_for_training(source, purpose)
    if not purpose_eligible:
        raise PipelineError(f"Source {source.get('source_id', '<unknown>')} is not eligible: {purpose_reason}",
                            code="source_not_eligible")
    if (policy.max_total_bytes <= 0 or policy.max_raw_storage_bytes <= 0 or
            policy.max_single_file_bytes <= 0 or policy.max_expanded_bytes <= 0 or
            policy.chunk_bytes <= 0 or policy.timeout_seconds <= 0 or policy.max_retries < 0 or
            policy.min_request_interval_seconds < 0 or policy.max_redirects < 0 or not policy.allowed_hosts):
        raise PipelineError("Download policy contains an invalid limit", code="invalid_download_policy")
    url = str(asset.get("url", ""))
    _validate_url(url, policy)
    asset_id = str(asset.get("asset_id", ""))
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}", asset_id):
        raise PipelineError("asset_id is not a safe filename component", code="unsafe_asset_id")
    source_id = str(source.get("source_id", ""))
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,63}", source_id):
        raise PipelineError("source_id is not a safe storage component", code="unsafe_source_id")
    fmt = str(asset.get("format", "")).lower()
    try:
        asset_max = int(asset.get("max_bytes") or policy.max_single_file_bytes)
    except (TypeError, ValueError) as exc:
        raise PipelineError("Asset max_bytes must be a positive integer", code="invalid_quota") from exc
    max_file = min(policy.max_single_file_bytes, asset_max)
    if max_file <= 0:
        raise PipelineError("Single-file limit must be positive", code="invalid_quota")
    root = Path(raw_root)
    source_dir = root / str(source["source_id"])
    suffix = fmt if fmt in {"jsonl", "ndjson", "json", "csv", "tsv", "txt", "text", "md", "markdown", "rst", "html", "zip", "tar", "tar.gz", "tgz", "gz"} else "bin"
    target = source_dir / f"{asset_id}.{suffix}"
    sidecar = source_dir / f"{asset_id}.manifest.json"
    part = target.with_name(target.name + ".part")
    part_metadata = target.with_name(target.name + ".part.meta.json")
    expected = expected_sha256 or asset.get("sha256")
    source_quota = per_source_quota_bytes if per_source_quota_bytes is not None else policy.max_raw_storage_bytes
    if source_quota <= 0:
        raise PipelineError("Per-source raw-data quota must be positive", code="invalid_quota")
    if (_path_has_symlink_component(root) or _path_has_symlink_component(source_dir) or
            target.is_symlink() or sidecar.is_symlink() or part.is_symlink() or part_metadata.is_symlink()):
        raise PipelineError("Raw storage paths must not be symbolic links", code="unsafe_storage_path")
    if target.exists() or sidecar.exists():
        if refresh:
            raise PipelineError("Raw artifacts are immutable; register a new pinned asset/revision instead of refreshing in place",
                                code="immutable_raw_artifact")
        if target.exists() and sidecar.exists():
            try:
                previous = json.loads(sidecar.read_text(encoding="utf-8"))
                local_hash = sha256_file(target)
                if previous.get("sha256") == local_hash and previous.get("source_url") == url and previous.get("asset_id") == asset_id:
                    return AcquisitionResult(RawArtifactManifest(**previous), True, 0, 0)
            except (OSError, ValueError, TypeError, KeyError):
                pass
        raise PipelineError("Existing artifact or manifest does not verify; use explicit review, not overwrite",
                            code="existing_artifact_conflict")
    if dry_run:
        return {
            "source_id": source["source_id"], "asset_id": asset_id, "url": url,
            "destination": str(target), "format": fmt, "max_bytes": max_file,
            "expected_sha256": expected, "dry_run": True,
        }
    source_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        source_dir.chmod(0o700)
    except OSError:
        pass
    if part.exists() and not part.is_file():
        raise PipelineError("Partial artifact is not a regular file", code="unsafe_partial_artifact")
    local_existing = part.stat().st_size if part.exists() else 0
    resume_validator: tuple[str, str] | None = None
    if not policy.resume_partial_downloads and (part.exists() or part_metadata.exists()):
        _quarantine_partial(part, part_metadata, root, source_id, "resume-disabled")
        local_existing = 0
    elif part.exists():
        try:
            partial_info = json.loads(part_metadata.read_text(encoding="utf-8")) if part_metadata.is_file() else {}
        except (OSError, UnicodeError, json.JSONDecodeError):
            partial_info = {}
        url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()
        identity_matches = (partial_info.get("url_sha256") == url_hash and
                            partial_info.get("asset_id") == asset_id and
                            partial_info.get("source_revision") == (source_revision or source.get("source_revision")))
        if partial_info.get("etag"):
            resume_validator = ("ETag", str(partial_info["etag"]))
        elif partial_info.get("last_modified"):
            resume_validator = ("Last-Modified", str(partial_info["last_modified"]))
        if not identity_matches or resume_validator is None:
            _quarantine_partial(part, part_metadata, root, source_id, "partial-not-safely-resumable")
            local_existing = 0
            resume_validator = None
    elif part_metadata.exists():
        _quarantine(part_metadata, root, source_id, "orphaned-part-metadata")
    if local_existing > max_file:
        _quarantine_partial(part, part_metadata, root, source_id, "oversized-part")
        local_existing = 0
        resume_validator = None
    existing_total, by_source = _raw_usage(root)
    source_used = by_source.get(source_id, 0)
    local_metadata_bytes = part_metadata.stat().st_size if local_existing and part_metadata.exists() else 0
    local_artifact_bytes = local_existing + local_metadata_bytes
    other_total = max(0, existing_total - local_artifact_bytes)
    other_source = max(0, source_used - local_artifact_bytes)
    manifest_reserve = min(4096, max(1024, 2 * len(url.encode("utf-8")) + 512))
    artifact_size_cap = min(max_file,
                            policy.max_raw_storage_bytes - other_total - local_metadata_bytes - manifest_reserve,
                            source_quota - other_source - local_metadata_bytes - manifest_reserve)
    if artifact_size_cap <= 0 or local_existing > artifact_size_cap:
        if part.exists() and local_existing > 0:
            _quarantine_partial(part, part_metadata, root, source_id, "quota-exceeded-part")
        raise PipelineError("No remaining raw-data quota for this artifact", code="storage_quota_exceeded")
    disk_free = shutil.disk_usage(source_dir).free
    if disk_free < policy.free_disk_reserve_bytes:
        raise PipelineError("Free disk is below the configured safety reserve", code="disk_reserve_exceeded")
    if opener is None:
        opener = urllib.request.build_opener(_NoRedirect())
    attempts = 0
    redirects = 0
    request_url = url
    final_url = url
    content_type = "application/octet-stream"
    etag: str | None = None
    last_modified: str | None = None
    declared_length: int | None = None
    network_bytes = 0
    wire_budget = policy.max_total_bytes

    while attempts <= policy.max_retries:
        headers = {"User-Agent": "AI-FOUNDATION-data-platform/0.1 (+https://github.com/1khaledhemad-commits/Dataset)"}
        if local_existing:
            headers["Range"] = f"bytes={local_existing}-"
            headers["If-Range"] = resume_validator[1]
        request = urllib.request.Request(request_url, headers=headers, method="GET")
        _wait_for_host_rate_limit(urllib.parse.urlparse(request_url).hostname or "", policy, sleep)
        attempts += 1
        try:
            with opener.open(request, timeout=policy.timeout_seconds) as response:
                status = getattr(response, "status", response.getcode())
                if status in {301, 302, 303, 307, 308}:
                    location = response.headers.get("Location")
                    if not location or redirects >= policy.max_redirects:
                        raise PipelineError("Redirect missing Location or redirect limit exceeded", code="redirect_rejected")
                    next_url = urllib.parse.urljoin(request_url, location)
                    _validate_url(next_url, policy)
                    redirects += 1
                    request_url = next_url
                    continue
                if status == 304 and target.exists():
                    raise PipelineError("Unexpected 304 without an explicit conditional refresh", code="unexpected_not_modified")
                if status not in {200, 206}:
                    raise PipelineError(f"Unexpected HTTP status {status}", code="http_status", retryable=status in {408, 425, 429} or status >= 500)
                final_url = response.geturl() or request_url
                _validate_url(final_url, policy)
                content_type = response.headers.get("Content-Type", "application/octet-stream")
                etag = response.headers.get("ETag")
                last_modified = response.headers.get("Last-Modified")
                response_length = response.headers.get("Content-Length")
                declared_length = None
                expected_full_size: int | None = None
                if response_length is not None:
                    try:
                        declared_length = int(response_length)
                    except ValueError as exc:
                        raise PipelineError("Invalid Content-Length header", code="invalid_content_length") from exc
                    if declared_length < 0 or declared_length > artifact_size_cap or network_bytes + declared_length > wire_budget:
                        raise PipelineError("Declared response size exceeds a configured quota", code="storage_quota_exceeded")
                if status == 200 and local_existing > 0:
                    _quarantine_partial(part, part_metadata, root, source_id, "server-restarted-full-response")
                    local_existing = 0
                    resume_validator = None
                append = status == 206 and local_existing > 0
                if status == 206:
                    content_range = response.headers.get("Content-Range", "")
                    match = re.fullmatch(r"bytes\s+(\d+)-(\d+)/(\d+|\*)", content_range)
                    if not append or not match or int(match.group(1)) != local_existing or int(match.group(2)) < int(match.group(1)):
                        raise PipelineError("Server returned an invalid or unsolicited partial response", code="range_response_mismatch")
                    range_end = int(match.group(2))
                    response_etag = response.headers.get("ETag")
                    response_last_modified = response.headers.get("Last-Modified")
                    if resume_validator and ((resume_validator[0] == "ETag" and response_etag and response_etag != resume_validator[1]) or
                                             (resume_validator[0] == "Last-Modified" and response_last_modified and response_last_modified != resume_validator[1])):
                        raise PipelineError("Resumed response validator does not match the partial artifact", code="resume_validator_mismatch")
                    if declared_length is not None and range_end - local_existing + 1 != declared_length:
                        raise PipelineError("Content-Length and Content-Range disagree", code="length_mismatch")
                    if match.group(3) != "*":
                        expected_full_size = int(match.group(3))
                        if expected_full_size <= range_end or expected_full_size > min(max_file, artifact_size_cap):
                            raise PipelineError("Content-Range total exceeds a configured quota or is inconsistent", code="storage_quota_exceeded")
                        if range_end != expected_full_size - 1:
                            raise PipelineError("Partial response did not cover the complete remaining range", code="range_response_mismatch")
                if append and declared_length is not None and local_existing + declared_length > artifact_size_cap:
                    raise PipelineError("Resumed artifact would exceed a configured quota", code="storage_quota_exceeded")
                if not append:
                    local_existing = 0
                mode = "ab" if append else "wb"
                current_validator = etag or last_modified
                if current_validator:
                    write_json_atomic(part_metadata, {
                        "url_sha256": hashlib.sha256(url.encode("utf-8")).hexdigest(),
                        "asset_id": asset_id,
                        "source_revision": source_revision or source.get("source_revision"),
                        "etag": etag,
                        "last_modified": last_modified,
                    }, overwrite=part_metadata.exists())
                    resume_validator = ("ETag", etag) if etag else ("Last-Modified", last_modified or "")
                elif not append and part_metadata.exists():
                    _quarantine(part_metadata, root, source_id, "validator-removed")
                    resume_validator = None
                current_meta_bytes = part_metadata.stat().st_size if part_metadata.exists() else 0
                artifact_size_cap = min(max_file,
                                        policy.max_raw_storage_bytes - other_total - current_meta_bytes - manifest_reserve,
                                        source_quota - other_source - current_meta_bytes - manifest_reserve)
                wire_budget = policy.max_total_bytes
                if artifact_size_cap <= 0 or wire_budget < 0 or (append and local_existing > artifact_size_cap):
                    raise PipelineError("Partial metadata leaves no remaining transfer quota", code="storage_quota_exceeded")
                digest = hashlib.sha256()
                if append:
                    with part.open("rb") as old:
                        for old_chunk in iter(lambda: old.read(policy.chunk_bytes), b""):
                            digest.update(old_chunk)
                transferred = 0
                with part.open(mode) as handle:
                    while True:
                        chunk = response.read(policy.chunk_bytes)
                        if not chunk:
                            break
                        transferred += len(chunk)
                        current_size = local_existing + transferred
                        if network_bytes + len(chunk) > wire_budget:
                            raise PipelineError("Network transfer bytes exceeded the configured download quota", code="storage_quota_exceeded")
                        if current_size > max_file or current_size > artifact_size_cap:
                            raise PipelineError("Downloaded bytes exceeded a configured quota", code="storage_quota_exceeded")
                        if shutil.disk_usage(source_dir).free - len(chunk) < policy.free_disk_reserve_bytes:
                            raise PipelineError("Download reached the free-disk safety reserve", code="disk_reserve_exceeded")
                        handle.write(chunk)
                        digest.update(chunk)
                        network_bytes += len(chunk)
                    handle.flush()
                    os.fsync(handle.fileno())
                actual_size = local_existing + transferred
                if declared_length is not None:
                    expected_response_size = declared_length + (local_existing if append else 0)
                    if actual_size < expected_response_size:
                        local_existing = actual_size
                        raise PipelineError("Response ended before its declared Content-Length; retry/resume is required",
                                            code="length_mismatch", retryable=True)
                    if actual_size > expected_response_size:
                        raise PipelineError("Response exceeded its declared Content-Length", code="length_mismatch")
                if expected_full_size is not None and actual_size != expected_full_size:
                    raise PipelineError("Resumed artifact size does not match Content-Range total", code="length_mismatch")
                if actual_size <= 0:
                    raise PipelineError("Downloaded artifact is empty", code="empty_artifact")
                if expected and digest.hexdigest().lower() != str(expected).lower():
                    _quarantine_partial(part, part_metadata, root, source_id, "checksum-mismatch")
                    raise PipelineError("SHA-256 mismatch; artifact moved to quarantine", code="checksum_mismatch")
                _validate_content(part, fmt, policy.max_expanded_bytes, content_type, asset)
                actual_hash = digest.hexdigest()
                _promote_file_exclusive(part, target)
                if part_metadata.exists():
                    part_metadata.unlink()
                manifest = RawArtifactManifest(
                    manifest_version=RAW_MANIFEST_VERSION,
                    source_id=str(source["source_id"]), asset_id=asset_id,
                    source_url=url, final_url=final_url, path=str(target), byte_count=actual_size,
                    sha256=actual_hash,
                    integrity_basis=("trusted_sha256_checksum_verified" if expected else
                                     "pinned_github_git_blob_sha1_verified; local_sha256_identifies_api_transport_only"
                                     if asset.get("source_git_blob_sha1") else
                                     "local_sha256_integrity_identifier_not_authenticity"),
                    content_type=content_type, expected_sha256=str(expected) if expected else None,
                    source_revision=source_revision or source.get("source_revision"), etag=etag,
                    last_modified=last_modified, acquired_at=_utc_now(), fixture_only=False,
                    source_checksum_algorithm="git-blob-sha1" if asset.get("source_git_blob_sha1") else None,
                    source_checksum=asset.get("source_git_blob_sha1"),
                )
                write_json_atomic(sidecar, manifest.to_dict())
                final_total, final_by_source = _raw_usage(root)
                if final_total > policy.max_raw_storage_bytes or final_by_source.get(source_id, 0) > source_quota:
                    _quarantine(target, root, source_id, "raw-storage-quota-exceeded")
                    _quarantine(sidecar, root, source_id, "raw-manifest-quota-exceeded")
                    raise PipelineError("Artifact and provenance manifest exceed raw-storage quota", code="storage_quota_exceeded")
                return AcquisitionResult(manifest, False, attempts, network_bytes)
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            if status in {301, 302, 303, 307, 308}:
                location = exc.headers.get("Location") if exc.headers else None
                if not location or redirects >= policy.max_redirects:
                    raise PipelineError("Redirect missing Location or redirect limit exceeded", code="redirect_rejected") from exc
                next_url = urllib.parse.urljoin(request_url, location)
                _validate_url(next_url, policy)
                redirects += 1
                request_url = next_url
                continue
            if status == 416 and part.exists():
                _quarantine_partial(part, part_metadata, root, source_id, "range-not-satisfiable")
                local_existing = 0
                resume_validator = None
                request_url = url
                if attempts <= policy.max_retries:
                    continue
            retryable = status in {408, 425, 429} or status >= 500
            if not retryable or attempts > policy.max_retries:
                raise PipelineError(f"HTTP request failed with status {status}", code="http_status", retryable=retryable) from exc
            delay = _retry_delay(exc.headers.get("Retry-After") if exc.headers else None, attempts, policy, random_uniform)
            sleep(delay)
        except PipelineError as exc:
            if exc.code in {"checksum_mismatch", "source_blob_checksum_mismatch", "source_blob_size_mismatch",
                            "format_validation_failed", "unexpected_html", "corrupt_archive",
                            "unsafe_archive", "empty_artifact", "range_response_mismatch",
                            "resume_validator_mismatch", "invalid_content_length",
                            "storage_quota_exceeded", "disk_reserve_exceeded"} and (part.exists() or part_metadata.exists()):
                _quarantine_partial(part, part_metadata, root, source_id, exc.code)
                raise
            if not exc.retryable or attempts > policy.max_retries:
                raise
            if exc.code == "length_mismatch":
                local_existing = part.stat().st_size if part.exists() else 0
                if local_existing and resume_validator is None:
                    _quarantine_partial(part, part_metadata, root, source_id, "short-response-without-validator")
                    local_existing = 0
            sleep(_retry_delay(None, attempts, policy, random_uniform))
        except http.client.IncompleteRead as exc:
            partial = bytes(exc.partial or b"")
            if partial:
                network_bytes += len(partial)
                current_size = (part.stat().st_size if part.exists() else 0) + len(partial)
                disk_free = shutil.disk_usage(source_dir).free
                if (network_bytes > wire_budget or current_size > max_file or current_size > artifact_size_cap or
                        disk_free - len(partial) < policy.free_disk_reserve_bytes):
                    if part.exists() or part_metadata.exists():
                        _quarantine_partial(part, part_metadata, root, source_id, "incomplete-response-quota-exceeded")
                    raise PipelineError("Incomplete response exceeded a byte, storage, or disk safety limit",
                                        code="storage_quota_exceeded") from exc
                with part.open("ab") as partial_file:
                    partial_file.write(partial)
                    partial_file.flush()
                    os.fsync(partial_file.fileno())
            local_existing = part.stat().st_size if part.exists() else 0
            if local_existing and resume_validator is None:
                _quarantine_partial(part, part_metadata, root, source_id, "no-resume-validator")
                local_existing = 0
            if attempts > policy.max_retries:
                raise PipelineError("Server closed a response before its declared length; partial bytes remain resumable",
                                    code="length_mismatch", retryable=True) from exc
            sleep(_retry_delay(None, attempts, policy, random_uniform))
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            local_existing = part.stat().st_size if part.exists() else 0
            if local_existing and resume_validator is None:
                _quarantine_partial(part, part_metadata, root, source_id, "no-resume-validator")
                local_existing = 0
            if attempts > policy.max_retries:
                raise PipelineError(f"Download failed after {attempts} attempts ({type(exc).__name__})",
                                    code="network_error", retryable=True) from exc
            sleep(_retry_delay(None, attempts, policy, random_uniform))
    raise PipelineError("Download retry budget exhausted", code="retry_budget_exhausted", retryable=True)


def _retry_delay(retry_after: str | None, attempt: int, policy: DownloadPolicy, random_uniform: Any) -> float:
    if retry_after:
        delay: float | None = None
        try:
            delay = float(retry_after)
        except ValueError:
            try:
                retry_time = email.utils.parsedate_to_datetime(retry_after)
                if retry_time.tzinfo is None:
                    retry_time = retry_time.replace(tzinfo=timezone.utc)
                delay = (retry_time - datetime.now(timezone.utc)).total_seconds()
            except (TypeError, ValueError, OverflowError):
                delay = None
        if delay is not None:
            delay = max(0.0, delay)
            if delay > 60.0:
                # Do not retry earlier than the server asked; stop instead of an unbounded sleep.
                raise PipelineError("Retry-After exceeds the bounded 60-second wait policy", code="retry_after_too_long", retryable=True)
            return delay
    base = min(30.0, policy.backoff_seconds * (2 ** max(0, attempt - 1)))
    return max(0.0, base + random_uniform(0.0, policy.jitter_seconds))


def _quarantine(path: Path, root: Path, source_id: str, reason: str) -> Path:
    quarantine = root.parent / "quarantine" / source_id
    quarantine.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        quarantine.chmod(0o700)
    except OSError:
        pass
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination = quarantine / f"{path.name}.{reason}.{timestamp}"
    if path.exists():
        os.replace(path, destination)
    return destination


def _quarantine_partial(part: Path, metadata_path: Path, root: Path, source_id: str, reason: str) -> None:
    if part.exists() or part.is_symlink():
        _quarantine(part, root, source_id, reason)
    if metadata_path.exists() or metadata_path.is_symlink():
        _quarantine(metadata_path, root, source_id, reason + "-metadata")


def acquire_fixture(
    source: dict[str, Any], asset: dict[str, Any], *, fixture_path: str | Path, raw_root: str | Path,
    max_bytes: int = 1024 * 1024,
) -> AcquisitionResult:
    """Explicitly labeled, bounded local-fixture acquisition (never real-source bytes)."""
    if source.get("source_type") != "local_fixture" or source.get("eligibility") != "APPROVED":
        raise PipelineError("Local fixture acquisition requires an explicit local_fixture source", code="fixture_source_required")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,63}", str(source.get("source_id", ""))):
        raise PipelineError("Fixture source_id is not a safe storage component", code="unsafe_source_id")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}", str(asset.get("asset_id", ""))):
        raise PipelineError("Fixture asset_id is not a safe filename component", code="unsafe_asset_id")
    path = Path(fixture_path)
    if max_bytes <= 0:
        raise PipelineError("Fixture byte quota must be positive", code="invalid_quota")
    if path.is_symlink() or not path.is_file():
        raise PipelineError(f"Fixture file is missing: {path}", code="fixture_missing")
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise PipelineError("Fixture is empty or exceeds its test-only byte quota", code="fixture_quota_exceeded")
    data_hash = sha256_file(path)
    root = Path(raw_root)
    target_dir = root / source["source_id"]
    if _path_has_symlink_component(root) or _path_has_symlink_component(target_dir):
        raise PipelineError("Fixture raw storage paths must not be symbolic links", code="unsafe_storage_path")
    target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        target_dir.chmod(0o700)
    except OSError:
        pass
    fmt = str(asset.get("format", "jsonl")).lower()
    if not re.fullmatch(r"[a-z0-9.]{1,16}", fmt):
        raise PipelineError("Fixture format is not a safe filename extension", code="unsupported_format")
    target = target_dir / f"{asset['asset_id']}.{fmt}"
    sidecar = target_dir / f"{asset['asset_id']}.manifest.json"
    if target.is_symlink() or sidecar.is_symlink():
        raise PipelineError("Fixture artifact paths must not be symbolic links", code="unsafe_storage_path")
    if target.exists() or sidecar.exists():
        if target.exists() and sidecar.exists():
            old = json.loads(sidecar.read_text(encoding="utf-8"))
            if old.get("sha256") == sha256_file(target) == data_hash and old.get("fixture_only") is True:
                return AcquisitionResult(RawArtifactManifest(**old), True, 0)
        raise PipelineError("Fixture acquisition target already exists but does not match", code="existing_artifact_conflict")
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".part", dir=target_dir)
    try:
        fixture_digest = hashlib.sha256()
        copied = 0
        with os.fdopen(fd, "wb") as out, path.open("rb") as inp:
            while True:
                chunk = inp.read(64 * 1024)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > max_bytes:
                    raise PipelineError("Fixture grew beyond its configured byte quota", code="fixture_quota_exceeded")
                out.write(chunk)
                fixture_digest.update(chunk)
            out.flush()
            os.fsync(out.fileno())
        temp = Path(temp_name)
        if copied != size or fixture_digest.hexdigest() != data_hash or sha256_file(temp) != data_hash:
            raise PipelineError("Local fixture changed while it was being copied", code="checksum_mismatch")
        _validate_content(temp, fmt, max_bytes, "application/octet-stream", asset)
        _promote_file_exclusive(temp, target)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise
    manifest = RawArtifactManifest(
        manifest_version=RAW_MANIFEST_VERSION, source_id=source["source_id"], asset_id=asset["asset_id"],
        source_url=f"fixture://{path.name}", final_url=f"fixture://{path.name}", path=str(target), byte_count=size,
        sha256=data_hash, integrity_basis="local_fixture_copy_verified_not_real_world_source",
        content_type="application/jsonl", expected_sha256=data_hash, source_revision="fixture-v1",
        etag=None, last_modified=None, acquired_at=_utc_now(), fixture_only=True,
    )
    write_json_atomic(sidecar, manifest.to_dict())
    return AcquisitionResult(manifest, False, 1)
