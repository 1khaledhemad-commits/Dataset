"""Streaming JSONL and atomic, overwrite-resistant filesystem helpers."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterable, Iterator

from .errors import PipelineError


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_jsonl(path: str | Path, *, max_records: int | None = None,
               max_bytes: int | None = None) -> Iterator[dict[str, Any]]:
    path = Path(path)
    if max_records is not None and max_records <= 0:
        raise PipelineError("JSONL record limit must be positive", code="invalid_resource_policy")
    if max_bytes is not None and max_bytes <= 0:
        raise PipelineError("JSONL byte limit must be positive", code="invalid_resource_policy")
    try:
        if max_bytes is not None and path.stat().st_size > max_bytes:
            raise PipelineError(f"JSONL exceeds the configured input-byte limit: {path}", code="input_byte_limit")
        total_bytes = 0
        record_count = 0
        line_number = 0
        with path.open("rb") as handle:
            while True:
                read_limit = max_bytes - total_bytes + 1 if max_bytes is not None else -1
                raw_line = handle.readline(read_limit)
                if not raw_line:
                    break
                line_number += 1
                total_bytes += len(raw_line)
                if max_bytes is not None and total_bytes > max_bytes:
                    raise PipelineError(f"JSONL exceeds the configured input-byte limit: {path}", code="input_byte_limit")
                if not raw_line.strip():
                    continue
                record_count += 1
                if max_records is not None and record_count > max_records:
                    raise PipelineError(f"JSONL exceeds the configured record limit: {path}", code="record_quota_exceeded")
                try:
                    line = raw_line.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise PipelineError(f"Invalid UTF-8 in JSONL at {path}:{line_number}", code="invalid_encoding") from exc
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise PipelineError(f"Malformed JSONL at {path}:{line_number}", code="malformed_jsonl") from exc
                if not isinstance(value, dict):
                    raise PipelineError(f"JSONL row must be an object at {path}:{line_number}", code="invalid_jsonl_record")
                yield value
    except FileNotFoundError as exc:
        raise PipelineError(f"JSONL file not found: {path}", code="input_missing") from exc
    except UnicodeDecodeError as exc:
        raise PipelineError(f"Invalid UTF-8 in JSONL: {path}", code="invalid_encoding") from exc


def _promote(temp_path: str, target: Path, *, overwrite: bool) -> None:
    if overwrite:
        os.replace(temp_path, target)
    else:
        try:
            os.link(temp_path, target)  # atomic no-clobber publication on the same filesystem
        except FileExistsError as exc:
            raise PipelineError(f"Refusing to overwrite existing output: {target}", code="output_exists") from exc
        os.unlink(temp_path)
    try:
        directory_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        # File content was fsynced before promotion; directory fsync is best-effort by filesystem.
        pass


def write_jsonl_atomic(path: str | Path, rows: Iterable[dict[str, Any]], *, overwrite: bool = False) -> tuple[int, int, str]:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise PipelineError(f"Refusing to overwrite existing output: {path}", code="output_exists")
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".part", dir=path.parent)
    count = 0
    byte_count = 0
    digest = hashlib.sha256()
    try:
        with os.fdopen(fd, "wb") as handle:
            for row in rows:
                encoded = (json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
                handle.write(encoded)
                digest.update(encoded)
                byte_count += len(encoded)
                count += 1
            handle.flush()
            os.fsync(handle.fileno())
        _promote(tmp_name, path, overwrite=overwrite)
        return count, byte_count, digest.hexdigest()
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def write_json_atomic(path: str | Path, value: dict[str, Any], *, overwrite: bool = False) -> str:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise PipelineError(f"Refusing to overwrite existing output: {path}", code="output_exists")
    encoded = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".part", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        _promote(tmp_name, path, overwrite=overwrite)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise
    return hashlib.sha256(encoded).hexdigest()


def write_text_atomic(path: str | Path, text: str, *, overwrite: bool = False) -> str:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise PipelineError(f"Refusing to overwrite existing output: {path}", code="output_exists")
    encoded = text.encode("utf-8")
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".part", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        _promote(tmp_name, path, overwrite=overwrite)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise
    return hashlib.sha256(encoded).hexdigest()
