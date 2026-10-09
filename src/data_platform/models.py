"""Versioned data contracts shared by pipeline stages."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

RECORD_SCHEMA_VERSION = "1.0.0"
RAW_MANIFEST_VERSION = "1.0.0"


@dataclass(frozen=True)
class ExtractedRecord:
    source_id: str
    source_record_id: str
    text: str
    source_url: str = ""
    source_revision: str = ""
    license_id: str = ""
    domain: str = "general"
    task_type: str = "language_modeling"
    attributes: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedRecord:
    record_id: str
    text: str
    language: str
    domain: str
    task_type: str
    source_id: str
    source_record_id: str
    source_url: str
    source_revision: str
    license_id: str
    content_hash: str
    ingestion_timestamp: str
    normalization_version: str = "1.0.0"
    schema_version: str = RECORD_SCHEMA_VERSION
    language_confidence: float = 0.0
    script_composition: dict[str, float] = field(default_factory=dict)
    language_profile: dict[str, Any] = field(default_factory=dict)
    quality_flags: list[str] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)
    attributes: dict[str, Any] = field(default_factory=dict)
    split_assignment: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "NormalizedRecord":
        """Load a record without silently dropping unknown semantic fields."""
        core = {
            "record_id", "text", "language", "domain", "task_type", "source_id",
            "source_record_id", "source_url", "source_revision", "license_id",
            "content_hash", "ingestion_timestamp",
        }
        missing = sorted(core - value.keys())
        if missing:
            raise ValueError(f"Missing normalized-record fields: {', '.join(missing)}")
        known = {f.name for f in cls.__dataclass_fields__.values()}
        extras = {k: v for k, v in value.items() if k not in known}
        attributes = dict(value.get("attributes") or {})
        if extras:
            attributes.setdefault("unmapped_source_fields", {}).update(extras)
        allowed = {k: v for k, v in value.items() if k in known}
        allowed["attributes"] = attributes
        return cls(**allowed)


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "errors": list(self.errors), "warnings": list(self.warnings)}


@dataclass(frozen=True)
class QualityAssessment:
    record_id: str
    outcome: str
    dimensions: dict[str, float | None]
    reasons: tuple[str, ...] = ()
    safety_flags: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "outcome": self.outcome,
            "dimensions": self.dimensions,
            "reasons": list(self.reasons),
            "safety_flags": list(self.safety_flags),
        }


@dataclass(frozen=True)
class RawArtifactManifest:
    manifest_version: str
    source_id: str
    asset_id: str
    source_url: str
    final_url: str
    path: str
    byte_count: int
    sha256: str
    integrity_basis: str
    content_type: str
    expected_sha256: str | None
    source_revision: str | None
    etag: str | None
    last_modified: str | None
    acquired_at: str
    fixture_only: bool = False
    source_checksum_algorithm: str | None = None
    source_checksum: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
