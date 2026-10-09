"""Reversible-by-policy Unicode normalization and script heuristics."""

from __future__ import annotations

import hashlib
import unicodedata
from datetime import datetime, timezone
from typing import Any

from .models import ExtractedRecord, NormalizedRecord
from .profiles import language_profile

NORMALIZATION_VERSION = "1.0.0"


def classify_language(text: str, *, min_letters: int = 8) -> tuple[str, float, dict[str, float]]:
    """Classify from Unicode letter-script proportions; this is a heuristic, not NLP."""
    counts = {"arabic": 0, "latin": 0, "other": 0}
    for char in text:
        if not unicodedata.category(char).startswith("L"):
            continue
        name = unicodedata.name(char, "")
        if "ARABIC" in name:
            counts["arabic"] += 1
        elif "LATIN" in name:
            counts["latin"] += 1
        else:
            counts["other"] += 1
    total = sum(counts.values())
    composition = {key: (value / total if total else 0.0) for key, value in counts.items()}
    if total < min_letters:
        return "unknown", 0.0 if total == 0 else min(0.49, total / min_letters * 0.49), composition
    ar, en, other = (composition[k] for k in ("arabic", "latin", "other"))
    if ar >= 0.15 and en >= 0.15:
        return "mixed", round(min(1.0, 0.5 + min(ar, en)), 4), composition
    if ar >= 0.55:
        return "ar", round(ar, 4), composition
    if en >= 0.70 and other < 0.25:
        return "en", round(en, 4), composition
    if other >= 0.50:
        return "other", round(other, 4), composition
    dominant = max(composition.values(), default=0.0)
    return "unknown", round(min(0.49, dominant), 4), composition


def normalize_text(text: str) -> tuple[str, list[str]]:
    """Apply NFC and line-ending cleanup; preserve Arabic distinctions and code."""
    flags: list[str] = []
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if any(0xD800 <= ord(char) <= 0xDFFF for char in text):
        text = text.encode("utf-8", errors="replace").decode("utf-8")
        flags.append("invalid_surrogate_replaced")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = unicodedata.normalize("NFC", text)
    if "\x00" in text:
        text = text.replace("\x00", "")
        flags.append("nul_character_removed")
    # Preserve every text/formatting distinction except documented line-ending and NFC cleanup.
    normalized = text
    if not normalized.strip():
        flags.append("empty_after_normalization")
    if normalized != text.strip():
        # Keep whitespace unchanged; this flag indicates only boundary whitespace is present.
        flags.append("boundary_whitespace_preserved")
    return normalized, flags


def normalize_record(
    extracted: ExtractedRecord,
    *,
    ingestion_timestamp: str | None = None,
) -> NormalizedRecord:
    text, flags = normalize_text(extracted.text)
    language, confidence, composition = classify_language(text)
    content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    timestamp = ingestion_timestamp or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    stable_seed = "\0".join((extracted.source_id, extracted.source_record_id, content_hash, NORMALIZATION_VERSION))
    record_id = hashlib.sha256(stable_seed.encode("utf-8")).hexdigest()
    if language == "unknown":
        flags.append("language_uncertain_script_heuristic")
    provenance: dict[str, Any] = dict(extracted.provenance)
    provenance.setdefault("normalization_policy", "Unicode NFC; CRLF/CR to LF; preserve whitespace, punctuation, Arabic letters, and diacritics")
    return NormalizedRecord(
        record_id=record_id,
        text=text,
        language=language,
        domain=extracted.domain,
        task_type=extracted.task_type,
        source_id=extracted.source_id,
        source_record_id=extracted.source_record_id,
        source_url=extracted.source_url,
        source_revision=extracted.source_revision,
        license_id=extracted.license_id,
        content_hash=content_hash,
        ingestion_timestamp=timestamp,
        normalization_version=NORMALIZATION_VERSION,
        language_confidence=confidence,
        script_composition=composition,
        language_profile=language_profile(text, language),
        quality_flags=flags,
        provenance=provenance,
        attributes=dict(extracted.attributes),
    )
