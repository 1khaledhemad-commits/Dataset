"""Transparent task-aware quality gates; no composite score hides a hard defect."""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

from .models import NormalizedRecord, QualityAssessment, ValidationResult
from .security import scan_possible_pii, scan_secrets
from .sources import eligibility_for_training

_TASK_MIN_CHARS = {
    "language_modeling": 40,
    "instruction_following": 20,
    "mathematics": 8,
    "programming": 12,
    "programming_reference": 20,
    "translation": 8,
    "qa": 12,
    "evaluation": 8,
    "structured_output": 8,
    "tool_use": 12,
    "dictionary": 2,
    "general": 20,
}


def _content_signals(record: NormalizedRecord, policy: dict[str, Any] | None = None) -> tuple[dict[str, float | None], list[str]]:
    policy = policy or {}
    defaults = policy.get("default", {})
    task_minimums = policy.get("task_minimum_characters", {})
    text = record.text
    reasons: list[str] = []
    chars = len(text)
    minimum = int(task_minimums.get(record.task_type, _TASK_MIN_CHARS.get(record.task_type, 20)))
    completeness = min(1.0, chars / max(minimum, 1))
    words = re.findall(r"\w+", text, flags=re.UNICODE)
    if not words:
        information = 0.0
        reasons.append("no_word_tokens")
    else:
        unique_ratio = len(set(word.casefold() for word in words)) / len(words)
        information = min(1.0, unique_ratio * min(1.0, len(words) / 20))
        repeated = max(Counter(word.casefold() for word in words).values()) / len(words)
        if len(words) >= 12 and repeated >= 0.40:
            reasons.append("excessive_word_repetition")
    paragraphs = [part.strip() for part in re.split(r"\n\s*\n", text) if part.strip()]
    repeated_paragraphs = len(paragraphs) - len(set(paragraph.casefold() for paragraph in paragraphs))
    if paragraphs and repeated_paragraphs:
        reasons.append("repeated_paragraphs")
    if re.search(r"(?is)<\s*(?:html|body|script|nav|div|p)\b", text) or "&nbsp;" in text.lower():
        reasons.append("html_residue")
    if re.search(r"(?i)cookie preferences|accept all cookies|javascript is disabled", text):
        reasons.append("boilerplate_candidate")
    maximum = int(defaults.get("maximum_record_characters", 1_000_000))
    if chars > maximum:
        reasons.append("extremely_long_record")
    # Formatting integrity is a deterministic heuristic; code/formula text is preserved.
    printable = sum(1 for c in text if c.isprintable() or c in "\n\t")
    formatting = printable / max(chars, 1)
    return {
        "content_completeness": round(completeness, 4),
        "information_density": round(information, 4),
        "formatting_integrity": round(formatting, 4),
    }, reasons


def assess_quality(
    record: NormalizedRecord,
    validation: ValidationResult,
    source: dict[str, Any] | None,
    *,
    purpose: str = "pretraining",
    policy: dict[str, Any] | None = None,
) -> QualityAssessment:
    policy = policy or {}
    defaults = policy.get("default", {})
    dimensions, reasons = _content_signals(record, policy)
    serialized_fields = json.dumps(record.attributes, ensure_ascii=False, sort_keys=True)
    scanned_content = record.text + "\n" + serialized_fields
    secret_findings = scan_secrets(scanned_content)
    pii_findings = scan_possible_pii(scanned_content)
    safety_flags = tuple(f.detector for f in (*secret_findings, *pii_findings))
    language_thresholds = policy.get("language_profiles", {})
    lang_min = float(language_thresholds.get(record.language, {}).get(
        "minimum_confidence", 0.45 if record.language == "unknown" else defaults.get("minimum_language_confidence", 0.60)
    ))
    language_score = record.language_confidence
    trust_map = {"high": 1.0, "medium": 0.7, "low": 0.2, "unknown": 0.0, "unverified": 0.0}
    trust_score = trust_map.get((source or {}).get("trust_level", "unknown"), 0.0)
    fixture_validation = bool(source and source.get("source_type") == "local_fixture" and purpose in {"fixture_validation", "test_only"})
    eligible, license_reason = ((True, "fixture-only validation; never a training permission") if fixture_validation else
                                eligibility_for_training(source, purpose) if source else
                                (False, "source provenance is absent"))
    dimensions.update({
        "structural_validity": 1.0 if validation.valid else 0.0,
        "language_confidence": round(language_score, 4),
        "source_trust": trust_score,
        "license_eligibility": None if fixture_validation else (1.0 if eligible else 0.0),
        "privacy_safety": 0.0 if safety_flags else 1.0,
        "duplication_risk": None,  # populated by the batch deduplication stage
        "task_suitability": round(min(dimensions["content_completeness"], dimensions["information_density"]), 4),
    })
    secret_action = defaults.get("secret_findings", "QUARANTINE")
    pii_action = defaults.get("possible_personal_identifiers", "NEEDS_HUMAN_REVIEW")
    format_min = float(defaults.get("minimum_formatting_integrity", 0.95))
    information_min = float(defaults.get("minimum_information_density", 0.20))
    if not validation.valid:
        reasons.extend(validation.errors)
        outcome = "REJECT"
    elif secret_findings:
        reasons.extend(f"secret_finding:{finding.detector}" for finding in secret_findings)
        outcome = secret_action
    elif pii_findings:
        reasons.extend(f"possible_pii_finding:{finding.detector}" for finding in pii_findings)
        outcome = pii_action
    elif not eligible:
        reasons.append(f"license_or_provenance_gate:{license_reason}")
        outcome = "NEEDS_HUMAN_REVIEW" if source else "REJECT"
    elif dimensions["formatting_integrity"] is not None and dimensions["formatting_integrity"] < format_min:
        reasons.append("formatting_integrity_below_threshold")
        outcome = "QUARANTINE"
    elif record.language == "unknown":
        reasons.append("language_label_unknown_requires_human_review")
        outcome = "NEEDS_HUMAN_REVIEW"
    elif language_score < lang_min:
        reasons.append("language_confidence_below_heuristic_threshold")
        outcome = "NEEDS_HUMAN_REVIEW"
    elif any(flag in reasons for flag in ("excessive_word_repetition", "html_residue", "extremely_long_record")):
        outcome = "QUARANTINE"
    elif dimensions["content_completeness"] < 1.0 or dimensions["information_density"] < information_min:
        outcome = "ACCEPT_WITH_WARNINGS"
        if dimensions["content_completeness"] < 1.0:
            reasons.append("short_for_task_profile")
        if dimensions["information_density"] < information_min:
            reasons.append("low_information_density_heuristic")
    elif "boilerplate_candidate" in reasons or "repeated_paragraphs" in reasons:
        outcome = "ACCEPT_WITH_WARNINGS"
    else:
        outcome = "ACCEPT"
    return QualityAssessment(record.record_id, outcome, dimensions, tuple(dict.fromkeys(reasons)), safety_flags)
