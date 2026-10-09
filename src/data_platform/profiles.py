"""Task-aware Arabic, English and parallel-text diagnostics.

Arabic variety and translation alignment are never asserted by these simple
checks; the profile intentionally reports uncertainty instead of rewriting text.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

_ARABIC_PUNCTUATION = set("،؛؟؞٪٫٬")
_DIALECT_MARKER_CANDIDATES = {
    # Indicators for human review only; lists are incomplete and not classifiers.
    "egyptian_candidate": {"إيه", "ايه", "عايز", "عايزة", "مش", "دلوقتي", "ازاي", "ليه"},
    "levantine_candidate": {"شو", "هيك", "بدي", "كتير", "هلأ", "هلق"},
    "gulf_candidate": {"وش", "شلون", "أبي", "ابي", "الحين"},
    "maghrebi_candidate": {"بزاف", "واش", "بغيت", "دابا"},
}


def language_profile(text: str, language: str) -> dict[str, Any]:
    arabic_letters = latin_letters = other_letters = 0
    arabic_diacritics = arabic_punctuation = presentation_forms = 0
    for char in text:
        code = ord(char)
        name = unicodedata.name(char, "")
        category = unicodedata.category(char)
        if category.startswith("L"):
            if "ARABIC" in name:
                arabic_letters += 1
            elif "LATIN" in name:
                latin_letters += 1
            else:
                other_letters += 1
        if "ARABIC" in name and category in {"Mn", "Me"}:
            arabic_diacritics += 1
        if char in _ARABIC_PUNCTUATION:
            arabic_punctuation += 1
        if 0xFB50 <= code <= 0xFDFF or 0xFE70 <= code <= 0xFEFF:
            presentation_forms += 1
    total = arabic_letters + latin_letters + other_letters
    profile: dict[str, Any] = {
        "profile_version": "1.0.0",
        "label": language,
        "arabic_letter_count": arabic_letters,
        "latin_letter_count": latin_letters,
        "other_letter_count": other_letters,
        "arabic_diacritic_count": arabic_diacritics,
        "arabic_punctuation_count": arabic_punctuation,
        "arabic_presentation_form_count": presentation_forms,
        "arabic_script_fraction": arabic_letters / total if total else 0.0,
        "latin_script_fraction": latin_letters / total if total else 0.0,
        "code_switch_present": arabic_letters > 0 and latin_letters > 0,
        "arabic_variety": "not_automatically_classified",
        "dialect_marker_candidates": [],
        "transliteration_candidate": False,
        "limitations": ["Unicode script proportions are not language identification; dialect and MSA require a validated classifier or review."],
    }
    if language in {"ar", "mixed"} or arabic_letters:
        words = {word.casefold() for word in re.findall(r"[\w\u0600-\u06ff]+", text, re.UNICODE)}
        profile["dialect_marker_candidates"] = sorted(
            tag for tag, markers in _DIALECT_MARKER_CANDIDATES.items() if words & markers
        )
        latin_words = re.findall(r"[A-Za-z0-9]+", text)
        profile["transliteration_candidate"] = any(
            re.search(r"(?:sh|kh|gh|th|dh|[23][a-z])", word, re.IGNORECASE) for word in latin_words
        )
    if language == "en":
        profile["sentence_terminal_marks"] = len(re.findall(r"[.!?](?:['\"])?(?:\s|$)", text))
        profile["code_or_formula_markers"] = sum(text.count(mark) for mark in ("```", "def ", "class ", "=", "->", "$", "\\frac"))
        profile["english_variety"] = "not_assessed"
    return profile


def validate_parallel_pair(attributes: dict[str, Any]) -> dict[str, Any]:
    """Validate declared aligned fields without claiming translation quality."""
    source = attributes.get("source_text")
    target = attributes.get("target_text")
    source_language = attributes.get("source_language")
    target_language = attributes.get("target_language")
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(source, str) or not source.strip():
        errors.append("source_text_missing")
    if not isinstance(target, str) or not target.strip():
        errors.append("target_text_missing")
    if source_language not in {"ar", "en"} or target_language not in {"ar", "en"}:
        errors.append("pair_language_labels_missing_or_unsupported")
    if source_language == target_language and source_language in {"ar", "en"}:
        warnings.append("source_and_target_language_labels_match")
    if isinstance(source, str) and isinstance(target, str):
        if source.strip().casefold() == target.strip().casefold():
            warnings.append("suspiciously_identical_translation_pair")
        ratio = len(source) / max(len(target), 1)
        if ratio > 8 or ratio < 0.125:
            warnings.append("extreme_length_ratio_heuristic")
    return {"valid_structure": not errors, "errors": errors, "warnings": warnings,
            "translation_alignment_quality": "not_assessed_without_reference_or_human_review"}
