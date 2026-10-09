"""Conservative safety scans that return detector names, never matched values."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SafetyFinding:
    detector: str
    severity: str

    def to_dict(self) -> dict[str, str]:
        return {"detector": self.detector, "severity": self.severity}


_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("openai_style_key", re.compile(r"\bsk-[A-Za-z0-9_-]{24,}\b")),
    ("credential_assignment", re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[^\s'\"]{6,}")),
    ("credential_url", re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@")),
)


_PII_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("possible_email_address", re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")),
    ("possible_us_ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
)


def scan_secrets(text: str) -> tuple[SafetyFinding, ...]:
    """Detect common credential patterns; false negatives remain possible."""
    return tuple(SafetyFinding(name, "high") for name, pattern in _SECRET_PATTERNS if pattern.search(text))


def scan_possible_pii(text: str) -> tuple[SafetyFinding, ...]:
    """Flag email/SSN-shaped strings for review; findings contain names only."""
    return tuple(SafetyFinding(name, "medium") for name, pattern in _PII_PATTERNS if pattern.search(text))


def scan_suspicious_archive_name(name: str) -> tuple[str, ...]:
    """Flag paths unsafe to extract; callers never write archive paths directly."""
    normalized = name.replace("\\", "/")
    parts = normalized.split("/")
    flags: list[str] = []
    if normalized.startswith("/") or any(part == ".." for part in parts):
        flags.append("archive_path_traversal")
    if len(parts) > 20:
        flags.append("archive_path_depth_exceeded")
    if normalized.lower().endswith((".exe", ".dll", ".so", ".dylib", ".bat", ".cmd", ".ps1")):
        flags.append("unexpected_executable_content")
    return tuple(flags)
