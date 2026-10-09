"""Source-governance checks; unknown rights fail closed."""

from __future__ import annotations

from typing import Any

from .errors import PipelineError


def is_acquisition_eligible(source: dict[str, Any], purpose: str = "pretraining") -> tuple[bool, str]:
    status = source.get("eligibility")
    if not isinstance(status, str) or status not in {"APPROVED", "APPROVED_WITH_RESTRICTIONS"}:
        return False, f"eligibility status is {status or 'missing'}"
    if purpose not in {"pretraining", "sft", "preference", "evaluation", "expert"}:
        raise PipelineError(f"Unknown dataset purpose: {purpose}", code="invalid_purpose")
    license_info = source.get("license") or {}
    if not isinstance(license_info, dict):
        return False, "license metadata is invalid"
    if purpose == "evaluation":
        evaluation_use = license_info.get("evaluation_use", "unknown")
        if evaluation_use not in {"permitted", "permitted_with_attribution"}:
            return False, "evaluation-use permission is not verified"
    else:
        training_use = license_info.get("training_use", "unknown")
        if training_use not in {"permitted", "permitted_with_attribution"}:
            return False, "training-use permission is not verified"
    if source.get("personal_data_risk") in {"high", "unassessed"}:
        return False, "personal-data risk is high or unassessed"
    if not source.get("trust_justification") or source.get("trust_level") in {"unknown", "unverified", "low"}:
        return False, "source trust has not been justified"
    return True, "eligible under the recorded purpose-specific rights decision; obey restrictions and attribution"

def require_acquisition_eligible(source: dict[str, Any]) -> None:
    eligible, reason = is_acquisition_eligible(source)
    if not eligible:
        raise PipelineError(f"Source {source.get('source_id', '<unknown>')} is not eligible: {reason}",
                            code="source_not_eligible")


def eligibility_for_training(source: dict[str, Any], purpose: str) -> tuple[bool, str]:
    """Evaluate recorded rights for one purpose; evaluation does not imply training permission."""
    if purpose not in {"pretraining", "sft", "preference", "evaluation", "expert"}:
        raise PipelineError(f"Unknown dataset purpose: {purpose}", code="invalid_purpose")
    if source.get("evaluation_only") and purpose != "evaluation":
        return False, "benchmark/held-out source is evaluation-only"
    ok, reason = is_acquisition_eligible(source, purpose)
    if not ok:
        return False, reason
    restrictions = source.get("restrictions", [])
    if source.get("eligibility") == "APPROVED_WITH_RESTRICTIONS" and (not isinstance(restrictions, list) or not restrictions):
        return False, "restricted approval has no documented restrictions"
    if purpose == "evaluation" and source.get("evaluation_only"):
        return True, "evaluation-only source is authorized only for evaluation"
    return True, "source decision permits this purpose subject to the recorded restrictions"
