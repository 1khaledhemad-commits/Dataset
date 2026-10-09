"""Named training-purpose profiles kept separate by objective."""

from __future__ import annotations

DATASET_PROFILES: dict[str, dict[str, object]] = {
    "general_language_modeling": {"purpose": "pretraining", "domains": ["general", "language"], "task_types": ["language_modeling"]},
    "arabic_language": {"purpose": "pretraining", "languages": ["ar"], "task_types": ["language_modeling"]},
    "english_language": {"purpose": "pretraining", "languages": ["en"], "task_types": ["language_modeling"]},
    "cross_lingual": {"purpose": "pretraining", "languages": ["mixed"], "task_types": ["translation", "language_modeling"]},
    "instruction_following": {"purpose": "sft", "task_types": ["instruction_following"]},
    "reasoning": {"purpose": "sft", "domains": ["reasoning"], "task_types": ["qa", "mathematics"]},
    "mathematics": {"purpose": "sft", "domains": ["mathematics"], "task_types": ["mathematics"]},
    "programming": {"purpose": "sft", "domains": ["programming"], "task_types": ["programming", "programming_reference"]},
    "structured_outputs": {"purpose": "sft", "task_types": ["structured_output"]},
    "tool_use": {"purpose": "sft", "task_types": ["tool_use"]},
    "expert_package": {"purpose": "expert", "task_types": ["expert"]},
    "evaluation_only": {"purpose": "evaluation", "task_types": ["evaluation"]},
}


def filter_profile(records: list[dict[str, object]], profile_name: str) -> list[dict[str, object]]:
    if profile_name not in DATASET_PROFILES:
        raise ValueError(f"Unknown dataset profile: {profile_name}")
    profile = DATASET_PROFILES[profile_name]
    return [row for row in records
            if (not profile.get("languages") or row.get("language") in profile["languages"])
            and (not profile.get("domains") or row.get("domain") in profile["domains"])
            and (not profile.get("task_types") or row.get("task_type") in profile["task_types"])]
