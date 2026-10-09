# AI-FOUNDATION Arabic–English Data Platform (pilot)

A dependency-free Python 3.11+ pilot for governed source registration, bounded acquisition, provenance-preserving text curation, validation, quality/safety gates, deduplication, leakage-aware splitting, and reproducible releases.

**Current state: implementation pilot only. No real-world corpus bytes have been acquired.** The only end-to-end execution is explicitly labeled synthetic fixture data. All registered real-world assets are blocked or need rights review; the current acquisition plan has zero eligible assets. GSM8K repository MIT text is retained as provenance evidence, not treated as dataset-level permission.

## Quick checks

```bash
python -m pip install -e .
data-platform sources validate
data-platform sources discover --language ar
data-platform plan
data-platform doctor
python -m unittest discover -v
```

The `discover` command ranks the local source registry only; it performs **no live source or rights checks**. `plan` does not download. Do not run a real `acquire`/`run` command unless a source is explicitly approved in `config/source_registry.yaml` for the requested purpose and its current provider terms, host, limits, privacy, and rights are reviewed.

Offline end-to-end fixture validation (writes only to the selected project root's ignored `data/`, `logs/`, and `reports/` directories):

```bash
data-platform smoke
```

Fixture output is marked `fixture_only` and must never be used as model training data. For a production-like workflow, use an isolated project copy and review `docs/operations_runbook.md` first.

## Canonical project files

- `config/source_registry.yaml` — governed sources, assets, purpose-specific rights, evidence, and explicit eligibility status. It is JSON syntax, a safe YAML 1.2 subset.
- `config/pipeline.json` — resource ceilings, normalization policy, quality profiles, deduplication settings, and split policy.
- `docs/data_architecture.md` — components, flow, record/provenance contract, and enforcement boundaries.
- `docs/dataset_quality_policy.md` — quality, safety, language, Arabic preservation, and deduplication policy.
- `docs/operations_runbook.md` — operator steps, release approval gate, failure handling, and storage practices.
- `docs/project_log.md` — dated execution log and current blockers.
- `docs/manual_sample_review.md` — the recorded, fixture-only spot-check; it is not a corpus review.
- `docs/implementation_report.md` — requested A–L capability/status report with observed results and limitations.

## Important release behavior

The real-data `run` path can acquire and curate only a source already approved by the registry. It writes a **manifest-only candidate** while owner/operator review is pending; it does not publish data records. A real data release requires a separate explicit approval record (`human_approval_status: "approved"`, `approved_by`, and `human_approval_reference`), and the release CLI rechecks current registry rights, source/asset/artifact provenance, record schema, quality/safety, duplicates, split assignments, and configured budgets. Caller-provided license decisions cannot override the registry.

That approval metadata is an operator audit record, not a digital signature or a substitute for legal review. Release manifest hashes provide integrity checks, not cryptographic authenticity.

## Scope and cautions

- Unknown, unverified, restricted, or out-of-scope rights fail closed. Repository/code licenses do not automatically establish rights in linked dataset content.
- Evaluation permissions are separate from training permissions. Evaluation-only sources may be acquired only for purpose `evaluation`; they are blocked from train-capable splits and rechecked at release.
- Arabic NFC/LF normalization preserves diacritics, punctuation, letter variants, and meaningful whitespace. Language, privacy, quality, and near-duplicate checks are heuristics—not semantic or legal determinations.
- Review the runbook before collecting. Do not bypass robots/access restrictions, terms, authentication, CAPTCHAs, or rate limits.
