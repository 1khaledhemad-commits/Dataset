# Operations runbook

**Environment:** Python 3.11+, standard library only; the current test environment is POSIX/Linux. This is a local pilot, not an always-on service. Resource values are in `config/pipeline.json`; never increase them to make an unsafe source fit.

## 0. Before any collection

1. Confirm you are in the `Dataset` repository and that `config/`, `docs/`, and `tests/` are the expected project files. Generated content belongs under ignored `data/`, `logs/`, and `reports/` paths.
2. Review the exact provider's current terms, dataset/component-level license, access rules, privacy documentation, split definitions, redistribution permission, attribution, and intended purpose. A repository license or README is not sufficient evidence for linked data.
3. Add or update `config/source_registry.yaml` with a pinned source revision, exact asset, access method, current evidence and timestamp, explicit `training_use`, `evaluation_use`, `redistribution`, risk, limits, and restrictions. Set `eligibility` to `NEEDS_REVIEW` until an accountable reviewer has approved the rights and source.
4. Do not bypass robots/access restrictions, authentication, CAPTCHAs, provider terms, or rate limits. This client only supports HTTPS hosts in the configured allowlist; it has no credential store and does not circumvent access controls.
5. Keep `evaluation_only: true` and `dataset_purpose: evaluation` for held-out benchmarks. Evaluation permission is distinct from training permission. Do not silently relabel test splits as training data.
6. Check disk reserve, per-file/source/total bytes, staging/release quotas, record count, record length, run duration, memory, and pairwise dedup cap. `doctor` reports observed host resources but does not change limits.

## 1. Safe inspection and planning

```bash
python -m data_platform --help
python -m data_platform sources validate
python -m data_platform sources list
python -m data_platform sources discover --language ar
python -m data_platform plan
python -m data_platform doctor
```

`discover` ranks registered metadata only; it makes no network calls and does not establish that a candidate is available or permitted. `plan` is a dry-run and lists each registered asset as planned or blocked. Current expected state: 13 source candidates, 1 registered real asset, **0 eligible**, **1 blocked**. Do not change this count by weakening rights gates.

A dry-run of the current GSM8K asset should fail closed before creating raw-data or audit directories:

```bash
python -m data_platform run gsm8k-openai gsm8k-train-pilot --dry-run
```

It is expected to return a structured `source_not_eligible` error because the data-level license scope is unresolved. Do not attempt acquisition while that status remains.

## 2. Offline smoke test

The smoke command copies `tests/fixtures/smoke_records.jsonl` into local raw storage with an explicit `local_fixture` source. It performs no network requests and labels all resulting records and releases `fixture_only`.

```bash
python -m data_platform smoke
```

It writes intermediate data under `data/raw`, `data/staging`, and `data/quarantine`, an isolated fixture-only release under `data/releases`, a run report under `reports/runs`, and audit events under `logs`. These files are ignored by Git but may contain record text; restrict filesystem permissions and clean up only according to your retention policy. A passing smoke is not evidence that a real source is eligible or that fixture rows can train a model.

For isolation, copy `config/` and `tests/fixtures/` into a temporary project root and run `python -m data_platform --root <temporary-root> smoke`; the checked-in smoke evidence was executed this way.

## 3. Approved acquisition and curation workflow

Only after rights review changes the exact source/asset to an approved state and `sources validate` plus `plan` show it eligible:

```bash
python -m data_platform acquire <source-id> <asset-id> --dry-run
python -m data_platform acquire <source-id> <asset-id>
```

Or use the bounded end-to-end command:

```bash
python -m data_platform run <source-id> <asset-id> --dry-run
python -m data_platform run <source-id> <asset-id>
```

The non-dry-run command downloads only the registered asset, honors configured limits, validates its expected format/checksum, and does not overwrite a completed raw artifact. Preserve the resulting raw sidecar manifest. Failed/partial bytes may be moved to quarantine; do not delete or silently reuse them before inspecting the failure reason. The successful real `run` path creates curated intermediates and a **manifest-only candidate**; it does not place real record JSONL in the release directory while approval is pending.

Standalone curation commands require explicit files and refuse to overwrite existing output. Inputs are bounded by configuration. Example:

```bash
python -m data_platform extract <source-id> <asset-id> --output data/staging/extracted.jsonl
python -m data_platform normalize --input data/staging/extracted.jsonl --output data/staging/normalized.jsonl
python -m data_platform validate --input data/staging/normalized.jsonl
```

Keep extraction/mapping decisions, hashes, quality assessments, dedup decisions, split manifests, and run reports with the run. Unknown fields are retained in record attributes rather than silently discarded.

## 4. Human review and real release

A real release must not be promoted automatically. Before publication:

- Review current rights and the exact registered source/asset/revision again.
- Review the bounded sample and quality/quarantine results; document which records/IDs were sampled. Do not generalize a small manual sample to an entire corpus.
- Confirm every evaluation-only or evaluation-purpose record remains held out; inspect duplicate-cluster split assignments.
- Confirm third-party notices and attribution are complete, redistribution is allowed for the intended publication, data are not sensitive, and no prohibited/held-out benchmark content entered training.
- Record approval outside the dataset payload (for example, a ticket/review reference) and set metadata fields `human_approval_status: "approved"`, `approved_by`, and `human_approval_reference`.

Then publish the reviewed split file through the CLI:

```bash
python -m data_platform release \
  --input data/staging/runs/<run-id>/split_records.jsonl \
  --release-id <new-immutable-release-id> \
  --purpose sft \
  --metadata <review-approval.json>

python -m data_platform verify-release data/releases/<new-immutable-release-id>
```

The CLI derives source eligibility, purpose-specific use rights, license identity, revision, asset IDs, and artifact hashes from the current registry and record provenance. Caller-supplied `source_license_decisions`, `source_manifest`, config hashes, quality thresholds, or byte ceilings do not override those derived values. The final release command rechecks records, quality/safety, exact/near duplicates (capped at 2,000 rows), splits/provenance, and quotas. Evaluation data require `--purpose evaluation`; train/training assignment is rejected at release. An evaluation-only source is rejected under every training purpose.

`--manifest-only` creates no released record JSONL. It can be used for an auditable metadata-only candidate, but it does not authorize data use or distribution. Do not use `human_approval_status` as a substitute for the accountable legal/owner review. It is an unsigned operator assertion.

## 5. Resource boundaries and failure handling

Default ceilings include 20,000,000 network bytes, 6,000,000 bytes per file, 12,000,000 bytes per source, 64 MiB each for raw/staging/release storage, 32 MiB archive expansion, 10,000 records/job, 2,000 records for pairwise dedup, 1.5 GB observed process RSS, 900 seconds per processing run, one configured concurrent job, and 512 MiB free disk reserve. Acquisition uses one request at a time per host and bounds `Retry-After` waits to 60 seconds; an excessive provider delay aborts rather than retrying early.

- `source_not_eligible` / `release_license_gate`: stop. Resolve actual rights with the data owner/legal reviewer; do not edit runtime metadata to override the registry.
- `host_not_allowed`, `unsafe_url`, `redirect_rejected`: stop. Do not add a new host until it is reviewed and intentionally configured.
- `storage_quota_exceeded`, `disk_reserve_exceeded`, `expanded_size_limit`, `record_quota_exceeded`, `dedup_record_limit`, `release_verification_limit`: stop and request a separately reviewed capacity plan; do not raise caps ad hoc.
- `checksum_mismatch`, `source_blob_checksum_mismatch`, `format_validation_failed`, `unsafe_archive`: keep the failure/quarantine evidence; never promote the artifact.
- `NEEDS_HUMAN_REVIEW`, `QUARANTINE`, `REJECT`: do not release those rows. Review in a controlled environment and record the disposition.
- `audit_write_failed` or audit quota exhaustion: stop; do not continue an acquisition/run without an audit record.
- Existing raw/release/output targets are immutable/no-clobber. Choose a new pinned asset/revision or release ID after a reviewed change; do not delete an existing artifact to force a rerun.

## 6. Audit, secrets, and retention

`logs/audit.jsonl` is a local append-only event log with a default 16 MiB quota, 64 KiB event cap, restrictive file mode, and no full source URLs or record bodies. It is not remote, signed, or tamper-evident. The acquisition code does not store credentials; keep tokens out of source URLs and CLI arguments. The secret scanner is heuristic and incomplete. Restrict raw/staging/quarantine access and define backup, retention, and incident response before any real collection. No global retention period is configured by this pilot.

## 7. Current blockers

- All 13 real-world source candidates are currently non-approved or rejected; one GSM8K train-asset is registered and blocked by unresolved dataset-level rights. No acquisition has been attempted.
- Repository/code license evidence is not sufficient for external dataset files. Several listed hosts are outside the sandbox's allowed host set or have unresolved terms.
- No real Arabic-English corpus sample has been extracted, manually checked, or benchmarked. No model-training integration or deployment has been tested.
- A small fixture smoke proves plumbing and failure behavior only; see the A–L report for precise counts and actual-versus-estimated status.
