# Project log

## Current state — 2026-10-09 UTC

**Pilot implementation; not a production deployment. No real-world corpus bytes have been acquired.** All real candidates are `NEEDS_REVIEW` or `REJECTED`; the one registered GSM8K asset remains blocked because the pinned repository MIT notice does not establish dataset-level rights. No download was attempted. Fixture records and their release are clearly `fixture_only` and must not be used for training.

### Work completed in this implementation pass

- Fixed the missing `validate_jsonl_file` test import that caused the prior 38-test run to error.
- Added registry-metadata source discovery and purpose-specific `evaluation_use`, with evaluation-only registry validation and fail-closed acquisition/release checks.
- Hardened source/config validation, JSONL and extraction byte/record bounds, CLI quality and pairwise-dedup rechecks, release verification limits, path/symlink checks, immutable split naming, cross-split duplicate-cluster checks, and audit-log event/concurrency quotas.
- Made real pipeline runs produce manifest-only candidates while approval is pending. A final real release now requires `human_approval_status: approved`, `approved_by`, and `human_approval_reference`; the CLI independently derives source rights from the current registry and rechecks quality, safety, duplicates, provenance, and budgets.
- Added docs for the architecture, quality policy, operations, sampled fixture spot-check, and A–L capability/status report.

### Verification evidence

- `PYTHONPATH=src python -m compileall -q src/data_platform` — exit 0.
- `python -m unittest discover -v` — **47 tests passed, 0 failures, 0 errors, 0 skips** (4.740 seconds in the final post-documentation run).
- CLI checks: `sources validate` — valid, 13 sources; `plan` — 0 eligible, 1 blocked, 0 eligible planned bytes; `sources discover --language ar` — 9 metadata candidates and `live_network_checks_performed: false`; `doctor` — Python 3.11.2, 2 logical CPUs, no GPU detected, standard-library-only dependency policy.
- `python -m pip wheel . --no-deps --no-build-isolation --wheel-dir /tmp/dataset-wheel-check` — package wheel built successfully, 73,178 bytes, SHA-256 `503d5595d42ae598df105379ca47c06345b3d26b1a64505517d8dd4c5b237c64`; generated local `build/` scratch was removed and added to `.gitignore`.
- Offline CLI smoke, executed in a temporary project root containing only copied config and fixtures: exit 0, `fixture_only: true`, `end_to_end_valid: true`, valid fixture release, 0 network/download bytes. Input/local fixture artifact: 1,678 bytes; scanned/emitted/normalized 10 records; 9 structurally valid; outcomes: 7 `ACCEPT`, 1 `NEEDS_HUMAN_REVIEW`, 1 `QUARANTINE`, 1 `REJECT`; 1 exact and 1 near duplicate; 5 unique/usable and 5 fixture records published. Fixture benchmark: 10 labeled pairs, TP=3, FP=0, TN=6, FN=1, precision=1.0, recall=0.75. Observed elapsed time 0.034 s, 297.991 records/s, peak process RSS 24,702,976 bytes, release record files 9,557 bytes. These are one tiny fixture run, not real-corpus performance estimates.
- The fixture's deterministic hash split was 4 train and 1 validation; no test group happened to be assigned. This is expected behavior for tiny groups and must not be reported as balanced production splits.
- The recorded manual spot-check covers selected synthetic rows only; see `docs/manual_sample_review.md`.

## Prior implementation context retained

The bounded acquisition/curation package already included an immutable source registry, pinned GSM8K repository license evidence, secure HTTP acquisition with retry/range-resume and byte quotas, safe archive inspection, extraction, Arabic-preserving NFC/LF normalization, quality/safety heuristics, exact/near deduplication, deterministic split assignment, atomic releases, CLI, and unit fixtures. Earlier 36-test runs and `compileall` had passed before the additional resource/CLI tests were added. The current final 47-test run supersedes those earlier results.

## Known blockers and next work

1. Obtain explicit dataset-level written rights for any real corpus before changing registry eligibility; GSM8K data remain unavailable to this project until then.
2. For Arabic and bilingual corpora, review per-component rights, privacy documentation, split policy, access host, and current provider terms; most linked hosts were not accessible or not assessed in this environment.
3. Run a small bounded real acquisition only after approval. Then record exact hashes/counts, manually review a bounded and logged sample, test Arabic quality/dialect and privacy limitations, and create a real manifest-only candidate.
4. Obtain independent owner/legal and human quality approval before using the manual release command. The approval fields are unsigned audit metadata, not a trust/signature system.
5. Benchmark against a representative labeled duplicate set, validated Arabic/English language and task classifiers, and a larger safe corpus before raising any workload limit.
6. Design production storage, access control, retention/deletion, backup, external/tamper-evident auditing, worker isolation, monitoring, concurrency control, and deployment integration. None is established by this local pilot.

See `docs/implementation_report.md` for the requested A–L capability and status breakdown.
