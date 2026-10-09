# A–L implementation and verification report

**As of:** 2026-10-09 UTC
**Overall capability status:** **PARTIAL — executable local pilot, not a production deployment.**
**Real-world corpus bytes acquired:** **0.** The only end-to-end execution used versioned synthetic fixtures and is labeled `fixture_only`. Fixture counts are not corpus counts. No rights, safety, quality, or performance claim is made for an uninspected real corpus.

Status labels describe tested capability, not permission to collect or train: **IMPLEMENTED** means code exists and its stated scope was exercised; **PARTIAL** means limited to registry metadata, heuristics, fixtures, or an untested path; **BLOCKED** means a fail-closed gate prevents current use; **NOT IMPLEMENTED** means no supported capability is provided.

## A. System scope and deployment state — PARTIAL

An executable, standard-library Python 3.11+ package exists in `src/data_platform/`, with versioned JSON/YAML-subset configuration, unit tests, offline smoke flow, reports, and operator documentation. It has not been deployed as a service, connected to a model-training job, run on a real corpus, or tested under production concurrency/retention/security controls.

## B. Governed source discovery — PARTIAL

`config/source_registry.yaml` records **13** candidates, source and asset metadata, purpose-specific rights, risk/trust notes, provenance evidence, and eligibility decisions. Registry validation passed. `sources discover --language ar` returned **9** Arabic-tagged metadata candidates with `live_network_checks_performed: false`; it ranks the local registry only, not live websites. `plan` reported **0 eligible assets, 1 blocked asset, 0 eligible planned bytes**. It does not estimate usable corpus yield.

## C. Rights and bounded acquisition — BLOCKED for real sources; IMPLEMENTED fail-closed controls

The only registered real asset is a proposed GSM8K training-split pilot. It remains `NEEDS_REVIEW`; both training and evaluation use are `unknown`. The pinned GitHub repository `LICENSE` was saved at `docs/licenses/gsm8k-MIT.txt`; its Git blob SHA-1 was matched to repository metadata. This is evidence about the repository notice, **not** a finding that the corpus is covered or may be trained on/redistributed. A unit/integration test confirms the CLI dry-run fails before raw or audit directories are created. No network acquisition was attempted.

The downloader implements host allowlisting, redirect validation, TLS-only production URLs, retry/range-resume controls, request pacing, total/per-source/file/disk limits, payload format checks, raw immutability, checksum verification, quarantine, and audit events. Real acquisition behavior against a licensed source remains unexecuted. Access-control, robots, terms, CAPTCHA, authentication, and rate-limit circumvention are not supported or allowed.

## D. Extraction and record provenance — IMPLEMENTED on bounded fixtures/tests; PARTIAL on real data

JSON/JSONL/NDJSON, CSV/TSV, UTF-8 text/HTML, gzip, and safe archive text-member paths are implemented with byte/record/expansion limits. Extraction records source ID/record ID, revision, license ID, asset ID, artifact SHA-256, and relevant source fields. The GSM8K registry entry pins an API blob object and deterministic sampling limits, but the corpus object was not fetched. Format coverage is unit-tested; no external data format has been validated against a real acquisition.

## E. Normalization and Arabic/English preservation — IMPLEMENTED as a deterministic transform; language recognition PARTIAL

Normalization applies Unicode NFC and LF line endings and preserves diacritics, punctuation, Arabic letter variants, case, whitespace, and indentation. Unit tests cover Arabic combining marks and code formatting; HTML preformatted layout is also tested. Unicode-script proportions classify language heuristically; Arabic MSA/dialect, English variety, transliteration, translation alignment, factuality, and fluency are **not** validated or automatically asserted. No real Arabic/English sample has been assessed.

## F. Structural, quality, privacy, and safety gates — IMPLEMENTED as pilot heuristics; corpus validation NOT DONE

Record validation checks schema/normalization version, required fields, SHA-256, NFC/LF, timestamp/timezone, language/confidence/script composition, and JSON metadata. Quality gates use configurable task lengths, language-confidence profiles, formatting and information-density heuristics, secret-pattern scans, possible email/US-SSN scans, and explicit `ACCEPT`, `ACCEPT_WITH_WARNINGS`, `REJECT`, `QUARANTINE`, and `NEEDS_HUMAN_REVIEW` outcomes. CLI release rechecks schema, quality, and safety; pending review cannot be promoted by metadata. Scanners are incomplete and heuristic; no false-negative study, privacy review of real records, factual review, or full human review has been performed.

## G. Deduplication and measurement — PARTIAL

Exact SHA-256 operates on normalized content. Near-dedup uses word-shingle Jaccard (5-word shingles, threshold 0.75), matching task/language only and skipping programming tasks. It is O(n²), capped at 2,000 records, and is **not semantic deduplication**. On the **10 synthetic labeled fixture pairs**, measured TP=3, FP=0, TN=6, FN=1, precision=1.0, recall=0.75. This small fixture benchmark is not representative or a corpus-level accuracy claim. The final smoke found 1 exact and 1 near duplicate among fixture records.

## H. Leakage-aware splits — IMPLEMENTED for supplied exact/near clusters; production balance PARTIAL

Splits are deterministic by configured seed and protected record/duplicate cluster; duplicate clusters cannot span splits. Evaluation-purpose records cannot use train/training assignment, evaluation-only sources cannot be acquired for training, and release checks the policy again. A synthetic unit test covers evaluation-only permission independent of training permission. The smoke fixture split was train=4, validation=1, test=0; deterministic hash assignment on five groups is not proportion balancing. Unobserved paraphrases or missing/forged upstream duplicate clusters can still leak; final CLI release performs a bounded duplicate recheck.

## I. Reproducible release and human promotion gate — PARTIAL; no real final release

Atomic immutable releases include source/license decisions, record/file hashes, notices, counts, transformations, quality thresholds, split policy, completion marker, and manifest hash; verification rechecks identity, files, record hashes/schema, purpose rights, evaluation separation, provenance, and configured size/record limits. Real `run` output is **manifest-only** while review is pending. Publishing real data requires an explicit `approved` status, approver, and approval reference, and the CLI re-derives source decisions from the registry. A passing fixture smoke produced a valid **fixture-only** release with 5 fixture records; no real release was created.

Approval metadata is an unsigned operator assertion, not a digital signature. A manifest hash stored beside a release does not prove its origin or make it tamper-evident. Filesystem access controls and legal/owner review remain external responsibilities.

## J. CLI, audit, resource limits, and operator docs — IMPLEMENTED as local controls; production operations PARTIAL

Commands include `doctor`, `sources validate/list/discover`, `plan`, `acquire`, `run`, `extract`, `normalize`, `validate`, `classify`, `evaluate`, `deduplicate`, `split`, `release`, `verify-release`, `report`, and `smoke`. Configured defaults include 20 MB total download, 6 MB single file, 12 MB per source, 64 MiB raw/staging/release storage, 32 MiB archive expansion, 10,000 records/job, 2,000 pairwise-dedup records, 1.5 GB observed RSS, 900 seconds/run, one configured concurrent job, and 512 MiB free-space reserve. JSONL readers, CLI input paths, release verification, metadata, output names, and audit appends have bounded checks.

The local append-only audit log has a 16 MiB default quota and 64 KiB event cap; it omits full URLs and record text. It is neither signed nor remote. Cross-process host-level job concurrency, managed retention, signed approvals, production identity/access control, monitoring/alerting, and external audit storage are not implemented.

## K. Test, CLI, and fixture execution evidence — PASS within the stated scope

Final recorded commands:

- `PYTHONPATH=src python -m compileall -q src/data_platform` — exit 0.
- `python -m unittest discover -v` — **47 passed, 0 failed, 0 errors, 0 skipped**, 4.740 s.
- `python -m pip wheel . --no-deps --no-build-isolation` — wheel build passed (73,178 bytes; SHA-256 `503d5595d42ae598df105379ca47c06345b3d26b1a64505517d8dd4c5b237c64`); generated build scratch was removed.
- CLI `sources validate` — valid, registry version 1.0.0, 13 sources.
- CLI `plan` — 0 eligible assets; 1 blocked; 0 planned eligible bytes.
- CLI Arabic discovery — 9 candidates; no live network checks.
- CLI doctor — Python 3.11.2, 2 logical CPUs, no GPU detected, standard-library-only dependency policy.
- Offline smoke in a temporary root — exit 0; `fixture_only: true`; `end_to_end_valid: true`; release verification valid; 0 download attempts/network bytes; local fixture copy 1,678 bytes; 10 scanned/extracted/normalized; 9 structurally valid; quality outcomes 7 accept, 1 human review, 1 quarantine, 1 reject; 1 exact and 1 near duplicate; 5 usable/published fixture rows; 9,557 bytes of release record files; 0.034 s elapsed; 297.991 fixture records/s; peak process RSS 24,702,976 bytes.

The observed smoke throughput and memory are measurements of one tiny local fixture run only. They are not benchmark estimates for larger data or production hardware. No real data bytes were downloaded.

## L. Blockers and non-implemented scope — BLOCKED / NOT IMPLEMENTED

- Dataset-level permission for GSM8K remains unknown; do not acquire it. Other Arabic, bilingual, web, benchmark, and code candidates also have unresolved rights/access/split/privacy questions or are rejected for the intended use. Current `plan` remains zero eligible.
- No real corpus payload, release, Arabic-English quality benchmark, source-size estimate validated by download, representative duplicate benchmark, or full/manual corpus review exists.
- No validated semantic dedup, production language/dialect/translation classifier, factuality/reference correctness check, automatic worker sandbox, acquisition from arbitrary external hosts, credential integration, or large-scale indexed dedup backend is implemented.
- No deployment, model training/evaluation integration, production retention/deletion process, formal signed approval, remote tamper-evident audit, production SLO, or security certification exists.

**Decision:** retain fail-closed statuses. The next permitted step is rights/access/privacy review and representative bounded fixture/real-data design—not a larger download or relaxed threshold.
