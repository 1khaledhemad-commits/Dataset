# Dataset quality and safety policy

**Policy status:** pilot, encoded in `config/pipeline.json` and `src/data_platform/quality.py`. These are deterministic gates and review signals, not legal review, factual QA, a validated Arabic NLP evaluation, or a claim that any real source is approved.

## 1. Non-negotiable source and purpose gates

- Unknown or unclear rights fail closed. `training_use` and `evaluation_use` are separate registry fields; repository licenses are not presumed to cover external corpora.
- An `evaluation_only` source is authorized only for `dataset_purpose: evaluation`. It cannot be acquired for training, included in a train-capable split, or released under a training purpose. Evaluation-purpose data cannot be assigned to `train`/`training`, even if the source is not marked evaluation-only.
- Release re-derives source decisions from the current registry. Caller-provided license statuses cannot override it.
- Real data are not automatically promoted from acquisition to training. The real pipeline writes a manifest-only candidate. A published release additionally requires an explicit approval status, approver, and approval reference; this is an audit field, not a cryptographic signature.

## 2. Text and schema invariants

- Normalization is Unicode NFC and CRLF/CR to LF only. Do not strip Arabic diacritics/tashkeel, rewrite alef/ya/ta marbuta variants, remove punctuation, lowercase content, collapse internal whitespace, or alter indentation.
- Boundary whitespace is preserved and flagged. NULs are removed with a quality flag; invalid surrogate code points are replaced and flagged. These transformations must be reported, not silently described as lossless.
- HTML parsing is enabled only for assets explicitly registered as HTML. It removes script/style/noscript payloads and preserves block boundaries and preformatted indentation as far as the parser allows. Always inspect task-specific fixtures; no HTML extraction is claimed to be perfect.
- Record IDs and content hashes are SHA-256 hex strings. Validation verifies the text hash, schema/normalization versions, supported language label, timestamp/timezone, JSON metadata, NFC, and LF.
- Extraction requires explicit text-field mappings for multi-field inputs. GSM8K's registered mapping labels `question` as `Question` and `answer` as `Solution`; other fields are not silently concatenated as text.

## 3. Configured gates and outcomes

Defaults in `config/pipeline.json`:

- Minimum heuristic language confidence: `0.60` for Arabic, English, and mixed labels. `unknown` always routes to `NEEDS_HUMAN_REVIEW`.
- Minimum formatting-integrity heuristic: `0.95`.
- Minimum information-density heuristic: `0.20`.
- Maximum record length: `1,000,000` Unicode characters.
- Task-specific minimum characters: language modeling 40; instruction following 20; mathematics 8; programming 12; programming reference 20; translation 8; QA 12; evaluation 8; structured output 8; tool use 12; dictionary 2; general 20.
- Secret findings: `QUARANTINE`. Possible personal identifiers: `NEEDS_HUMAN_REVIEW`.

Outcome meanings:

- `ACCEPT` / `ACCEPT_WITH_WARNINGS` — structurally valid and passes configured heuristics, with any warnings recorded. This is not a statement of factual/legal correctness.
- `REJECT` — invalid schema/text, empty content, invalid hash, or another structural hard failure.
- `QUARANTINE` — likely secret, clearly unsafe/boilerplate/markup residue, extreme record length, or other configured hard-quality signal. Preserve for controlled investigation only under a retention policy.
- `NEEDS_HUMAN_REVIEW` — possible PII, unknown/uncertain language, language confidence under threshold, unresolved rights/provenance, or another ambiguous decision. Do not publish until reviewed.

The pipeline writes quality assessments and quarantine/rejection outputs. A release command reruns the same source-aware quality and privacy gates; metadata cannot turn a `REJECT`, `QUARANTINE`, or `NEEDS_HUMAN_REVIEW` row into an accepted example.

## 4. Arabic, English, and mixed-language policy

- Script labels are heuristics over Unicode letter scripts, with minimum-text uncertainty. They are not validated language identification and do not classify Arabic MSA versus dialect.
- Diacritics, Arabic punctuation, presentation forms, code-switching, transliteration candidates, and script proportions are counted as diagnostic metadata only. No dialect, sentiment, translation quality, or factuality claim is inferred.
- Arabic/English parallel pairs receive a structural field/language check and simple warning heuristics only. Translation alignment quality remains `not_assessed_without_reference_or_human_review`.
- Code, equations, indentation, and mixed-script tokens are retained. Near-deduplication skips programming/programming-reference task types to reduce false merges caused by punctuation or identifier differences.

## 5. Privacy and secrets

The pilot scans record text plus JSON-serializable attributes for common credential patterns, email-shaped strings, and US-SSN-shaped strings. Findings report detector names only; matched values are not copied into assessment output or audit events. These pattern lists are incomplete. False negatives are expected, and any suspected sensitive content must be reviewed and handled under the source's privacy policy. Do not place secrets in registry URLs, command arguments, logs, or test fixtures.

## 6. Deduplication and leakage policy

- Exact duplicates use SHA-256 of normalized text. Case, punctuation, Arabic diacritics, and meaningful whitespace remain part of that exact hash.
- Near-duplicate detection is word-shingle Jaccard (`shingle_size: 5`, threshold `0.75`), not semantic similarity. It is only compared for the same task type and language; programming tasks are skipped. Retained/dropped decisions, similarity, cluster IDs, and reasons remain auditable.
- The implementation is pairwise O(n²) and refuses batches above 2,000 records. It is a bounded pilot path, not a large-corpus index.
- Duplicate clusters stay in one split when cluster decisions are provided. Release rechecks for exact/near duplicates and rejects cross-split cluster IDs. Unobserved paraphrases and semantic duplicates may still leak.
- Split assignment is deterministic for a seed and protected group, but small fixture groups can miss splits or badly approximate proportions. Do not report hash-threshold proportions as corpus balancing.

## 7. Review and evidence requirements

Record the reviewer/date, sampled IDs, and findings in `docs/manual_sample_review.md` or a versioned review artifact. Keep sample results separate from corpus-wide claims. The current recorded review is only of synthetic fixture examples. No real corpus sample, Arabic dialect review, license review, or full manual review has been completed.
