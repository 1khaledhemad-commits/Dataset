# Recorded spot-check (fixture only)

- **Date:** 2026-10-09 (UTC)
- **Reviewer:** Arena Agent Mode, visual/text spot-check; not an independent human QA or legal review
- **Input:** `tests/fixtures/smoke_records.jsonl` (10 synthetic rows, 1,678 bytes)
- **Purpose:** inspect a small sample of mixed-language, exact/near-duplicate, and code-format cases while exercising the offline path
- **Real-world source records reviewed:** 0

## Selected rows and observations

| Record ID(s) | Spot-check observation | Limits |
|---|---|---|
| `en-001`, `en-002` | English curation sentence is repeated exactly; appropriate exact-duplicate fixture. | Synthetic sentence only; not evidence about a real corpus. |
| `en-near-001`, `en-near-002` | Long English pipeline description differs by a short appended sentence; appropriate near-duplicate fixture pair. | One labeled example cannot establish near-duplicate detector quality. |
| `ar-001` | Coherent Arabic sentence about preserving meaning, provenance, license, and quality review. | No dialect/Msa classification or translation/factuality check was performed. |
| `mixed-001` | Arabic/English code-switch with the English provenance term and a source-license phrase left intact. | No language-model evaluation or bilingual fluency review. |
| `code-001` | Python-like function and four-space indentation are represented as source text; line breaks/indentation should be retained. | No execution or correctness evaluation of the code. |

The fixture suite also contains short, empty, and markup/boilerplate edge cases, but they were not part of this documented manual sample. Their observed pipeline outcomes are automated test results, not manual judgments.

## Conclusion

The selected rows are suitable for exercising the declared synthetic test cases. This is **not** a manual review of all fixture rows, any acquired source corpus, license scope, Arabic dialect coverage, safety false-negative rate, factual correctness, or production readiness. Fixture records remain test-only and do not count as acquired real-world data.
