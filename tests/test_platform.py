from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
import zipfile
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlparse
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from data_platform import acquisition
from data_platform.acquisition import DownloadPolicy, _validate_content, _validate_url, acquire_http, acquire_fixture
from data_platform.audit import append_audit_event
from data_platform.config import load_json_yaml, validate_pipeline_config, validate_registry
from data_platform.deduplication import benchmark_near_duplicate_detector, deduplicate
from data_platform.errors import PipelineError
from data_platform.extraction import extract_artifact
from data_platform.models import ExtractedRecord, NormalizedRecord
from data_platform.normalization import classify_language, normalize_record, normalize_text
from data_platform.pipeline import run_fixture_smoke
from data_platform.profiles import language_profile, validate_parallel_pair
from data_platform.quality import assess_quality
from data_platform.releases import create_release, verify_release
from data_platform.security import scan_possible_pii, scan_secrets
from data_platform.sources import eligibility_for_training, is_acquisition_eligible
from data_platform.splitting import assert_no_group_leakage, split_records
from data_platform.storage import read_jsonl, write_json_atomic, write_jsonl_atomic
from data_platform.validation import validate_jsonl_file, validate_record



def source_record(source_id: str = "licensed-test", *, fixture: bool = True,
                  revision: str = "rev-1", license_id: str = "CC-BY-4.0",
                  artifact_hash: str | None = None, asset_id: str = "asset-test",
                  text: str = "A sufficiently detailed English record explains its source and preserves useful provenance.") -> NormalizedRecord:
    artifact_hash = artifact_hash or hashlib.sha256((source_id + "-artifact").encode()).hexdigest()
    extracted = ExtractedRecord(
        source_id=source_id,
        source_record_id="row-1",
        text=text,
        source_url="https://data.example.org/dataset.jsonl",
        source_revision=revision,
        license_id=license_id,
        domain="general",
        task_type="language_modeling",
        attributes={},
        provenance={"fixture_only": fixture, "artifact_sha256": artifact_hash, "asset_id": asset_id,
                    "artifact_path": "tests/fixture.jsonl" if fixture else "data/raw/source/asset.jsonl"},
    )
    record = normalize_record(extracted, ingestion_timestamp="2026-10-09T00:00:00Z")
    return record


def eligible_source(source_id: str = "licensed-test", *, evaluation_only: bool = False) -> dict:
    return {
        "source_id": source_id,
        "name": "Test-licensed source",
        "source_type": "test_source",
        "eligibility": "APPROVED",
        "trust_level": "high",
        "trust_justification": "local deterministic unit test source",
        "license": {"name": "CC BY 4.0", "spdx_id": "CC-BY-4.0", "training_use": "permitted_with_attribution"},
        "redistribution": "permitted_with_attribution",
        "attribution": ["Test data author"],
        "restrictions": ["retain the notice"],
        "personal_data_risk": "low",
        "evaluation_only": evaluation_only,
    }


def make_local_server():
    body = b'{"text":"A local server sends enough valid English text for safe bounded acquisition and provenance tests."}\n'
    state = {"counts": Counter(), "requests": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return

        def _send(self, status: int, payload: bytes = b"", *, content_type: str = "application/x-ndjson",
                  headers: dict[str, str] | None = None, declared_length: int | None = None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload) if declared_length is None else declared_length))
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if payload:
                try:
                    self.wfile.write(payload)
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass

        def do_GET(self):
            route = urlparse(self.path).path
            state["counts"][route] += 1
            state["requests"].append({"path": route, "range": self.headers.get("Range"),
                                      "if_range": self.headers.get("If-Range")})
            if route == "/retry":
                if state["counts"][route] == 1:
                    self._send(503, b"", headers={"Retry-After": "0"})
                else:
                    self._send(200, body, headers={"ETag": '"v1"'})
            elif route == "/retry-after-too-long":
                self._send(429, b"", headers={"Retry-After": "120"})
            elif route == "/range":
                start = 0
                raw_range = self.headers.get("Range")
                if raw_range:
                    try:
                        start = int(raw_range.removeprefix("bytes=").removesuffix("-"))
                    except ValueError:
                        start = len(body)
                if start >= len(body):
                    self._send(416, b"", headers={"Content-Range": f"bytes */{len(body)}"})
                elif raw_range:
                    remaining = body[start:]
                    self._send(206, remaining, headers={
                        "Content-Range": f"bytes {start}-{len(body)-1}/{len(body)}", "ETag": '"v1"'
                    })
                else:
                    self._send(200, body, headers={"ETag": '"v1"'})
            elif route == "/incomplete":
                if state["counts"][route] == 1:
                    self._send(200, body, headers={"ETag": '"v1"'}, declared_length=len(body) + 7)
                    self.close_connection = True
                else:
                    self._send(200, body, headers={"ETag": '"v1"'})
            elif route == "/html":
                self._send(200, b"<!doctype html><html><body>Access denied</body></html>", content_type="text/html")
            elif route == "/checksum":
                self._send(200, body, headers={"ETag": '"v1"'})
            elif route == "/too-large":
                self._send(200, b"", declared_length=4096)
            elif route == "/redirect":
                self._send(302, b"", headers={"Location": "https://unapproved.example.invalid/payload"})
            elif route == "/not-found":
                self._send(404, b"not found", content_type="text/plain")
            else:
                self._send(200, body, headers={"ETag": '"v1"'})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, state, body


class PlatformTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import sys
        if str(ROOT / "src") not in sys.path:
            sys.path.insert(0, str(ROOT / "src"))

    def test_registry_and_pipeline_config_validate(self):
        registry = load_json_yaml(ROOT / "config" / "source_registry.yaml")
        config = load_json_yaml(ROOT / "config" / "pipeline.json")
        self.assertEqual(validate_registry(registry), [])
        self.assertEqual(validate_pipeline_config(config), [])
        self.assertEqual(len(registry["sources"]), 13)

    def test_evaluation_only_rights_are_independent_and_fail_closed(self):
        source = eligible_source("evaluation-only-source", evaluation_only=True)
        source["license"]["training_use"] = "restricted"
        source["license"]["evaluation_use"] = "permitted_with_attribution"
        self.assertEqual(eligibility_for_training(source, "evaluation")[0], True)
        self.assertFalse(eligibility_for_training(source, "sft")[0])
        source["license"]["evaluation_use"] = "unknown"
        self.assertFalse(eligibility_for_training(source, "evaluation")[0])
        registry = load_json_yaml(ROOT / "config" / "source_registry.yaml")
        held_out = next(item for item in registry["sources"] if item["evaluation_only"])
        held_out["eligibility"] = "APPROVED"
        held_out["license"]["training_use"] = "restricted"
        held_out["license"]["evaluation_use"] = "permitted_with_attribution"
        self.assertEqual(validate_registry(registry), [])

    def test_registry_and_config_validation_report_malformed_nested_values(self):
        registry = load_json_yaml(ROOT / "config" / "source_registry.yaml")
        registry["sources"][0]["license"] = None
        registry["sources"][0]["eligibility"] = []
        registry["sources"][0]["assets"][0]["url"] = []
        errors = validate_registry(registry)
        self.assertTrue(any("license must be an object" in error for error in errors))
        self.assertTrue(any("eligibility" in error for error in errors))
        self.assertTrue(any("url must be HTTPS" in error for error in errors))
        self.assertTrue(validate_pipeline_config({"config_version": "1.0.0", "normalization": None}))

    def test_unknown_gsm8k_license_scope_fails_closed(self):
        registry = load_json_yaml(ROOT / "config" / "source_registry.yaml")
        gsm8k = next(s for s in registry["sources"] if s["source_id"] == "gsm8k-openai")
        self.assertEqual(gsm8k["eligibility"], "NEEDS_REVIEW")
        self.assertEqual(gsm8k["license"]["training_use"], "unknown")
        self.assertFalse(is_acquisition_eligible(gsm8k)[0])
        self.assertFalse(eligibility_for_training(gsm8k, "sft")[0])

    def test_invalid_threshold_and_nonfinite_splits_return_errors_not_tracebacks(self):
        config = load_json_yaml(ROOT / "config" / "pipeline.json")
        config["deduplication"]["near_duplicate_jaccard_threshold"] = "not-a-number"
        config["splits"]["proportions"] = {"train": float("nan"), "test": float("nan")}
        errors = validate_pipeline_config(config)
        self.assertTrue(any("threshold" in error for error in errors))
        self.assertTrue(any("proportions" in error for error in errors))

    def test_registry_rejects_unsafe_asset_filename_and_query_url(self):
        registry = load_json_yaml(ROOT / "config" / "source_registry.yaml")
        sample = next(s for s in registry["sources"] if s["assets"])
        asset = sample["assets"][0]
        original_id, original_url = asset["asset_id"], asset["url"]
        asset["asset_id"] = "../escape"
        asset["url"] = "https://api.github.com/resource?token=not-allowed"
        errors = validate_registry(registry)
        self.assertTrue(any("safe filename" in error for error in errors))
        self.assertTrue(any("query parameters" in error for error in errors))
        asset["asset_id"], asset["url"] = original_id, original_url

    def test_url_allowlist_rejects_query_credentials_and_nonstandard_https_port(self):
        policy = DownloadPolicy(allowed_hosts=("api.github.com",))
        for url in ("https://api.github.com/a?token=secret", "https://api.github.com:444/a",
                    "https://user:pass@api.github.com/a", "https://api.github.com/a#fragment"):
            with self.subTest(url=url), self.assertRaises(PipelineError):
                _validate_url(url, policy)

    def test_github_blob_base64_whitespace_hash_and_deterministic_sample(self):
        payload = b"".join([
            b'{"id":"r1","question":"What is two plus two?","answer":"Add two and two to get four."}\n',
            b'{"id":"r2","question":"What is three plus four?","answer":"Add three and four to get seven."}\n',
            b'{"id":"r3","question":"What is five plus six?","answer":"Add five and six to get eleven."}\n',
            b'{"id":"r4","question":"What is eight plus one?","answer":"Add eight and one to get nine."}\n',
        ])
        blob_sha = hashlib.sha1(b"blob " + str(len(payload)).encode() + b"\0" + payload).hexdigest()
        encoded = base64.b64encode(payload).decode("ascii")
        wrapped = "\n".join(encoded[i:i + 40] for i in range(0, len(encoded), 40))
        api_file = {"encoding": "base64", "content": wrapped, "sha": blob_sha, "size": len(payload),
                    "path": "data/train.jsonl"}
        asset_manifest = {"sha256": hashlib.sha256(json.dumps(api_file).encode()).hexdigest(),
                          "byte_count": len(json.dumps(api_file)), "path": "blob.json"}
        source = eligible_source("github-test")
        asset = {"asset_id": "blob-test", "format": "json", "decoded_format": "jsonl",
                 "content_encoding": "github_git_blob_base64", "source_git_blob_sha1": blob_sha,
                 "source_path": "data/train.jsonl", "text_fields": ["question", "answer"],
                 "sample_records": 2, "sample_seed": 17, "max_source_records": 4, "max_records": 4,
                 "domain": "mathematics", "task_type": "mathematics", "dataset_purpose": "sft"}
        stats: dict[str, int] = {}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "blob.json"
            path.write_text(json.dumps(api_file), encoding="utf-8")
            records = list(extract_artifact(path, source=source, asset=asset, artifact_manifest=asset_manifest,
                                            text_field=None, max_records=4, stats=stats))
            again = list(extract_artifact(path, source=source, asset=asset, artifact_manifest=asset_manifest,
                                          text_field=None, max_records=4))
        self.assertEqual(len(records), 2)
        self.assertEqual([r.source_record_id for r in records], [r.source_record_id for r in again])
        self.assertEqual(stats["source_records_scanned"], 4)
        self.assertEqual(stats["records_emitted"], 2)
        self.assertTrue(all(r.attributes["source_git_blob_sha1"] == blob_sha for r in records))
        self.assertIn("Question:\n", records[0].text)
        self.assertIn("Solution:\n", records[0].text)

    def test_github_blob_hash_mismatch_is_rejected(self):
        raw = b'{"id":"1","question":"Question text","answer":"Answer text"}\n'
        api_file = {"encoding": "base64", "content": base64.b64encode(raw).decode(), "sha": "0" * 40,
                    "size": len(raw)}
        source = eligible_source("github-test")
        asset = {"asset_id": "blob-test", "format": "json", "decoded_format": "jsonl",
                 "content_encoding": "github_git_blob_base64", "source_git_blob_sha1": "0" * 40,
                 "text_fields": ["question", "answer"], "max_source_records": 2, "max_records": 2}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "blob.json"
            path.write_text(json.dumps(api_file), encoding="utf-8")
            with self.assertRaises(PipelineError) as ctx:
                list(extract_artifact(path, source=source, asset=asset, artifact_manifest={"sha256": "x", "byte_count": path.stat().st_size}, max_records=2))
        self.assertEqual(ctx.exception.code, "source_blob_checksum_mismatch")

    def test_normalization_preserves_arabic_diacritics_indentation_and_spacing(self):
        original = "  def answer():\r\n    return 'x'  \r\n\nالْعَرَبِيَّةُ، أَإِآ؛؟  "
        normalized, _ = normalize_text(original)
        expected = original.replace("\r\n", "\n").replace("\r", "\n")
        self.assertEqual(normalized, expected)
        self.assertTrue(normalized.startswith("  def"))
        self.assertIn("    return", normalized)
        self.assertTrue(normalized.endswith("  "))
        self.assertIn("الْعَرَبِيَّةُ", normalized)
        record_a = normalize_record(ExtractedRecord("stable-src", "stable-row", original), ingestion_timestamp="2026-01-01T00:00:00Z")
        record_b = normalize_record(ExtractedRecord("stable-src", "stable-row", original), ingestion_timestamp="2026-10-09T00:00:00Z")
        self.assertEqual(record_a.record_id, record_b.record_id)
        self.assertEqual(record_a.content_hash, hashlib.sha256(expected.encode()).hexdigest())
        self.assertIn("preserve whitespace", record_a.provenance["normalization_policy"])

    def test_script_classification_and_arabic_profile_are_uncertain_and_non_destructive(self):
        self.assertEqual(classify_language("مرحبا بالعالم هذه عينة عربية كاملة النص")[0], "ar")
        self.assertEqual(classify_language("A complete English sentence includes several clear words.")[0], "en")
        self.assertEqual(classify_language("هذا نص عربي with English words in one sentence")[0], "mixed")
        self.assertEqual(classify_language("abc")[0], "unknown")
        profile = language_profile("شو كتير العربية English", "mixed")
        self.assertTrue(profile["code_switch_present"])
        self.assertIn("levantine_candidate", profile["dialect_marker_candidates"])
        self.assertEqual(profile["arabic_variety"], "not_automatically_classified")
        pair = validate_parallel_pair({"source_text": "مرحبا", "target_text": "Hello there", "source_language": "ar", "target_language": "en"})
        self.assertTrue(pair["valid_structure"])
        self.assertEqual(pair["translation_alignment_quality"], "not_assessed_without_reference_or_human_review")

    def test_html_extraction_preserves_blocks_preformatted_code_and_arabic(self):
        html = """<html><body><p>فقرة عربية مع التشكيل الْعَرَبِيَّةُ.</p><pre>def f():
    return 1</pre><script>secret()</script><p>Second paragraph.</p></body></html>"""
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "page.html"
            path.write_text(html, encoding="utf-8")
            source = eligible_source("html-source")
            asset = {"asset_id": "html-asset", "format": "html", "domain": "general", "task_type": "general"}
            artifact = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "byte_count": path.stat().st_size,
                        "path": str(path), "final_url": "https://example.org/page.html"}
            record, = list(extract_artifact(path, source=source, asset=asset, artifact_manifest=artifact,
                                            max_expanded_bytes=4096))
        self.assertIn("الْعَرَبِيَّةُ", record.text)
        self.assertIn("\n    return 1", record.text)
        self.assertIn("Second paragraph.", record.text)
        self.assertNotIn("secret()", record.text)

    def test_structural_validator_rejects_content_hash_mismatch(self):
        record = source_record()
        self.assertTrue(validate_record(record).valid)
        payload = record.to_dict()
        payload["content_hash"] = "0" * 64
        result = validate_record(payload)
        self.assertFalse(result.valid)
        self.assertIn("content_hash does not match normalized text", result.errors)

    def test_secret_detector_redacts_values_and_quality_quarantines(self):
        secret = "api_key=DEMO_NOT_A_REAL_SECRET_VALUE_20261009"
        findings = scan_secrets(secret)
        self.assertEqual([f.detector for f in findings], ["credential_assignment"])
        self.assertNotIn(secret, json.dumps([f.to_dict() for f in findings]))
        record = source_record(text=f"This sufficiently long safety review record includes a test credential marker {secret}.")
        assessment = assess_quality(record, validate_record(record), eligible_source(), purpose="sft")
        encoded = json.dumps(assessment.to_dict())
        self.assertEqual(assessment.outcome, "QUARANTINE")
        self.assertIn("credential_assignment", encoded)
        self.assertNotIn("DEMO_NOT_A_REAL_SECRET_VALUE_20261009", encoded)

    def test_possible_pii_is_review_only_and_value_is_not_returned(self):
        text = "The record contains a contact example.person@example.invalid for controlled review purposes."
        findings = scan_possible_pii(text)
        self.assertEqual(findings[0].detector, "possible_email_address")
        self.assertNotIn("example.person", json.dumps([f.to_dict() for f in findings]))
        record = source_record(text=text)
        assessment = assess_quality(record, validate_record(record), eligible_source(), purpose="sft")
        self.assertEqual(assessment.outcome, "NEEDS_HUMAN_REVIEW")
        self.assertNotIn("example.person", json.dumps(assessment.to_dict()))

    def test_near_duplicate_benchmark_has_explicit_false_positive_and_false_negative_counts(self):
        labels = []
        for row in read_jsonl(ROOT / "tests" / "fixtures" / "near_duplicate_labels.jsonl"):
            labels.append((row["left"], row["right"], row["is_duplicate"]))
        result = benchmark_near_duplicate_detector(labels, threshold=0.75)
        self.assertEqual(result["labeled_pairs"], 10)
        self.assertEqual(result["true_positive"], 3)
        self.assertEqual(result["false_positive"], 0)
        self.assertEqual(result["true_negative"], 6)
        self.assertEqual(result["false_negative"], 1)
        self.assertEqual(result["precision"], 1.0)
        self.assertEqual(result["recall"], 0.75)

    def test_exact_and_near_deduplication_returns_reversible_decisions(self):
        first = source_record(text="A sufficiently detailed record explains the data provenance and preserves Arabic-English review decisions.")
        exact = source_record(text=first.text)
        exact.source_record_id = "row-2"
        exact.record_id = hashlib.sha256(b"another-record-id").hexdigest()
        near = source_record(text=first.text + " Reproducible.")
        near.source_record_id = "row-3"
        near.record_id = hashlib.sha256(b"third-record-id").hexdigest()
        kept, decisions = deduplicate([first, exact, near], threshold=0.75, shingle_size=5)
        self.assertEqual(len(kept), 1)
        self.assertEqual(len(decisions), 3)
        self.assertEqual(sum(not d.retained for d in decisions), 2)
        self.assertEqual(len({d.cluster_id for d in decisions}), 1)

    def test_duplicate_clusters_stay_within_one_deterministic_split(self):
        records = [source_record(source_id="source-a", text=f"A detailed record {i} preserves the project provenance and creates a clear audit trail for the review pipeline.") for i in range(8)]
        cluster_map = {records[0].record_id: "cluster-shared", records[1].record_id: "cluster-shared"}
        first, manifest_a = split_records(records, seed=17, proportions={"train": 0.6, "validation": 0.2, "test": 0.2}, cluster_by_record=cluster_map)
        second, manifest_b = split_records(records, seed=17, proportions={"train": 0.6, "validation": 0.2, "test": 0.2}, cluster_by_record=cluster_map)
        assert_no_group_leakage(first, cluster_by_record=cluster_map)
        self.assertEqual([r.split_assignment for r in first], [r.split_assignment for r in second])
        self.assertEqual(manifest_a["group_assignments"], manifest_b["group_assignments"])
        self.assertEqual(first[0].split_assignment, first[1].split_assignment)

    def test_split_rejects_nan_and_invalid_proportions(self):
        record = source_record()
        for proportions in ({"train": float("nan"), "test": float("nan")}, [0.5, 0.5], {}):
            with self.subTest(proportions=proportions), self.assertRaises(ValueError):
                split_records([record], seed=1, proportions=proportions)  # type: ignore[arg-type]

    def test_zip_expansion_traversal_and_corruption_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bomb = root / "expanded.zip"
            with zipfile.ZipFile(bomb, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("text.txt", b"x" * 4096)
            with self.assertRaises(PipelineError) as ctx:
                _validate_content(bomb, "zip", 100, "application/zip")
            self.assertEqual(ctx.exception.code, "expanded_size_limit")
            traversal = root / "traversal.zip"
            with zipfile.ZipFile(traversal, "w") as archive:
                archive.writestr("../escape.txt", "not extracted")
            with self.assertRaises(PipelineError) as ctx2:
                _validate_content(traversal, "zip", 4096, "application/zip")
            self.assertEqual(ctx2.exception.code, "unsafe_archive")
            corrupt = root / "corrupt.zip"
            corrupt.write_bytes(b"not a ZIP archive")
            with self.assertRaises(PipelineError) as ctx3:
                _validate_content(corrupt, "zip", 4096, "application/zip")
            self.assertEqual(ctx3.exception.code, "corrupt_archive")

    def test_gzip_is_bounded_and_extracted_without_losing_utf8(self):
        text = "العربية English text remains intact in the bounded compressed fixture."
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "data.txt.gz"
            path.write_bytes(gzip.compress(text.encode("utf-8")))
            _validate_content(path, "gz", 1024, "application/gzip")
            source = eligible_source("gzip-test")
            asset = {"asset_id": "gzip", "format": "gz", "domain": "general", "task_type": "general"}
            result = list(extract_artifact(path, source=source, asset=asset,
                                           artifact_manifest={"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                                              "byte_count": path.stat().st_size}, max_expanded_bytes=1024))
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].text, text)
            with self.assertRaises(PipelineError) as ctx:
                _validate_content(path, "gz", 10, "application/gzip")
            self.assertEqual(ctx.exception.code, "expanded_size_limit")

    def test_jsonl_readers_enforce_byte_and_record_budgets(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "input.jsonl"
            path.write_text('{"n":1}\n{"n":2}\n', encoding="utf-8")
            with self.assertRaises(PipelineError) as ctx:
                list(read_jsonl(path, max_records=1, max_bytes=100))
            self.assertEqual(ctx.exception.code, "record_quota_exceeded")
            with self.assertRaises(PipelineError) as ctx2:
                list(read_jsonl(path, max_records=10, max_bytes=5))
            self.assertEqual(ctx2.exception.code, "input_byte_limit")
            report = validate_jsonl_file(path, max_records=1, max_bytes=100)
            self.assertFalse(report["valid"])
            self.assertIn("record_limit_exceeded", {entry["error"] for entry in report["errors"]})

    def test_cli_help_registry_plan_and_dry_run_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            shutil.copytree(ROOT / "config", root / "config")
            env = dict(os.environ)
            env["PYTHONPATH"] = str(ROOT / "src")
            help_result = subprocess.run([sys.executable, "-m", "data_platform", "--help"], cwd=ROOT,
                                         env=env, capture_output=True, text=True, check=False)
            self.assertEqual(help_result.returncode, 0, help_result.stderr)
            validate_result = subprocess.run([sys.executable, "-m", "data_platform", "--root", str(root),
                                               "sources", "validate"], cwd=ROOT, env=env,
                                              capture_output=True, text=True, check=False)
            self.assertEqual(validate_result.returncode, 0, validate_result.stderr)
            self.assertTrue(json.loads(validate_result.stdout)["valid"])
            plan_result = subprocess.run([sys.executable, "-m", "data_platform", "--root", str(root), "plan"],
                                          cwd=ROOT, env=env, capture_output=True, text=True, check=False)
            plan = json.loads(plan_result.stdout)
            self.assertEqual(plan_result.returncode, 0, plan_result.stderr)
            self.assertEqual(plan["eligible_asset_count"], 0)
            self.assertEqual(plan["blocked_asset_count"], 1)
            discovery = subprocess.run([sys.executable, "-m", "data_platform", "--root", str(root),
                                         "sources", "discover", "--language", "ar"], cwd=ROOT, env=env,
                                        capture_output=True, text=True, check=False)
            self.assertEqual(discovery.returncode, 0, discovery.stderr)
            discovery_payload = json.loads(discovery.stdout)
            self.assertFalse(discovery_payload["live_network_checks_performed"])
            self.assertTrue(any("ar" in candidate["languages"] for candidate in discovery_payload["candidates"]))
            run_result = subprocess.run([sys.executable, "-m", "data_platform", "--root", str(root), "run",
                                         "gsm8k-openai", "gsm8k-train-pilot", "--dry-run"],
                                        cwd=ROOT, env=env, capture_output=True, text=True, check=False)
            self.assertEqual(run_result.returncode, 2)
            self.assertEqual(json.loads(run_result.stderr)["error"]["code"], "source_not_eligible")
            self.assertFalse((root / "data" / "raw").exists())
            self.assertFalse((root / "logs").exists())
            blocked_record = source_record(source_id="gsm8k-openai", fixture=False)
            blocked_record.split_assignment = "train"
            input_path = root / "blocked-records.jsonl"
            write_jsonl_atomic(input_path, [blocked_record.to_dict()])
            metadata_path = root / "forged-rights.json"
            metadata_path.write_text(json.dumps({
                "dataset_purpose": "sft",
                "source_license_decisions": {"gsm8k-openai": {
                    "eligibility": "APPROVED", "training_use": "permitted",
                    "redistribution": "permitted", "license_id": "MIT"}},
            }), encoding="utf-8")
            forged_release = subprocess.run([
                sys.executable, "-m", "data_platform", "--root", str(root), "release",
                "--input", str(input_path), "--release-id", "forged-release-001", "--purpose", "sft",
                "--metadata", str(metadata_path),
            ], cwd=ROOT, env=env, capture_output=True, text=True, check=False)
            self.assertEqual(forged_release.returncode, 2)
            self.assertEqual(json.loads(forged_release.stderr)["error"]["code"], "release_license_gate")
            self.assertFalse((root / "data" / "releases").exists())

    def test_cli_release_rechecks_quality_and_personal_data_even_with_manual_approval(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            shutil.copytree(ROOT / "config", root / "config")
            shutil.copytree(ROOT / "docs" / "licenses", root / "docs" / "licenses")
            registry_path = root / "config" / "source_registry.yaml"
            registry = load_json_yaml(registry_path)
            source = next(item for item in registry["sources"] if item["source_id"] == "gsm8k-openai")
            source["eligibility"] = "APPROVED"
            source["eligibility_reason"] = "synthetic test-only approval to exercise downstream release gates"
            source["license"]["training_use"] = "permitted_with_attribution"
            source["redistribution"] = "permitted_with_attribution"
            registry_path.write_text(json.dumps(registry, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            artifact_hash = hashlib.sha256(b"synthetic release-gate fixture").hexdigest()
            record = source_record(source_id="gsm8k-openai", fixture=False, artifact_hash=artifact_hash,
                                   text="This synthetic record includes sample.person@example.invalid for privacy review and is intentionally not releasable.")
            record.source_revision = source["source_revision"]
            record.license_id = source["license"]["spdx_id"]
            record.provenance["asset_id"] = source["assets"][0]["asset_id"]
            record.split_assignment = "train"
            input_path = root / "records.jsonl"
            write_jsonl_atomic(input_path, [record.to_dict()])
            metadata_path = root / "approval.json"
            metadata_path.write_text(json.dumps({"human_approval_status": "approved", "approved_by": "Synthetic test",
                                                "human_approval_reference": "test-only"}), encoding="utf-8")
            env = dict(os.environ); env["PYTHONPATH"] = str(ROOT / "src")
            result = subprocess.run([
                sys.executable, "-m", "data_platform", "--root", str(root), "release",
                "--input", str(input_path), "--release-id", "unsafe-quality-001", "--purpose", "sft",
                "--metadata", str(metadata_path),
            ], cwd=ROOT, env=env, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
            self.assertEqual(json.loads(result.stderr)["error"]["code"], "release_quality_gate")
            self.assertFalse((root / "data" / "releases").exists())

    def test_write_helpers_refuse_to_overwrite_existing_files(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "rows.jsonl"
            write_jsonl_atomic(path, [{"n": 1}])
            original = path.read_bytes()
            with self.assertRaises(PipelineError) as ctx:
                write_jsonl_atomic(path, [{"n": 2}])
            self.assertEqual(ctx.exception.code, "output_exists")
            self.assertEqual(path.read_bytes(), original)
            manifest = Path(temp) / "metadata.json"
            write_json_atomic(manifest, {"value": "original"})
            with self.assertRaises(PipelineError):
                write_json_atomic(manifest, {"value": "changed"})
            self.assertEqual(json.loads(manifest.read_text())["value"], "original")

    def test_release_requires_registry_grounded_provenance_and_notice(self):
        license_text = "TEST LICENSE NOTICE\nCopyright test author.\nPermission is granted with attribution.\n"
        license_hash = hashlib.sha256(license_text.encode()).hexdigest()
        artifact_hash = hashlib.sha256(b"synthetic transport artifact").hexdigest()
        record = source_record(fixture=False, artifact_hash=artifact_hash)
        record.split_assignment = "train"
        source = eligible_source()
        metadata = {
            "dataset_purpose": "sft",
            "human_approval_status": "approved", "approved_by": "synthetic test actor",
            "human_approval_reference": "unit-test-only; not a real approval",
            "max_release_storage_bytes": 1024 * 1024,
            "source_manifest": [{"source_id": source["source_id"], "source_revision": "rev-1",
                                 "asset_id": "asset-test", "artifact_sha256": artifact_hash,
                                 "license_id": "CC-BY-4.0", "eligibility": "APPROVED", "evaluation_only": False}],
            "source_license_decisions": {source["source_id"]: {
                "eligibility": "APPROVED", "evaluation_only": False,
                "license": "CC BY 4.0", "license_id": "CC-BY-4.0", "license_url": "https://example.org/license",
                "training_use": "permitted_with_attribution", "redistribution": "permitted_with_attribution",
                "restrictions": ["retain notice"], "attribution": ["Test data author"],
                "license_text": license_text, "license_text_sha256": license_hash,
            }},
        }
        with tempfile.TemporaryDirectory() as temp:
            manifest = create_release([record], releases_root=Path(temp) / "releases", release_id="test-release-001", metadata=metadata)
            release_dir = Path(temp) / "releases" / "test-release-001"
            self.assertEqual(manifest["counts"]["published_records"], 1)
            self.assertNotIn("license_text", manifest["source_license_decisions"][source["source_id"]])
            notices = (release_dir / "THIRD_PARTY_NOTICES.txt").read_text(encoding="utf-8")
            self.assertIn(license_text.strip(), notices)
            self.assertTrue(verify_release(release_dir)["valid"])
            with self.assertRaises(PipelineError) as ctx:
                create_release([record], releases_root=Path(temp) / "releases", release_id="test-release-001", metadata=metadata)
            self.assertEqual(ctx.exception.code, "release_exists")

    def test_release_rejects_unsafe_split_names_before_writing(self):
        record = source_record(fixture=True)
        record.split_assignment = "../../escape"
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(PipelineError) as ctx:
                create_release([record], releases_root=Path(temp) / "releases", release_id="unsafe-split-001",
                               metadata={"dataset_purpose": "fixture_validation"})
            self.assertEqual(ctx.exception.code, "invalid_split")
            self.assertFalse((Path(temp) / "escape.jsonl").exists())

    def test_release_rejects_mixed_fixture_and_real_records(self):
        fixture = source_record(fixture=True, source_id="fixture-a")
        real = source_record(fixture=False, source_id="fixture-a")
        fixture.split_assignment = real.split_assignment = "evaluation"
        metadata = {"dataset_purpose": "fixture_validation"}
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(PipelineError) as ctx:
                create_release([fixture, real], releases_root=Path(temp), release_id="mixed-fixture-001", metadata=metadata)
        self.assertEqual(ctx.exception.code, "mixed_fixture_release_blocked")

    def test_real_release_requires_explicit_human_approval_reference(self):
        artifact_hash = hashlib.sha256(b"human gate test artifact").hexdigest()
        record = source_record(fixture=False, artifact_hash=artifact_hash)
        record.split_assignment = "train"
        source = eligible_source()
        metadata = {
            "dataset_purpose": "sft",
            "source_manifest": [{"source_id": source["source_id"], "source_revision": "rev-1",
                                 "asset_id": "asset-test", "artifact_sha256": artifact_hash,
                                 "license_id": "CC-BY-4.0", "eligibility": "APPROVED", "evaluation_only": False}],
            "source_license_decisions": {source["source_id"]: {
                "eligibility": "APPROVED", "evaluation_only": False, "license": "CC BY 4.0",
                "license_id": "CC-BY-4.0", "training_use": "permitted_with_attribution",
                "redistribution": "permitted_with_attribution", "restrictions": ["retain notice"],
                "attribution": ["Test data author"], "license_text": "Test license notice"}},
        }
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(PipelineError) as ctx:
                create_release([record], releases_root=Path(temp) / "releases", release_id="approval-gate-001", metadata=metadata)
            self.assertEqual(ctx.exception.code, "human_approval_required")
            metadata.update({"human_approval_status": "approved", "approved_by": "Test Reviewer",
                             "human_approval_reference": "review-ticket-123"})
            create_release([record], releases_root=Path(temp) / "releases", release_id="approval-gate-002", metadata=metadata)

    def test_release_blocks_unresolved_rights_evaluation_leak_and_bad_notice_hash(self):
        artifact_hash = hashlib.sha256(b"another synthetic artifact").hexdigest()
        record = source_record(fixture=False, artifact_hash=artifact_hash)
        record.split_assignment = "train"
        base = {
            "dataset_purpose": "sft", "human_approval_status": "approved", "approved_by": "synthetic test actor",
            "human_approval_reference": "unit-test-only; not a real approval",
            "source_manifest": [{"source_id": record.source_id, "source_revision": "rev-1", "asset_id": "asset-test",
                                 "artifact_sha256": artifact_hash, "license_id": "CC-BY-4.0",
                                 "eligibility": "APPROVED", "evaluation_only": False}],
            "source_license_decisions": {record.source_id: {"eligibility": "APPROVED", "evaluation_only": False,
                "license": "CC BY 4.0", "license_id": "CC-BY-4.0", "training_use": "unknown",
                "redistribution": "unknown", "restrictions": [], "attribution": []}},
        }
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(PipelineError) as ctx:
                create_release([record], releases_root=Path(temp) / "unknown", release_id="unknown-rights-001", metadata=base)
            self.assertEqual(ctx.exception.code, "release_license_gate")
            evaluation_source = eligible_source(evaluation_only=True)
            evaluation_record = source_record(source_id=evaluation_source["source_id"], fixture=False,
                                               artifact_hash=artifact_hash, license_id="CC-BY-4.0")
            evaluation_record.split_assignment = "train"
            eval_metadata = json.loads(json.dumps(base))
            eval_metadata["dataset_purpose"] = "sft"
            eval_metadata["source_manifest"][0].update({"source_id": evaluation_source["source_id"], "evaluation_only": True})
            eval_metadata["source_license_decisions"] = {evaluation_source["source_id"]: {
                "eligibility": "APPROVED", "evaluation_only": True, "license": "CC BY 4.0", "license_id": "CC-BY-4.0",
                "training_use": "permitted_with_attribution", "redistribution": "permitted_with_attribution",
                "restrictions": ["evaluation only"], "attribution": ["Test data author"]}}
            with self.assertRaises(PipelineError) as ctx2:
                create_release([evaluation_record], releases_root=Path(temp) / "evaluation", release_id="evaluation-leak-001", metadata=eval_metadata)
            self.assertEqual(ctx2.exception.code, "evaluation_leakage_blocked")
            valid_meta = json.loads(json.dumps(base))
            valid_meta["source_license_decisions"][record.source_id].update({"training_use": "permitted_with_attribution",
                "redistribution": "permitted_with_attribution", "license_text": "License text", "license_text_sha256": "0" * 64})
            with self.assertRaises(PipelineError) as ctx3:
                create_release([record], releases_root=Path(temp) / "bad-notice", release_id="bad-notice-001", metadata=valid_meta)
            self.assertEqual(ctx3.exception.code, "license_notice_hash_mismatch")

    def test_evaluation_release_requires_evaluation_rights_and_no_train_split(self):
        source = eligible_source("evaluation-only-source", evaluation_only=True)
        artifact_hash = hashlib.sha256(b"evaluation-only test artifact").hexdigest()
        record = source_record(source_id=source["source_id"], fixture=False, artifact_hash=artifact_hash)
        record.split_assignment = "evaluation"
        metadata = {
            "dataset_purpose": "evaluation", "human_approval_status": "approved", "approved_by": "synthetic test actor",
            "human_approval_reference": "unit-test-only; not a real approval",
            "source_manifest": [{"source_id": source["source_id"], "source_revision": "rev-1",
                                 "asset_id": "asset-test", "artifact_sha256": artifact_hash,
                                 "license_id": "CC-BY-4.0", "eligibility": "APPROVED", "evaluation_only": True}],
            "source_license_decisions": {source["source_id"]: {
                "eligibility": "APPROVED", "evaluation_only": True, "license": "CC BY 4.0",
                "license_id": "CC-BY-4.0", "training_use": "restricted",
                "evaluation_use": "permitted_with_attribution", "redistribution": "permitted_with_attribution",
                "restrictions": ["evaluation only"], "attribution": ["Test data author"],
                "license_text": "Test evaluation license notice"}},
        }
        with tempfile.TemporaryDirectory() as temp:
            release = Path(temp) / "evaluation-release"
            create_release([record], releases_root=release, release_id="evaluation-release-001", metadata=metadata)
            self.assertTrue(verify_release(release / "evaluation-release-001")["valid"])
            training_record = source_record(source_id=source["source_id"], fixture=False, artifact_hash=artifact_hash)
            training_record.split_assignment = "train"
            with self.assertRaises(PipelineError) as ctx:
                create_release([training_record], releases_root=Path(temp) / "training-release",
                               release_id="evaluation-leak-002", metadata={**metadata, "dataset_purpose": "evaluation"})
            self.assertEqual(ctx.exception.code, "evaluation_leakage_blocked")

    def test_manifest_only_release_has_no_published_records_and_verifies(self):
        record = source_record(fixture=True)
        record.split_assignment = "evaluation"
        with tempfile.TemporaryDirectory() as temp:
            manifest = create_release([record], releases_root=Path(temp) / "releases", release_id="manifest-only-001",
                                      metadata={"dataset_purpose": "fixture_validation"}, manifest_only=True)
            self.assertEqual(manifest["counts"]["published_records"], 0)
            self.assertEqual(manifest["counts"]["manifest_records"], 1)
            self.assertEqual(manifest["files"], {})
            self.assertTrue(verify_release(Path(temp) / "releases" / "manifest-only-001")["valid"])

    def test_pending_real_candidate_is_manifest_only_and_not_a_training_release(self):
        artifact_hash = hashlib.sha256(b"candidate-only synthetic artifact").hexdigest()
        source = eligible_source("candidate-source")
        record = source_record(source_id=source["source_id"], fixture=False, artifact_hash=artifact_hash)
        record.split_assignment = "train"
        metadata = {
            "dataset_purpose": "sft", "human_approval_status": "pending_owner_review",
            "source_manifest": [{"source_id": source["source_id"], "source_revision": "rev-1",
                                 "asset_id": "asset-test", "artifact_sha256": artifact_hash,
                                 "license_id": "CC-BY-4.0", "eligibility": "APPROVED", "evaluation_only": False}],
            "source_license_decisions": {source["source_id"]: {
                "eligibility": "APPROVED", "evaluation_only": False, "license": "CC BY 4.0",
                "license_id": "CC-BY-4.0", "training_use": "permitted_with_attribution",
                "redistribution": "unknown", "restrictions": ["review before publication"], "attribution": []}},
        }
        with tempfile.TemporaryDirectory() as temp:
            release_root = Path(temp) / "releases"
            manifest = create_release([record], releases_root=release_root, release_id="candidate-only-001",
                                      metadata=metadata, manifest_only=True)
            self.assertEqual(manifest["counts"]["published_records"], 0)
            self.assertEqual(manifest["counts"]["manifest_records"], 1)
            self.assertEqual(manifest["files"], {})
            result = verify_release(release_root / "candidate-only-001")
            self.assertTrue(result["valid"], result["errors"])
            self.assertEqual(result["human_approval_status"], "pending_owner_review")

    def test_release_verification_detects_file_and_manifest_tampering(self):
        record = source_record(fixture=True)
        record.split_assignment = "train"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "releases"
            create_release([record], releases_root=root, release_id="tamper-test-001",
                           metadata={"dataset_purpose": "fixture_validation"})
            release = root / "tamper-test-001"
            data_file = release / "records-train.jsonl"
            data_file.write_bytes(data_file.read_bytes() + b" ")
            result = verify_release(release)
            self.assertFalse(result["valid"])
            self.assertTrue(any("sha256_mismatch" in e for e in result["errors"]))
            with self.assertRaises(PipelineError):
                create_release([record], releases_root=root, release_id="tamper-test-001",
                               metadata={"dataset_purpose": "fixture_validation"})

    def test_release_quota_failure_leaves_no_partial_release_directory(self):
        record = source_record(fixture=True)
        record.split_assignment = "train"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "releases"
            with self.assertRaises(PipelineError) as ctx:
                create_release([record], releases_root=root, release_id="quota-fail-001",
                               metadata={"dataset_purpose": "fixture_validation", "max_release_storage_bytes": 1})
            self.assertEqual(ctx.exception.code, "release_storage_quota_exceeded")
            self.assertFalse((root / "quota-fail-001").exists())
            self.assertEqual(list(root.iterdir()), [])

    def test_parallel_host_pacing_uses_configured_interval(self):
        policy = DownloadPolicy(min_request_interval_seconds=1.0)
        with patch.object(acquisition.time, "monotonic", side_effect=[10.0, 10.0, 10.1, 10.1]):
            waited = []
            acquisition._LAST_REQUEST_BY_HOST.pop("rate-test.example", None)
            acquisition._wait_for_host_rate_limit("rate-test.example", policy, waited.append)
            acquisition._wait_for_host_rate_limit("rate-test.example", policy, waited.append)
        self.assertAlmostEqual(waited[0], 0.9)

    def test_audit_log_is_append_only_minimal_and_never_records_url_query(self):
        with tempfile.TemporaryDirectory() as temp:
            append_audit_event(temp, {"event": "test", "url_sha256": "abc"})
            path = Path(temp) / "logs" / "audit.jsonl"
            before = path.read_bytes()
            append_audit_event(temp, {"event": "second", "artifact_sha256": "def"})
            after = path.read_bytes()
            self.assertTrue(after.startswith(before))
            self.assertEqual(len(after.splitlines()), 2)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(OSError):
                append_audit_event(temp, {"event": "quota"}, max_bytes=len(after))

    def test_http_retries_transient_errors_and_records_network_bytes(self):
        server, thread, state, body = make_local_server()
        try:
            source = eligible_source("retry-source")
            asset = {"asset_id": "retry-asset", "url": f"http://127.0.0.1:{server.server_port}/retry",
                     "format": "jsonl", "max_bytes": 2048, "dataset_purpose": "sft"}
            policy = DownloadPolicy(max_total_bytes=8192, max_raw_storage_bytes=8192, max_single_file_bytes=2048,
                                    max_expanded_bytes=4096, free_disk_reserve_bytes=0, timeout_seconds=2,
                                    max_retries=2, backoff_seconds=0, jitter_seconds=0, allowed_hosts=("127.0.0.1",),
                                    allow_http_local_for_tests=True, min_request_interval_seconds=0)
            with tempfile.TemporaryDirectory() as temp:
                result = acquire_http(source, asset, raw_root=Path(temp) / "data" / "raw", policy=policy,
                                      per_source_quota_bytes=8192, sleep=lambda _delay: None,
                                      random_uniform=lambda _a, _b: 0)
                self.assertEqual(result.attempts, 2)
                self.assertEqual(result.network_bytes_downloaded, len(body))
                self.assertEqual(Path(result.manifest.path).read_bytes(), body)
                events = [json.loads(line) for line in (Path(temp) / "logs" / "audit.jsonl").read_text().splitlines()]
                self.assertEqual([e["event"] for e in events], ["acquisition_started", "acquisition_completed"])
                self.assertEqual(events[-1]["network_bytes_downloaded"], len(body))
                self.assertEqual(state["counts"]["/retry"], 2)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

    def test_http_range_resume_requires_validator_and_verifies_content_range(self):
        server, thread, state, body = make_local_server()
        try:
            source = eligible_source("resume-source")
            asset = {"asset_id": "resume-asset", "url": f"http://127.0.0.1:{server.server_port}/range",
                     "format": "jsonl", "max_bytes": 2048, "dataset_purpose": "sft"}
            policy = DownloadPolicy(max_total_bytes=8192, max_raw_storage_bytes=8192, max_single_file_bytes=2048,
                                    max_expanded_bytes=4096, free_disk_reserve_bytes=0, timeout_seconds=2,
                                    max_retries=1, allowed_hosts=("127.0.0.1",), allow_http_local_for_tests=True,
                                    min_request_interval_seconds=0)
            with tempfile.TemporaryDirectory() as temp:
                raw = Path(temp) / "data" / "raw" / "resume-source"
                raw.mkdir(parents=True)
                target = raw / "resume-asset.jsonl.part"
                target.write_bytes(body[:11])
                meta = raw / "resume-asset.jsonl.part.meta.json"
                meta.write_text(json.dumps({"url_sha256": hashlib.sha256(asset["url"].encode()).hexdigest(),
                                            "asset_id": "resume-asset", "source_revision": None,
                                            "etag": '"v1"', "last_modified": None}), encoding="utf-8")
                result = acquire_http(source, asset, raw_root=Path(temp) / "data" / "raw", policy=policy,
                                      per_source_quota_bytes=8192, sleep=lambda _delay: None,
                                      random_uniform=lambda _a, _b: 0)
                self.assertEqual(Path(result.manifest.path).read_bytes(), body)
                self.assertEqual(result.network_bytes_downloaded, len(body) - 11)
                self.assertEqual(state["requests"][0]["range"], "bytes=11-")
                self.assertEqual(state["requests"][0]["if_range"], '"v1"')
                self.assertFalse(meta.exists())
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

    def test_incomplete_response_retries_without_unbounded_partial_writes(self):
        server, thread, state, body = make_local_server()
        try:
            source = eligible_source("incomplete-source")
            asset = {"asset_id": "incomplete-asset", "url": f"http://127.0.0.1:{server.server_port}/incomplete",
                     "format": "jsonl", "max_bytes": 2048, "dataset_purpose": "sft"}
            policy = DownloadPolicy(max_total_bytes=8192, max_raw_storage_bytes=8192, max_single_file_bytes=2048,
                                    max_expanded_bytes=4096, free_disk_reserve_bytes=0, timeout_seconds=2,
                                    max_retries=3, allowed_hosts=("127.0.0.1",), allow_http_local_for_tests=True,
                                    min_request_interval_seconds=0)
            with tempfile.TemporaryDirectory() as temp:
                result = acquire_http(source, asset, raw_root=Path(temp) / "data" / "raw", policy=policy,
                                      per_source_quota_bytes=8192, sleep=lambda _delay: None,
                                      random_uniform=lambda _a, _b: 0)
                self.assertEqual(Path(result.manifest.path).read_bytes(), body)
                self.assertLessEqual(result.network_bytes_downloaded, 2 * len(body))
                self.assertEqual(state["counts"]["/incomplete"], 2)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

    def test_http_rejects_nonretryable_status_and_honors_bounded_retry_after(self):
        server, thread, state, _body = make_local_server()
        try:
            source = eligible_source("status-source")
            policy = DownloadPolicy(max_total_bytes=8192, max_raw_storage_bytes=8192, max_single_file_bytes=2048,
                                    max_expanded_bytes=4096, free_disk_reserve_bytes=0, timeout_seconds=2,
                                    max_retries=2, allowed_hosts=("127.0.0.1",), allow_http_local_for_tests=True,
                                    min_request_interval_seconds=0)
            with tempfile.TemporaryDirectory() as temp:
                asset = {"asset_id": "not-found", "url": f"http://127.0.0.1:{server.server_port}/not-found",
                         "format": "jsonl", "max_bytes": 2048, "dataset_purpose": "sft"}
                with self.assertRaises(PipelineError) as ctx:
                    acquire_http(source, asset, raw_root=Path(temp) / "data" / "raw", policy=policy,
                                 sleep=lambda _delay: None, random_uniform=lambda _a, _b: 0)
                self.assertEqual(ctx.exception.code, "http_status")
                self.assertEqual(state["counts"]["/not-found"], 1)
                asset["asset_id"] = "retry-after"
                asset["url"] = f"http://127.0.0.1:{server.server_port}/retry-after-too-long"
                with self.assertRaises(PipelineError) as ctx2:
                    acquire_http(source, asset, raw_root=Path(temp) / "data" / "raw", policy=policy,
                                 sleep=lambda _delay: None, random_uniform=lambda _a, _b: 0)
                self.assertEqual(ctx2.exception.code, "retry_after_too_long")
                self.assertEqual(state["counts"]["/retry-after-too-long"], 1)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

    def test_unexpected_html_and_checksum_mismatch_are_quarantined(self):
        server, thread, state, _body = make_local_server()
        try:
            source = eligible_source("quarantine-source")
            policy = DownloadPolicy(max_total_bytes=8192, max_raw_storage_bytes=8192, max_single_file_bytes=2048,
                                    max_expanded_bytes=4096, free_disk_reserve_bytes=0, timeout_seconds=2,
                                    max_retries=0, allowed_hosts=("127.0.0.1",), allow_http_local_for_tests=True,
                                    min_request_interval_seconds=0)
            with tempfile.TemporaryDirectory() as temp:
                for asset_id, route, sha, expected_code in (
                    ("html-response", "/html", None, "unexpected_html"),
                    ("wrong-checksum", "/checksum", "0" * 64, "checksum_mismatch"),
                ):
                    asset = {"asset_id": asset_id, "url": f"http://127.0.0.1:{server.server_port}{route}",
                             "format": "jsonl", "max_bytes": 2048, "dataset_purpose": "sft"}
                    if sha:
                        asset["sha256"] = sha
                    with self.assertRaises(PipelineError) as ctx:
                        acquire_http(source, asset, raw_root=Path(temp) / "data" / "raw", policy=policy,
                                     sleep=lambda _delay: None, random_uniform=lambda _a, _b: 0)
                    self.assertEqual(ctx.exception.code, expected_code)
                    target = Path(temp) / "data" / "raw" / source["source_id"] / f"{asset_id}.jsonl"
                    self.assertFalse(target.exists())
                quarantined = list((Path(temp) / "data" / "quarantine" / source["source_id"]).iterdir())
                self.assertGreaterEqual(len(quarantined), 2)
                audit = (Path(temp) / "logs" / "audit.jsonl").read_text(encoding="utf-8")
                self.assertNotIn("Access denied", audit)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

    def test_http_content_length_cap_redirect_allowlist_and_no_query_secrets(self):
        server, thread, state, _body = make_local_server()
        try:
            source = eligible_source("limits-source")
            policy = DownloadPolicy(max_total_bytes=8192, max_raw_storage_bytes=8192, max_single_file_bytes=128,
                                    max_expanded_bytes=4096, free_disk_reserve_bytes=0, timeout_seconds=2,
                                    max_retries=0, allowed_hosts=("127.0.0.1",), allow_http_local_for_tests=True,
                                    min_request_interval_seconds=0)
            with tempfile.TemporaryDirectory() as temp:
                asset = {"asset_id": "oversized", "url": f"http://127.0.0.1:{server.server_port}/too-large",
                         "format": "jsonl", "max_bytes": 128, "dataset_purpose": "sft"}
                with self.assertRaises(PipelineError) as ctx:
                    acquire_http(source, asset, raw_root=Path(temp) / "data" / "raw", policy=policy,
                                 sleep=lambda _delay: None, random_uniform=lambda _a, _b: 0)
                self.assertEqual(ctx.exception.code, "storage_quota_exceeded")
                self.assertEqual(state["counts"]["/too-large"], 1)
                asset["asset_id"] = "redirect"
                asset["url"] = f"http://127.0.0.1:{server.server_port}/redirect"
                with self.assertRaises(PipelineError) as ctx2:
                    acquire_http(source, asset, raw_root=Path(temp) / "data" / "raw", policy=policy,
                                 sleep=lambda _delay: None, random_uniform=lambda _a, _b: 0)
                self.assertEqual(ctx2.exception.code, "host_not_allowed")
                asset["asset_id"] = "secret-url"
                asset["url"] = f"http://127.0.0.1:{server.server_port}/retry?token=DO_NOT_LOG_THIS_VALUE"
                with self.assertRaises(PipelineError) as ctx3:
                    acquire_http(source, asset, raw_root=Path(temp) / "data" / "raw", policy=policy,
                                 sleep=lambda _delay: None, random_uniform=lambda _a, _b: 0)
                self.assertEqual(ctx3.exception.code, "unsafe_url")
                audit_text = (Path(temp) / "logs" / "audit.jsonl").read_text(encoding="utf-8")
                self.assertNotIn("DO_NOT_LOG_THIS_VALUE", audit_text)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

    def test_unknown_license_is_blocked_before_any_network_request(self):
        server, thread, state, _body = make_local_server()
        try:
            source = eligible_source("blocked-source")
            source["eligibility"] = "NEEDS_REVIEW"
            asset = {"asset_id": "blocked", "url": f"http://127.0.0.1:{server.server_port}/retry",
                     "format": "jsonl", "max_bytes": 1024, "dataset_purpose": "sft"}
            policy = DownloadPolicy(allowed_hosts=("127.0.0.1",), allow_http_local_for_tests=True,
                                    free_disk_reserve_bytes=0, min_request_interval_seconds=0)
            with tempfile.TemporaryDirectory() as temp:
                with self.assertRaises(PipelineError) as ctx:
                    acquire_http(source, asset, raw_root=Path(temp) / "data" / "raw", policy=policy)
                self.assertEqual(ctx.exception.code, "source_not_eligible")
                self.assertEqual(sum(state["counts"].values()), 0)
                events = [json.loads(line) for line in (Path(temp) / "logs" / "audit.jsonl").read_text().splitlines()]
                self.assertEqual(events[-1]["error_code"], "source_not_eligible")
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

    def test_download_quota_counts_and_quarantines_oversized_partial_file(self):
        server, thread, state, _body = make_local_server()
        try:
            source = eligible_source("partial-quota-source")
            asset = {"asset_id": "partial", "url": f"http://127.0.0.1:{server.server_port}/not-found",
                     "format": "jsonl", "max_bytes": 128, "dataset_purpose": "sft"}
            policy = DownloadPolicy(max_total_bytes=4096, max_raw_storage_bytes=4096, max_single_file_bytes=128,
                                    max_expanded_bytes=1024, free_disk_reserve_bytes=0, timeout_seconds=2,
                                    max_retries=0, allowed_hosts=("127.0.0.1",), allow_http_local_for_tests=True,
                                    min_request_interval_seconds=0)
            with tempfile.TemporaryDirectory() as temp:
                raw = Path(temp) / "data" / "raw" / source["source_id"]
                raw.mkdir(parents=True)
                (raw / "partial.jsonl.part").write_bytes(b"P" * 129)
                with self.assertRaises(PipelineError):
                    acquire_http(source, asset, raw_root=Path(temp) / "data" / "raw", policy=policy,
                                 per_source_quota_bytes=4096, sleep=lambda _delay: None)
                quarantined = list((Path(temp) / "data" / "quarantine" / source["source_id"]).iterdir())
                self.assertTrue(any("part" in file.name for file in quarantined))
                self.assertEqual(state["counts"]["/not-found"], 1)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

    def test_local_fixture_copy_is_bounded_and_labeled(self):
        source = {"source_id": "local-fixture", "source_type": "local_fixture", "eligibility": "APPROVED"}
        with tempfile.TemporaryDirectory() as temp:
            source_path = Path(temp) / "fixture.jsonl"
            source_path.write_text('{"text":"A sufficiently long fixture record for validating local acquisition."}\n', encoding="utf-8")
            result = acquire_fixture(source, {"asset_id": "fixture-one", "format": "jsonl"},
                                     fixture_path=source_path, raw_root=Path(temp) / "data" / "raw", max_bytes=1024)
            self.assertTrue(result.manifest.fixture_only)
            self.assertEqual(result.network_bytes_downloaded, 0)
            self.assertTrue(Path(result.manifest.path).exists())

    def test_fixture_only_pipeline_runs_end_to_end_without_network(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            shutil.copytree(ROOT / "config", root / "config")
            shutil.copytree(ROOT / "tests" / "fixtures", root / "tests" / "fixtures")
            with patch("urllib.request.build_opener", side_effect=AssertionError("network must not be used")):
                report = run_fixture_smoke(root)
            self.assertTrue(report["fixture_only"])
            self.assertTrue(report["end_to_end_valid"])
            self.assertEqual(report["measurements"]["downloaded_bytes"], 0)
            self.assertEqual(report["measurements"]["network_bytes_transferred"], 0)
            self.assertEqual(report["measurements"]["source_records_scanned"], 10)
            self.assertEqual(report["measurements"]["selected_records_emitted"], 10)
            self.assertGreater(report["measurements"]["published_records"], 0)
            self.assertGreater(report["measurements"]["exact_duplicate_records"], 0)
            self.assertGreater(report["measurements"]["quarantined_records"], 0)
            self.assertTrue(verify_release(report["release_path"])["valid"])
            events = [json.loads(line) for line in (root / "logs" / "audit.jsonl").read_text().splitlines()]
            self.assertEqual([e["event"] for e in events], ["pipeline_run_started", "pipeline_run_completed"])
            self.assertTrue(all(e["fixture_only"] for e in events))
            run_manifest = json.loads(Path(report["run_manifest_path"]).read_text(encoding="utf-8"))
            self.assertEqual(run_manifest["release_verification"]["valid"], True)


if __name__ == "__main__":
    unittest.main()
