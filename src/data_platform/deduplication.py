"""Exact and word-shingle near-duplicate detection with reversible decisions."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable

from .models import NormalizedRecord

_TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)


@dataclass(frozen=True)
class DuplicateDecision:
    record_id: str
    cluster_id: str
    retained_record_id: str
    method: str
    similarity: float
    retained: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "cluster_id": self.cluster_id,
            "retained_record_id": self.retained_record_id,
            "method": self.method,
            "similarity": self.similarity,
            "retained": self.retained,
            "reason": self.reason,
        }


def duplicate_normalize(text: str) -> str:
    """Canonical Unicode/line-ending form; do not erase case or formatting."""
    return unicodedata.normalize("NFC", text.replace("\r\n", "\n").replace("\r", "\n"))


def shingles(text: str, size: int = 5) -> frozenset[tuple[str, ...]]:
    tokens = _TOKEN_RE.findall(duplicate_normalize(text).casefold())
    if not tokens:
        return frozenset()
    if len(tokens) < size:
        return frozenset({tuple(tokens)})
    return frozenset(tuple(tokens[i:i + size]) for i in range(len(tokens) - size + 1))


def jaccard(left: frozenset[Any], right: frozenset[Any]) -> float:
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def benchmark_near_duplicate_detector(labels: Iterable[tuple[str, str, bool]], *, threshold: float = 0.75,
                                       shingle_size: int = 5) -> dict[str, Any]:
    """Measure the exact deployed detector on explicitly labeled text pairs."""
    tp = fp = tn = fn = 0
    for left, right, is_duplicate in labels:
        predicted = jaccard(shingles(left, shingle_size), shingles(right, shingle_size)) >= threshold
        if predicted and is_duplicate:
            tp += 1
        elif predicted:
            fp += 1
        elif is_duplicate:
            fn += 1
        else:
            tn += 1
    n = tp + fp + tn + fn
    return {
        "method": "word-shingle Jaccard (not semantic similarity)",
        "threshold": threshold,
        "shingle_size": shingle_size,
        "labeled_pairs": n,
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "false_negative_rate": fn / (fn + tp) if fn + tp else None,
    }


def deduplicate(records: list[NormalizedRecord], *, threshold: float = 0.75, shingle_size: int = 5,
                qualities: dict[str, str] | None = None) -> tuple[list[NormalizedRecord], list[DuplicateDecision]]:
    """Cluster records by exact content first, then near-duplicate Jaccard.

    Pairwise comparison is intentionally O(n^2), avoiding hidden state or an
    unbenchmarked LSH dependency. It is appropriate for bounded pilot batches;
    large corpora should use a separately benchmarked indexed backend.
    """
    if not 0 < threshold <= 1:
        raise ValueError("threshold must be in (0, 1]")
    count = len(records)
    parents = list(range(count))

    def find(item: int) -> int:
        while parents[item] != item:
            parents[item] = parents[parents[item]]
            item = parents[item]
        return item

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parents[max(ra, rb)] = min(ra, rb)

    hashes: dict[str, list[int]] = defaultdict(list)
    for index, record in enumerate(records):
        hashes[record.content_hash].append(index)
    pairs: dict[tuple[int, int], tuple[str, float]] = {}
    for group in hashes.values():
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                left, right = sorted((group[i], group[j]))
                pairs[(left, right)] = ("exact", 1.0)
                union(left, right)
    vectors = [shingles(r.text, shingle_size) for r in records]
    code_tasks = {"programming", "programming_reference"}
    for i in range(count):
        for j in range(i + 1, count):
            if find(i) == find(j):
                continue
            if records[i].task_type != records[j].task_type or records[i].language != records[j].language:
                continue
            if records[i].task_type in code_tasks:
                continue  # code punctuation, identifiers and indentation are semantically important
            similarity = jaccard(vectors[i], vectors[j])
            if similarity >= threshold:
                pairs[(i, j)] = ("near_duplicate_word_shingle_jaccard", similarity)
                union(i, j)
    clusters: dict[int, list[int]] = defaultdict(list)
    for index in range(count):
        clusters[find(index)].append(index)
    quality_order = {"ACCEPT": 4, "ACCEPT_WITH_WARNINGS": 3, "NEEDS_HUMAN_REVIEW": 2,
                     "QUARANTINE": 1, "REJECT": 0}
    decisions: list[DuplicateDecision] = []
    retained: list[NormalizedRecord] = []
    for indices in sorted(clusters.values(), key=lambda ids: min(records[i].record_id for i in ids)):
        ranked = sorted(indices, key=lambda i: (
            -quality_order.get((qualities or {}).get(records[i].record_id, "NEEDS_HUMAN_REVIEW"), 0),
            records[i].source_id, records[i].record_id,
        ))
        keeper = ranked[0]
        cluster_id = "dup-" + hashlib.sha256(
            "\0".join(sorted(records[i].record_id for i in indices)).encode("utf-8")
        ).hexdigest()[:16]
        retained.append(records[keeper])
        for index in sorted(indices, key=lambda i: records[i].record_id):
            if index == keeper:
                decisions.append(DuplicateDecision(records[index].record_id, cluster_id,
                    records[keeper].record_id, "unique", 1.0, True, "highest-ranked record in cluster"))
                continue
            left, right = sorted((index, keeper))
            method, similarity = pairs.get((left, right), ("transitive_cluster", 0.0))
            decisions.append(DuplicateDecision(records[index].record_id, cluster_id,
                records[keeper].record_id, method, similarity, False,
                "duplicate retained in audit decisions; source provenance is unchanged"))
    retained.sort(key=lambda r: r.record_id)
    decisions.sort(key=lambda d: d.record_id)
    return retained, decisions
