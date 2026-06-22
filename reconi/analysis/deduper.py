"""Deduplication using SimHash and edit distance clustering."""

import hashlib
import logging
from typing import Any

from ..core.celery_app import celery_app
from ..core.database import SessionLocal, Finding as DBFinding, FindingCluster, ReconJob
from ..core.plugin import Finding

logger = logging.getLogger(__name__)

SIMHASH_BITS = 64
HAMMING_THRESHOLD = 8


def simhash(text: str) -> int:
    features = _tokenize(text)
    vector = [0] * SIMHASH_BITS

    for feature in features:
        h = int(hashlib.md5(feature.encode("utf-8", errors="replace")).hexdigest(), 16)
        for i in range(SIMHASH_BITS):
            if (h >> i) & 1:
                vector[i] += 1
            else:
                vector[i] -= 1

    result = 0
    for i in range(SIMHASH_BITS):
        if vector[i] > 0:
            result |= (1 << i)

    return result & ((1 << SIMHASH_BITS) - 1)


def hamming_distance(a: int, b: int) -> int:
    x = a ^ b
    return x.bit_count()


def _tokenize(text: str) -> list[str]:
    text = text.lower()
    tokens: list[str] = []
    current = ""
    for ch in text:
        if ch.isalnum() or ch in "_-.":
            current += ch
        else:
            if current:
                tokens.append(current)
                current = ""
    if current:
        tokens.append(current)
    if not tokens:
        tokens = [text]
    shingles = set()
    for i in range(len(tokens)):
        for size in (2, 3):
            if i + size <= len(tokens):
                shingles.add(" ".join(tokens[i:i + size]))
    return list(shingles) if shingles else tokens


def _finding_to_text(f: dict) -> str:
    parts = [
        f.get("type", ""),
        f.get("ai_type", ""),
        f.get("value", ""),
        f.get("context", "") or "",
    ]
    return " ".join(p for p in parts if p)


def cluster_findings(findings: list[dict]) -> list[list[dict]]:
    if not findings:
        return []

    hashes = [(i, simhash(_finding_to_text(f))) for i, f in enumerate(findings)]
    hashes.sort(key=lambda x: x[0])

    parent = list(range(len(findings)))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: int, y: int):
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[ry] = rx

    for i in range(len(hashes)):
        for j in range(i + 1, len(hashes)):
            dist = hamming_distance(hashes[i][1], hashes[j][1])
            if dist <= HAMMING_THRESHOLD:
                union(hashes[i][0], hashes[j][0])

    clusters: dict[int, list[dict]] = {}
    for i, f in enumerate(findings):
        root = find(i)
        clusters.setdefault(root, []).append(f)

    return list(clusters.values())


def deduplicate_findings_data(findings: list[dict]) -> list[dict]:
    clusters = cluster_findings(findings)
    deduped: list[dict] = []
    for cluster in clusters:
        cluster.sort(key=lambda f: f.get("confidence", 0.0), reverse=True)
        representative = cluster[0]
        representative["_cluster_size"] = len(cluster)
        representative["_cluster_members"] = [c.get("value", "")[:80] for c in cluster]
        deduped.append(representative)
    return deduped


@celery_app.task(name="analysis.deduplicate_findings")
def deduplicate_findings(job_id: str, findings_raw: list[dict]) -> list[dict]:
    db = SessionLocal()
    try:
        deduped = deduplicate_findings_data(findings_raw)

        for d in deduped:
            cluster_size = d.get("_cluster_size", 1)
            if cluster_size > 1:
                representative_id = d.get("id") or d.get("_db_id")
                if representative_id:
                    cluster = FindingCluster(
                        representative_id=representative_id,
                        members=[c.get("value", "")[:200] for c in d.get("_cluster_members", [])],
                        simhash=str(simhash(_finding_to_text(d))),
                    )
                    db.add(cluster)
        db.commit()

        return deduped
    except Exception as e:
        db.rollback()
        logger.error("Deduplication error: %s", e)
        return findings_raw
    finally:
        db.close()
