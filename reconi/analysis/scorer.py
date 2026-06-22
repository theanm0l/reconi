"""Confidence scoring algorithm for findings."""

import logging
import re
from typing import Any

from ..core.celery_app import celery_app
from ..core.database import SessionLocal, Finding as DBFinding, ReconJob
from ..core.plugin import Finding

logger = logging.getLogger(__name__)

BASE_SCORES: dict[str, dict[str, float]] = {
    "url_discovery": {"min": 40, "max": 60},
    "dorking": {"min": 50, "max": 70},
    "code_mining": {"min": 60, "max": 80},
    "leaks": {"min": 70, "max": 90},
    "js_analysis": {"min": 50, "max": 70},
    "dns_infra": {"min": 60, "max": 80},
    "api_discovery": {"min": 40, "max": 65},
    "osint": {"min": 45, "max": 70},
}

_source_reliability: dict[str, float] = {
    "wayback": 0.7, "waybackurls": 0.7, "gau": 0.65, "gauplus": 0.65,
    "commoncrawl": 0.6, "urlscan": 0.55, "alienvault": 0.55,
    "virustotal": 0.6, "crtsh": 0.75, "certspotter": 0.7,
    "hackertarget": 0.55, "google": 0.7, "bing": 0.65,
    "duckduckgo": 0.6, "github_code": 0.8, "github_gists": 0.75,
    "github_repos": 0.85, "github_commits": 0.8, "github_issues": 0.75,
    "gitlab": 0.7, "shodan_query": 0.8, "shodan": 0.8,
    "publicwww": 0.65, "nerdydata": 0.55, "pastebin": 0.7,
    "postman_api": 0.8, "postman_explore": 0.8, "swaggerhub": 0.75,
    "apis_guru": 0.7, "dehashed": 0.9, "intelx": 0.85,
    "leakcheck": 0.75, "haveibeenpwned": 0.8, "snusbase": 0.85,
}

FALSE_POSITIVE_PATTERNS = re.compile(
    r"(?i)(example|test|sample|demo|placeholder|fake|dummy|xxxx|TODO|FIXME|changeme|your.?key|your.?token|localhost|127\.0\.0\.1)",
)

PLACEHOLDER_PATTERNS = re.compile(
    r"(?i)(<.*>|\{\{.*\}\}|\$\{.*\}|\[.*\])",
)

TEST_CONTEXT_PATTERNS = re.compile(
    r"(?i)(\btest\b|\bdev\b|\bstaging\b|\blocal\b|\bmock\b|\bfixture\b)",
)


def _get_source_reliability(source: str) -> float:
    source_lower = source.lower()
    for key, rel in _source_reliability.items():
        if key in source_lower:
            return rel
    if "secret_detector" in source_lower:
        return 0.85
    return 0.5


def _get_category_from_source(source: str) -> str:
    source_lower = source.lower()
    category_map = {
        "url_discovery": ["wayback", "gau", "commoncrawl", "urlscan", "alienvault", "crtsh", "certspotter", "hackertarget", "virustotal"],
        "dorking": ["google", "bing", "duckduckgo", "github_code", "github_gists", "gitlab", "shodan_query", "publicwww", "nerdydata"],
        "code_mining": ["github_repos", "github_commits", "github_issues", "pastebin"],
        "api_discovery": ["postman", "swaggerhub", "apis_guru", "graphql"],
        "js_analysis": ["endpoints", "sourcemaps", "webpack", "firebase", "s3_buckets", "config_files"],
        "dns_infra": ["whois", "reverse_ip", "asn", "spf", "dmarc", "cname"],
        "leaks": ["dehashed", "intelx", "leakcheck", "haveibeenpwned", "snusbase"],
        "osint": ["reddit", "trello"],
    }
    for category, keywords in category_map.items():
        for kw in keywords:
            if kw in source_lower:
                return category
    return "url_discovery"


def score_finding(finding: dict) -> float:
    source = finding.get("source", "")
    finding_type = finding.get("type", finding.get("ai_type", ""))
    finding_severity = finding.get("severity", finding.get("ai_severity", "info"))
    context = finding.get("context", "") or ""
    value = finding.get("value", "")

    category = _get_category_from_source(source)
    base_range = BASE_SCORES.get(category, {"min": 40, "max": 60})
    reliability = _get_source_reliability(source)

    base = base_range["min"] + (base_range["max"] - base_range["min"]) * reliability
    score = base

    severity_boost = {"critical": 20, "high": 15, "medium": 10, "low": 5, "info": 0}
    score += severity_boost.get(finding_severity, 0)

    ai_adjustment = finding.get("ai_confidence_adjustment", 0.0)
    if isinstance(ai_adjustment, (int, float)):
        score += ai_adjustment * 20

    validation = finding.get("_validation", {}) or {}
    if validation.get("is_valid"):
        score += validation.get("confidence_boost", 0.0) * 25

    cluster_size = finding.get("_cluster_size", 1)
    if cluster_size > 1:
        score += min(10, cluster_size * 2)

    entropy_val = finding.get("raw", {}) or {}
    entropy = entropy_val.get("entropy", 0.0) if isinstance(entropy_val, dict) else 0.0
    if entropy > 4.0:
        score += 10
    elif entropy > 3.5:
        score += 5

    if finding.get("correlation_groups"):
        score += 5

    text = f"{value} {context}"
    if FALSE_POSITIVE_PATTERNS.search(text):
        score -= 15

    if PLACEHOLDER_PATTERNS.search(value):
        score -= 10

    if TEST_CONTEXT_PATTERNS.search(context):
        score -= 5

    if not value or len(value) < 4:
        score -= 20

    return max(0.0, min(100.0, score))


@celery_app.task(name="analysis.score_findings_batch")
def score_findings_batch(job_id: str, findings_raw: list[dict]) -> list[dict]:
    db = SessionLocal()
    try:
        for f in findings_raw:
            score = score_finding(f)
            f["confidence"] = round(score, 2)
            f["severity"] = f.get("severity", f.get("ai_severity", "info"))
            if score >= 85:
                f["severity"] = "critical"
            elif score >= 65:
                f["severity"] = "high"
            elif score >= 45:
                f["severity"] = "medium"
            elif score >= 25:
                f["severity"] = "low"
            else:
                f["severity"] = "info"

            finding_id = f.get("id") or f.get("_db_id")
            if finding_id and db:
                db_finding = db.query(DBFinding).filter(DBFinding.id == finding_id).first()
                if db_finding:
                    db_finding.confidence = score
                    db_finding.severity = f["severity"]
                    db_finding.cwe_id = f.get("cwe_id")
                    db_finding.ai_summary = f.get("_classification_reasoning", "")[:500]
        if db:
            db.commit()
        return findings_raw
    except Exception as e:
        db.rollback()
        logger.error("Scoring error: %s", e)
        return findings_raw
    finally:
        db.close()
