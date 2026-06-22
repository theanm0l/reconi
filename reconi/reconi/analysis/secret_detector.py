"""Regex-based secret detection with entropy scoring."""

import math
import re
from collections import Counter
from typing import Any

from ..core.celery_app import celery_app
from ..core.database import SessionLocal, Finding as DBFinding, ReconJob
from ..core.plugin import Finding

_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "github_token_classic"),
    (re.compile(r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}"), "github_token_fine_grained"),
    (re.compile(r"sk_live_[a-zA-Z0-9]{24}"), "stripe_live_key"),
    (re.compile(r"pk_live_[a-zA-Z0-9]{24}"), "stripe_publishable_key"),
    (re.compile(r"rk_live_[a-zA-Z0-9]{24}"), "stripe_restricted_key"),
    (re.compile(r"sk_test_[a-zA-Z0-9]{24}"), "stripe_test_key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key"),
    (re.compile(r"(?:AWS|aws)?[\W_]*secret[\W_]*[:=]?\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"), "aws_secret_key"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "google_api_key"),
    (re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"), "google_oauth_client_id"),
    (re.compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"), "slack_bot_token"),
    (re.compile(r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"), "slack_user_token"),
    (re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,10}/B[a-zA-Z0-9_]{8,10}/[a-zA-Z0-9_]{24}"), "slack_webhook"),
    (re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9\-_]{60,68}"), "discord_webhook"),
    (re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"), "jwt_token"),
    (re.compile(r"-{5}BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-{5}"), "private_key_pem"),
    (re.compile(r"(?i)(?:(?:api|key|secret|token|auth|password|passwd|pwd)[_-]?(?:key|token|secret)?)\s*[:=]\s*[\"'][a-zA-Z0-9_\-.]{20,}[\"']"), "generic_api_key"),
    (re.compile(r"(?i)(?:(?:mysql|postgres(?:ql)?|mongodb|redis|sqlite|oracle|mssql)://[^\s\"']+)"), "database_url"),
    (re.compile(r"SMTP_(?:HOST|PORT|USER|PASS|PASSWORD)\s*=\s*[^\n]+"), "smtp_config"),
    (re.compile(r"sk-[a-zA-Z0-9]{48}"), "openai_standard_key"),
    (re.compile(r"sk-proj-[a-zA-Z0-9_-]{156}"), "openai_project_key"),
    (re.compile(r"[a-f0-9]{32}-us[0-9]{1,2}"), "mailchimp_api_key"),
    (re.compile(r"[0-9]+:[a-zA-Z0-9_-]{35}"), "telegram_bot_token"),
    (re.compile(r"SK[0-9a-fA-F]{32}"), "twilio_sid"),
    (re.compile(r"sq0atp-[0-9A-Za-z\-_]{22}"), "square_access_token"),
    (re.compile(r"sq0csp-[0-9A-Za-z\-_]{43}"), "square_personal_token"),
    (re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"), "paypal_access_token"),
    (re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "heroku_api_key"),
]

ENTROPY_THRESHOLD = 3.5

COMMON_FALSE_POSITIVES = re.compile(
    r"(?i)(example|test|sample|placeholder|your[-_]?key|changeme|TODO|FIXME|xxxx+|12345+|fake)",
)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def detect_secrets(text: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for pattern, name in _PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            start = match.start()
            end = match.end()
            ent = entropy(value)
            if ent < ENTROPY_THRESHOLD:
                continue
            if COMMON_FALSE_POSITIVES.search(value):
                continue
            results.append({
                "pattern_name": name,
                "value": value,
                "start": start,
                "end": end,
                "entropy": round(ent, 4),
            })
    return results


def extract_secrets_from_findings(findings: list[Finding]) -> list[Finding]:
    secret_findings: list[Finding] = []
    seen = set()

    for f in findings:
        text_to_scan = f.value or ""
        if f.context:
            text_to_scan += "\n" + f.context

        detected = detect_secrets(text_to_scan)
        for secret in detected:
            dedup_key = (secret["pattern_name"], secret["value"])
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            secret_findings.append(Finding(
                source=f"secret_detector:{secret['pattern_name']}",
                type="secret",
                value=secret["value"],
                context=f"Detected in {f.source}: {f.context[:200] if f.context else f.value[:200]}",
                url_found_on=f.url_found_on,
                severity=_infer_severity(secret["pattern_name"]),
                confidence=min(0.95, max(0.4, secret["entropy"] / 6.0)),
                raw={
                    "original_source": f.source,
                    "original_type": f.type,
                    "entropy": secret["entropy"],
                    "pattern": secret["pattern_name"],
                    "position": {"start": secret["start"], "end": secret["end"]},
                },
            ))

    return secret_findings


CRITICAL_PATTERNS = {
    "aws_access_key", "aws_secret_key", "stripe_live_key", "stripe_restricted_key",
    "private_key_pem", "paypal_access_token", "slack_bot_token", "slack_user_token",
    "discord_webhook",
}
HIGH_PATTERNS = {
    "github_token_classic", "github_token_fine_grained", "google_api_key",
    "openai_standard_key", "openai_project_key", "database_url", "telegram_bot_token",
    "twilio_sid",
}
MEDIUM_PATTERNS = {
    "slack_webhook", "square_access_token", "square_personal_token",
    "mailchimp_api_key", "heroku_api_key", "smtp_config",
}


def _infer_severity(pattern_name: str) -> str:
    if pattern_name in CRITICAL_PATTERNS:
        return "critical"
    if pattern_name in HIGH_PATTERNS:
        return "high"
    if pattern_name in MEDIUM_PATTERNS:
        return "medium"
    return "low"


@celery_app.task(name="analysis.detect_secrets_batch")
def detect_secrets_batch(job_id: str, findings_raw: list[dict]) -> list[dict]:
    db = SessionLocal()
    try:
        findings = [Finding(
            source=f.get("source", "unknown"),
            type=f.get("type", "unknown"),
            value=f.get("value", ""),
            context=f.get("context"),
            url_found_on=f.get("url_found_on"),
            severity=f.get("severity", "info"),
            confidence=f.get("confidence", 0.0),
            raw=f.get("raw"),
            found_at=f.get("found_at", ""),
        ) for f in findings_raw]

        secrets = extract_secrets_from_findings(findings)
        for s in secrets:
            db_finding = DBFinding(
                target_id="",
                job_id=job_id,
                source=s.source,
                type=s.type,
                value=s.value,
                context=s.context,
                url_found_on=s.url_found_on,
                confidence=s.confidence,
                severity=s.severity,
                raw_json=s.raw,
            )
            db.add(db_finding)
        db.commit()
        return [{
            "source": s.source,
            "type": s.type,
            "value": s.value,
            "context": s.context,
            "severity": s.severity,
            "confidence": s.confidence,
            "raw": s.raw,
        } for s in secrets]
    except Exception as e:
        db.rollback()
        return [{"error": str(e)}]
    finally:
        db.close()
