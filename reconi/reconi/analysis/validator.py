"""Live API key and endpoint validation for findings."""

import asyncio
import logging
import re
from typing import Any

import httpx

from ..core.celery_app import celery_app
from ..core.config import settings
from ..core.database import SessionLocal, Finding as DBFinding, ReconJob, ValidationResult
from ..core.plugin import Finding

logger = logging.getLogger(__name__)

AWS_ACCESS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
GITHUB_TOKEN_RE = re.compile(r"ghp_[a-zA-Z0-9]{36}")
STRIPE_LIVE_RE = re.compile(r"sk_live_[a-zA-Z0-9]{24}")
STRIPE_TEST_RE = re.compile(r"sk_test_[a-zA-Z0-9]{24}")
GOOGLE_API_RE = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
SLACK_BOT_RE = re.compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}")
URL_RE = re.compile(r"https?://[^\s\"'<>]+")


async def validate_github_token(token: str) -> dict[str, Any]:
    timeout = settings.config.validation.max_validation_timeout
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
        resp = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.v3+json",
            },
        )
        if resp.status_code == 200:
            scopes = resp.headers.get("X-OAuth-Scopes", "")
            return {"is_valid": True, "detail": f"Valid GitHub token — scopes: {scopes}", "confidence_boost": 0.3}
        if resp.status_code == 401:
            return {"is_valid": False, "detail": "Invalid/expired GitHub token", "confidence_boost": -0.2}
        return {"is_valid": False, "detail": f"GitHub API returned {resp.status_code}", "confidence_boost": -0.1}


async def validate_stripe_key(key: str) -> dict[str, Any]:
    timeout = settings.config.validation.max_validation_timeout
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
        resp = await client.get(
            "https://api.stripe.com/v1/charges",
            auth=(key, ""),
            params={"limit": 1},
        )
        if resp.status_code == 200:
            return {"is_valid": True, "detail": "Valid Stripe key — access confirmed", "confidence_boost": 0.3}
        if resp.status_code == 401:
            return {"is_valid": False, "detail": "Invalid/revoked Stripe key", "confidence_boost": -0.2}
        if resp.status_code == 403:
            return {"is_valid": True, "detail": "Stripe key valid but insufficient permissions", "confidence_boost": 0.15}
        return {"is_valid": False, "detail": f"Stripe API returned {resp.status_code}", "confidence_boost": -0.1}


async def validate_aws_key(access_key: str, secret_key: str | None = None) -> dict[str, Any]:
    if not secret_key:
        return {"is_valid": False, "detail": "AWS secret key required for validation", "confidence_boost": 0.0}
    timeout = settings.config.validation.max_validation_timeout
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
        body = "Action=GetCallerIdentity&Version=2011-06-15"
        resp = await client.post(
            "https://sts.amazonaws.com/",
            content=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"AWS4-HMAC-SHA256 Credential={access_key}/...",
            },
        )
        if resp.status_code == 200:
            return {"is_valid": True, "detail": "AWS credentials valid — STS call succeeded", "confidence_boost": 0.35}
        if resp.status_code in (403, 400):
            return {"is_valid": False, "detail": "AWS credentials invalid or insufficient permissions", "confidence_boost": -0.2}
        return {"is_valid": False, "detail": f"AWS STS returned {resp.status_code}", "confidence_boost": -0.1}


async def validate_google_api(key: str) -> dict[str, Any]:
    timeout = settings.config.validation.max_validation_timeout
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
        resp = await client.get(
            "https://www.googleapis.com/oauth2/v1/tokeninfo",
            params={"access_token": key},
        )
        if resp.status_code == 200:
            data = resp.json()
            return {"is_valid": True, "detail": f"Valid Google API key — scope info: {data}", "confidence_boost": 0.3}
        if resp.status_code == 400:
            return {"is_valid": False, "detail": "Invalid Google API key", "confidence_boost": -0.2}
        return {"is_valid": False, "detail": f"Google API returned {resp.status_code}", "confidence_boost": -0.1}


async def validate_slack_token(token: str) -> dict[str, Any]:
    timeout = settings.config.validation.max_validation_timeout
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
        resp = await client.get(
            "https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("ok"):
                return {"is_valid": True, "detail": f"Valid Slack token — team: {data.get('team', 'unknown')}", "confidence_boost": 0.3}
            return {"is_valid": False, "detail": f"Invalid Slack token: {data.get('error', 'unknown')}", "confidence_boost": -0.2}
        return {"is_valid": False, "detail": f"Slack API returned {resp.status_code}", "confidence_boost": -0.1}


async def validate_generic_endpoint(url: str) -> dict[str, Any]:
    timeout = settings.config.validation.max_validation_timeout
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
        try:
            resp = await client.head(url, follow_redirects=True)
            return {
                "is_valid": True,
                "detail": f"Endpoint reachable — status {resp.status_code}",
                "confidence_boost": 0.1,
            }
        except httpx.TimeoutException:
            return {"is_valid": False, "detail": "Endpoint timed out", "confidence_boost": -0.05}
        except Exception as e:
            return {"is_valid": False, "detail": f"Endpoint unreachable: {e}", "confidence_boost": -0.1}


async def validate_email(email: str) -> bool:
    timeout = settings.config.validation.max_validation_timeout
    domain = email.rsplit("@", 1)[-1]
    dns_servers = ["1.1.1.1", "8.8.8.8"]
    for dns in dns_servers:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
            try:
                resp = await client.get(
                    f"https://cloudflare-dns.com/dns-query",
                    params={"name": domain, "type": "MX"},
                    headers={"Accept": "application/dns-json"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if not data.get("Answer"):
                        return False
                    return True
            except Exception:
                continue
    return False


VALIDATOR_ROUTES = [
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "github_token", validate_github_token),
    (re.compile(r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}"), "github_token", validate_github_token),
    (re.compile(r"sk_live_[a-zA-Z0-9]{24}"), "stripe_key", validate_stripe_key),
    (re.compile(r"sk_test_[a-zA-Z0-9]{24}"), "stripe_key", validate_stripe_key),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_key", None),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "google_api", validate_google_api),
    (re.compile(r"xox[baprs]-[0-9]+-[0-9]+-[a-zA-Z0-9]+"), "slack_token", validate_slack_token),
    (re.compile(r"https?://[^\s\"'<>]+"), "endpoint", validate_generic_endpoint),
]


async def run_validation(finding: dict) -> dict[str, Any]:
    if not settings.config.validation.live_api_test:
        return {"is_valid": False, "detail": "Live validation disabled in config", "confidence_boost": 0.0}

    value = finding.get("value", "")
    finding_type = finding.get("type", finding.get("ai_type", ""))
    risky_apis = settings.config.validation.risky_apis

    if finding_type == "email":
        try:
            valid = await validate_email(value)
            if valid:
                return {"is_valid": True, "detail": "Email domain has MX records", "confidence_boost": 0.15}
            return {"is_valid": False, "detail": "No MX records for email domain", "confidence_boost": -0.1}
        except Exception as e:
            return {"is_valid": False, "detail": f"Email validation error: {e}", "confidence_boost": 0.0}

    for pattern, route_name, validator_fn in VALIDATOR_ROUTES:
        if pattern.search(value):
            if route_name in risky_apis:
                return {"is_valid": False, "detail": f"Validation for {route_name} disabled (risky API)", "confidence_boost": 0.0}
            if validator_fn is None:
                return {"is_valid": False, "detail": f"No validator available for {route_name} without secret key", "confidence_boost": 0.0}
            try:
                if route_name == "aws_key":
                    raw = finding.get("raw", {}) or {}
                    secret_key = raw.get("aws_secret_key") or finding.get("_aws_secret", "")
                    result = await validate_aws_key(value, secret_key if secret_key else None)
                else:
                    result = await validator_fn(value)
                return result
            except Exception as e:
                logger.error("Validation error for %s: %s", value[:20], e)
                return {"is_valid": False, "detail": f"Validation error: {e}", "confidence_boost": 0.0}

    return {"is_valid": False, "detail": "No applicable validator found", "confidence_boost": 0.0}


@celery_app.task(name="analysis.run_validation_batch")
def run_validation_batch(job_id: str, findings_raw: list[dict]) -> list[dict]:
    db = SessionLocal()
    results: list[dict] = []

    async def _run():
        nonlocal results
        for f_raw in findings_raw:
            validation = await run_validation(f_raw)
            f_raw["_validation"] = validation
            results.append(f_raw)

            finding_id = f_raw.get("id") or f_raw.get("_db_id")
            if finding_id and db:
                val_result = ValidationResult(
                    finding_id=finding_id,
                    validator="live_api" if validation["is_valid"] else "none",
                    result="valid" if validation["is_valid"] else "invalid",
                    detail=validation.get("detail", ""),
                )
                db.add(val_result)

                if validation["is_valid"]:
                    db_finding = db.query(DBFinding).filter(DBFinding.id == finding_id).first()
                    if db_finding:
                        db_finding.is_validated = True
                        db_finding.confidence = min(1.0, db_finding.confidence + validation.get("confidence_boost", 0.0))
        if db:
            db.commit()

    asyncio.run(_run())

    try:
        db.close()
    except Exception:
        pass

    return results
