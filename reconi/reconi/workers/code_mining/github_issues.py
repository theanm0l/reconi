"""GitHub issue/PR search — scan for exposed credentials, debug info, internal URLs."""
import asyncio
import os
import re
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule

_CREDENTIAL_PATTERNS = [
    (re.compile(r'(?i)(?:password|passwd|pwd|secret|token|apikey|api_key|auth\w*)\s*[:=]\s*["\']?([^\s"\'<>]{6,})'), "exposed_credential"),
    (re.compile(r'(?i)(?:login|username|user)\s*[:=]\s*["\']?([^\s"\'<>]{4,})'), "exposed_username"),
    (re.compile(r'(?i)https?://(?!github\.com)[^\s<>"\'{}|\\^`\[\]]*(?:admin|test|staging|dev|internal|localhost|127\.0\.0\.1)[^\s<>"\'{}|\\^`\[\]]*'), "internal_url"),
    (re.compile(r'(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|jdbc)://[^\s<>"\'{}|\\^`\[\]]+'), "db_connection_string"),
    (re.compile(r'(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), "email_address"),
    (re.compile(r'(?i)debug\s*[:=]\s*true'), "debug_enabled"),
    (re.compile(r'(?i)-----BEGIN\s(?:RSA|DSA|EC|OPENSSH|PGP)?\s?PRIVATE\s?KEY'), "private_key"),
]


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
        return netloc
    return target.split(":")[0].split("/")[0]


class GithubIssuesModule(ReconModule):
    name = "github_issues"
    category = "code_mining"
    description = "Search GitHub issues and PRs for exposed credentials and internal URLs"
    requires_api_key = True
    rate_limit_delay = 1.0

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        token = os.getenv("GITHUB_TOKEN", "")
        if not token:
            findings.append(Finding(source=self.name, type="error", value="GITHUB_TOKEN not set", severity="info", confidence=0.0))
            return findings

        domain = _extract_domain(target)
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"}

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(60), headers=headers) as client:
                search_url = f"https://api.github.com/search/issues?q={domain}&per_page=100"
                resp = await client.get(search_url)
                resp.raise_for_status()
                data = resp.json()
                items = data.get("items", [])

            for issue in items[:50]:
                await asyncio.sleep(0.5)
                title = issue.get("title", "")
                body = issue.get("body") or ""
                issue_url = issue.get("html_url", "")
                state = issue.get("state", "")
                combined = f"{title}\n{body}"

                found_any = False
                for pattern, label in _CREDENTIAL_PATTERNS:
                    match = pattern.search(combined)
                    if match:
                        found_any = True
                        findings.append(Finding(
                            source=self.name,
                            type="issue",
                            value=issue_url,
                            context=f"[{state}] {title[:120]}",
                            url_found_on=search_url,
                            severity="high" if label in ("exposed_credential", "private_key", "db_connection_string") else "medium",
                            confidence=0.7,
                            raw={"state": state, "detected": label, "snippet": (match.group(0)[:100] if match else "")},
                        ))

                if not found_any and title:
                    findings.append(Finding(
                        source=self.name,
                        type="issue",
                        value=issue_url,
                        context=f"[{state}] {title[:120]}",
                        url_found_on=search_url,
                        severity="info",
                        confidence=0.3,
                        raw={"state": state, "body_snippet": body[:200] if body else ""},
                    ))

        except Exception as e:
            findings.append(Finding(source=self.name, type="error", value=str(e), severity="info", confidence=0.0))

        return findings


@celery_app.task(name="code_mining.github_issues")
def run_github_issues_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = GithubIssuesModule()
            results = await module.run(target)

            for f in results:
                db_finding = DBFinding(
                    target_id=job.target_id if job else "",
                    job_id=job_id,
                    source=f.source,
                    type=f.type,
                    value=f.value,
                    context=f.context,
                    url_found_on=f.url_found_on,
                    confidence=f.confidence,
                    severity=f.severity,
                    raw_json=f.raw,
                )
                db.add(db_finding)

            if job:
                job.status = "completed"
                job.items_found = len(results)
                db.commit()
        except Exception as e:
            if job:
                job.status = "failed"
                job.error_message = str(e)
                db.commit()
        finally:
            db.close()

    asyncio.run(_run())
