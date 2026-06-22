"""GitHub commit search — scan commit messages and diffs for secrets."""
import asyncio
import os
import re
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule

_SECRET_PATTERNS = [
    (re.compile(r'([a-zA-Z0-9_-]{20,60})', re.IGNORECASE), "possible_api_key"),
    (re.compile(r'(?i)(?:password|passwd|pwd|secret|token|apikey|api_key|auth)\s*[:=]\s*["\']?([^\s"\'<>]{8,})'), "credential"),
    (re.compile(r'(?i)sk-[a-zA-Z0-9]{32,}'), "openai_key"),
    (re.compile(r'(?i)AKIA[0-9A-Z]{16}'), "aws_access_key"),
    (re.compile(r'(?i)ghp_[0-9a-zA-Z]{36}'), "github_pat"),
    (re.compile(r'(?i)gho_[0-9a-zA-Z]{36}'), "github_oauth"),
    (re.compile(r'(?i)github_pat_[0-9a-zA-Z_]{22,}'), "github_pat_v2"),
    (re.compile(r'(?i)xox[baprs]-[0-9a-zA-Z-]{10,}'), "slack_token"),
    (re.compile(r'(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^\s<>"\'{}|\\^`\[\]]+'), "db_connection_string"),
    (re.compile(r'(?i)-----BEGIN\s(?:RSA|DSA|EC|OPENSSH|PGP)?\s?PRIVATE\s?KEY(?: BLOCK)?-----'), "private_key"),
    (re.compile(r'(?i)(?:api|app|auth|client|secret|token|key)_?(?:key|token|secret)?\s*[:=]\s*["\']?([^\s"\'<>]{16,})'), "named_secret"),
]


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
        return netloc
    return target.split(":")[0].split("/")[0]


def _scan_content(content: str) -> list[dict]:
    hits = []
    for pattern, label in _SECRET_PATTERNS:
        for match in pattern.finditer(content):
            val = match.group(1) if match.groups() else match.group(0)
            hits.append({"type": label, "value": val})
    return hits


class GithubCommitsModule(ReconModule):
    name = "github_commits"
    category = "code_mining"
    description = "Search GitHub commits for a domain and scan for exposed secrets"
    requires_api_key = True
    rate_limit_delay = 1.0

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        token = os.getenv("GITHUB_TOKEN", "")
        if not token:
            findings.append(Finding(source=self.name, type="error", value="GITHUB_TOKEN not set", severity="info", confidence=0.0))
            return findings

        domain = _extract_domain(target)
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.cloak-preview+json",
        }

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(60), headers=headers) as client:
                search_url = f"https://api.github.com/search/commits?q={domain}&per_page=100&sort=committer-date"
                resp = await client.get(search_url)
                resp.raise_for_status()
                data = resp.json()
                commits = data.get("items", [])

            for item in commits[:50]:
                await asyncio.sleep(0.5)
                commit = item.get("commit", {})
                message = commit.get("message", "")
                author = commit.get("committer", {}).get("name", "unknown")
                commit_url = item.get("html_url", "")

                hits = _scan_content(message)
                for hit in hits:
                    findings.append(Finding(
                        source=self.name,
                        type="commit",
                        value=commit_url,
                        context=f"[{author}] {message[:120]}",
                        url_found_on=search_url,
                        severity="high",
                        confidence=0.7,
                        raw={"author": author, "detected": hit["type"], "matched": hit["value"][:80]},
                    ))

                if not hits and message:
                    findings.append(Finding(
                        source=self.name,
                        type="commit",
                        value=commit_url,
                        context=f"[{author}] {message[:120]}",
                        url_found_on=search_url,
                        severity="info",
                        confidence=0.4,
                        raw={"author": author, "sha": item.get("sha", "")},
                    ))

        except Exception as e:
            findings.append(Finding(source=self.name, type="error", value=str(e), severity="info", confidence=0.0))

        return findings


@celery_app.task(name="code_mining.github_commits")
def run_github_commits_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = GithubCommitsModule()
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
