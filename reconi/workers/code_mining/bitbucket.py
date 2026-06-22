"""Bitbucket API — search repositories and code for domain mentions."""
import asyncio
import os
import re
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule

_SENSITIVE_PATTERNS = [
    (re.compile(r'(?i)(?:password|passwd|pwd|secret|token|apikey|api_key|auth)\s*[:=]\s*["\']?([^\s"\'<>]{8,})'), "credential"),
    (re.compile(r'(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^\s<>"\'{}|\\^`\[\]]+'), "db_connection_string"),
    (re.compile(r'(?i)-----BEGIN\s(?:RSA|DSA|EC|OPENSSH)?\s?PRIVATE\s?KEY'), "private_key"),
]


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
        return netloc
    return target.split(":")[0].split("/")[0]


class BitbucketModule(ReconModule):
    name = "bitbucket"
    category = "code_mining"
    description = "Search Bitbucket API for repositories and code mentioning a domain"
    requires_api_key = False
    rate_limit_delay = 1.0

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        bitbucket_user = os.getenv("BITBUCKET_USER", "")
        bitbucket_app_password = os.getenv("BITBUCKET_APP_PASSWORD", "")
        auth = None
        if bitbucket_user and bitbucket_app_password:
            auth = (bitbucket_user, bitbucket_app_password)

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(45), auth=auth) as client:
                search_url = f'https://api.bitbucket.org/2.0/repositories?q=name~"{domain}"'
                resp = await client.get(search_url)
                resp.raise_for_status()
                data = resp.json()
                repos = data.get("values", [])

            for repo in repos[:30]:
                await asyncio.sleep(0.5)
                repo_name = repo.get("full_name", repo.get("name", ""))
                repo_url = repo.get("links", {}).get("html", {}).get("href", "")
                description = repo.get("description", "")

                findings.append(Finding(
                    source=self.name,
                    type="repo",
                    value=repo_url or f"https://bitbucket.org/{repo_name}",
                    context=description,
                    url_found_on=search_url,
                    severity="info",
                    confidence=0.6,
                    raw={"full_name": repo_name, "language": repo.get("language", ""), "updated": repo.get("updated_on", "")},
                ))

                try:
                    repo_slug = repo.get("slug", repo.get("name", ""))
                    owner = repo.get("workspace", {}).get("slug", repo.get("owner", {}).get("username", ""))
                    if owner and repo_slug:
                        async with httpx.AsyncClient(timeout=httpx.Timeout(45), auth=auth) as client:
                            commits_url = f"https://api.bitbucket.org/2.0/repositories/{owner}/{repo_slug}/commits?pagelen=10"
                            commits_resp = await client.get(commits_url)
                            if commits_resp.status_code == 200:
                                commits_data = commits_resp.json()
                                for commit in commits_data.get("values", [])[:10]:
                                    message = commit.get("message", "")
                                    for pattern, label in _SENSITIVE_PATTERNS:
                                        match = pattern.search(message)
                                        if match:
                                            findings.append(Finding(
                                                source=self.name,
                                                type="code",
                                                value=commit.get("links", {}).get("html", {}).get("href", ""),
                                                context=f"Commit: {message[:120]}",
                                                url_found_on=repo_url,
                                                severity="high",
                                                confidence=0.7,
                                                raw={"detected": label, "commit_hash": commit.get("hash", "")},
                                            ))
                except Exception:
                    pass

            next_url = data.get("next")
            page = 0
            while next_url and page < 3:
                page += 1
                await asyncio.sleep(1.0)
                try:
                    async with httpx.AsyncClient(timeout=httpx.Timeout(45), auth=auth) as client:
                        resp = await client.get(next_url)
                        resp.raise_for_status()
                        data = resp.json()
                        repos = data.get("values", [])
                        next_url = data.get("next")

                    for repo in repos[:20]:
                        repo_name = repo.get("full_name", repo.get("name", ""))
                        repo_url = repo.get("links", {}).get("html", {}).get("href", "")
                        findings.append(Finding(
                            source=self.name,
                            type="repo",
                            value=repo_url or f"https://bitbucket.org/{repo_name}",
                            context=repo.get("description", ""),
                            url_found_on=search_url,
                            severity="info",
                            confidence=0.5,
                            raw={"full_name": repo_name},
                        ))
                except Exception:
                    break

        except Exception as e:
            findings.append(Finding(source=self.name, type="error", value=str(e), severity="info", confidence=0.0))

        return findings


@celery_app.task(name="code_mining.bitbucket")
def run_bitbucket_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = BitbucketModule()
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
