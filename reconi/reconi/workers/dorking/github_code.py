"""GitHub code search module — search for domain references in code on GitHub."""

import asyncio
import base64
import os
from datetime import datetime, timezone

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, ReconJob
from ...core.plugin import Finding, ReconModule


class GitHubCodeModule(ReconModule):
    name = "github_code"
    category = "dorking"
    description = "Search GitHub code for domain references and secrets"
    requires_api_key = True
    rate_limit_delay = 2.5

    QUERIES = [
        '"{domain}"',
        '"{domain}" password',
        '"{domain}" api_key',
        '"{domain}" secret',
        '"{domain}" token',
        '"{domain}" client_secret',
    ]

    def __init__(self) -> None:
        self.token = os.environ.get("GITHUB_TOKEN", "")

    async def _search_code(self, client: httpx.AsyncClient, query: str) -> list[dict]:
        if not self.token:
            return []
        url = "https://api.github.com/search/code"
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
        }
        params = {"q": query, "per_page": 30}
        try:
            resp = await client.get(url, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json()
            return data.get("items", [])
        except Exception:
            return []

    async def run(self, target: str) -> list[Finding]:
        domain = target.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]
        findings: list[Finding] = []
        if not self.token:
            return findings
        async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
            for query_template in self.QUERIES:
                query = query_template.format(domain=domain)
                items = await self._search_code(client, query)
                for item in items:
                    repo = item.get("repository", {})
                    repo_name = repo.get("full_name", "")
                    file_path = item.get("path", "")
                    html_url = item.get("html_url", "")
                    if not html_url:
                        continue
                    findings.append(
                        Finding(
                            source=self.name,
                            type="code",
                            value=html_url,
                            context=f"repo: {repo_name}, path: {file_path}",
                            url_found_on=(
                                f"https://api.github.com/search/code?q={query}"
                            ),
                            severity="info",
                            confidence=0.7,
                            raw={
                                "repo": repo_name,
                                "path": file_path,
                                "url": html_url,
                                "query": query,
                            },
                            found_at=datetime.now(timezone.utc).isoformat(),
                        )
                    )
                await asyncio.sleep(self.rate_limit_delay)
        return findings


github_code_module = GitHubCodeModule()


@celery_app.task(name="dorking.github_code")
def run_github_code_task(job_id: str, target: str) -> list[dict]:
    async def _run() -> list[dict]:
        findings = await github_code_module.run(target)
        return [f.__dict__ for f in findings]

    results = asyncio.run(_run())
    db = SessionLocal()
    try:
        job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
        if job:
            job.items_found = len(results)
            job.status = "completed"
            job.completed_at = datetime.now(timezone.utc)
            db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()
    return results
