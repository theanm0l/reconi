"""GitHub gists search module — search for domain references in public gists."""

import asyncio
import os
from datetime import datetime, timezone

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, ReconJob
from ...core.plugin import Finding, ReconModule


class GitHubGistsModule(ReconModule):
    name = "github_gists"
    category = "dorking"
    description = "Search GitHub gists for domain references"
    requires_api_key = True
    rate_limit_delay = 2.5

    def __init__(self) -> None:
        self.token = os.environ.get("GITHUB_TOKEN", "")

    async def _search_gists_code(self, client: httpx.AsyncClient, domain: str) -> list[dict]:
        if not self.token:
            return []
        url = "https://api.github.com/search/code"
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
        }
        params = {"q": f'"{domain}" in:gist', "per_page": 30}
        try:
            resp = await client.get(url, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json()
            return data.get("items", [])
        except Exception:
            return []

    async def _fetch_public_gists(self, client: httpx.AsyncClient, domain: str) -> list[dict]:
        matched: list[dict] = []
        try:
            resp = await client.get(
                "https://api.github.com/gists/public",
                params={"per_page": 100},
                headers={"Accept": "application/vnd.github.v3+json"},
            )
            resp.raise_for_status()
            gists = resp.json()
            for gist in gists:
                description = (gist.get("description") or "").lower()
                files = gist.get("files", {})
                file_names = " ".join(files.keys()).lower()
                if domain.lower() in description or domain.lower() in file_names:
                    matched.append(gist)
        except Exception:
            pass
        return matched

    async def run(self, target: str) -> list[Finding]:
        domain = target.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]
        findings: list[Finding] = []
        if not self.token:
            return findings
        async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
            code_items = await self._search_gists_code(client, domain)
            for item in code_items:
                gist_url = item.get("repository", {}).get("html_url", "")
                if not gist_url:
                    gist_url = item.get("html_url", "")
                if not gist_url:
                    continue
                findings.append(
                    Finding(
                        source=self.name,
                        type="gist",
                        value=gist_url,
                        context=f"path: {item.get('path', '')}",
                        url_found_on=f"https://api.github.com/search/code?q={domain}+in:gist",
                        severity="info",
                        confidence=0.6,
                        raw={"gist_url": gist_url, "path": item.get("path", ""), "query": domain},
                        found_at=datetime.now(timezone.utc).isoformat(),
                    )
                )
            await asyncio.sleep(self.rate_limit_delay)
            gists = await self._fetch_public_gists(client, domain)
            for gist in gists:
                gist_url = gist.get("html_url", "")
                if not gist_url:
                    continue
                findings.append(
                    Finding(
                        source=self.name,
                        type="gist",
                        value=gist_url,
                        context=gist.get("description", ""),
                        url_found_on="https://api.github.com/gists/public",
                        severity="info",
                        confidence=0.5,
                        raw={"gist_id": gist.get("id", ""), "description": gist.get("description", "")},
                        found_at=datetime.now(timezone.utc).isoformat(),
                    )
                )
                await asyncio.sleep(0.3)
        return findings


github_gists_module = GitHubGistsModule()


@celery_app.task(name="dorking.github_gists")
def run_github_gists_task(job_id: str, target: str) -> list[dict]:
    async def _run() -> list[dict]:
        findings = await github_gists_module.run(target)
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
