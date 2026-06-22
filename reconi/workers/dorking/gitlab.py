"""GitLab search module — search GitLab public blobs and projects for a domain."""

import asyncio
from datetime import datetime, timezone

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, ReconJob
from ...core.plugin import Finding, ReconModule


class GitLabModule(ReconModule):
    name = "gitlab"
    category = "dorking"
    description = "Search GitLab public repositories for domain references"
    requires_api_key = False
    rate_limit_delay = 1.5

    async def _search_blobs(self, client: httpx.AsyncClient, domain: str) -> list[dict]:
        url = "https://gitlab.com/api/v4/search"
        params = {"scope": "blobs", "search": domain, "per_page": 30}
        try:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return []

    async def _search_projects(self, client: httpx.AsyncClient, domain: str) -> list[dict]:
        url = "https://gitlab.com/api/v4/search"
        params = {"scope": "projects", "search": domain, "per_page": 30}
        try:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return []

    async def run(self, target: str) -> list[Finding]:
        domain = target.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]
        findings: list[Finding] = []
        async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
            blobs = await self._search_blobs(client, domain)
            for blob in blobs:
                path = blob.get("path", "")
                filename = blob.get("filename", "")
                project_id = blob.get("project_id", "")
                blob_url = (
                    f"https://gitlab.com/projects/{project_id}/blob/{blob.get('ref', 'main')}/{path}"
                    if project_id and path
                    else ""
                )
                if not blob_url:
                    continue
                findings.append(
                    Finding(
                        source=self.name,
                        type="code",
                        value=blob_url,
                        context=f"blob: {filename} (project #{project_id})",
                        url_found_on=f"https://gitlab.com/api/v4/search?scope=blobs&search={domain}",
                        severity="info",
                        confidence=0.6,
                        raw={"filename": filename, "path": path, "project_id": project_id},
                        found_at=datetime.now(timezone.utc).isoformat(),
                    )
                )
            await asyncio.sleep(self.rate_limit_delay)
            projects = await self._search_projects(client, domain)
            for proj in projects:
                web_url = proj.get("web_url", "")
                name = proj.get("name", "")
                if not web_url:
                    continue
                findings.append(
                    Finding(
                        source=self.name,
                        type="code",
                        value=web_url,
                        context=f"project: {name}",
                        url_found_on=f"https://gitlab.com/api/v4/search?scope=projects&search={domain}",
                        severity="info",
                        confidence=0.5,
                        raw={"name": name, "web_url": web_url, "description": proj.get("description", "")},
                        found_at=datetime.now(timezone.utc).isoformat(),
                    )
                )
        return findings


gitlab_module = GitLabModule()


@celery_app.task(name="dorking.gitlab")
def run_gitlab_task(job_id: str, target: str) -> list[dict]:
    async def _run() -> list[dict]:
        findings = await gitlab_module.run(target)
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
