"""PublicWWW dorking module — search websites for domain references via PublicWWW."""

import asyncio
import os
from datetime import datetime, timezone

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, ReconJob
from ...core.plugin import Finding, ReconModule


class PublicWWWModule(ReconModule):
    name = "publicwww"
    category = "dorking"
    description = "Search PublicWWW for websites containing domain references"
    requires_api_key = False
    rate_limit_delay = 2.0

    def __init__(self) -> None:
        self.api_key = os.environ.get("PUBLICWWW_API_KEY", "")

    async def _search_with_api(self, client: httpx.AsyncClient, domain: str) -> list[str]:
        if not self.api_key:
            return []
        url = f'https://publicwww.com/websites/"{domain}"/'
        params = {"export": "urls"}
        try:
            resp = await client.get(url, params=params, auth=(self.api_key, ""))
            resp.raise_for_status()
            urls = [line.strip() for line in resp.text.splitlines() if line.strip()]
            return urls
        except Exception:
            return []

    async def _search_scrape(self, client: httpx.AsyncClient, domain: str) -> list[str]:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/125.0.0.0 Safari/537.36"
            )
        }
        try:
            resp = await client.get(
                f'https://publicwww.com/websites/"{domain}"/',
                headers=headers,
            )
            resp.raise_for_status()
            urls: list[str] = []
            text = resp.text
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("http"):
                    urls.append(line)
            return urls
        except Exception:
            return []

    async def run(self, target: str) -> list[Finding]:
        domain = target.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]
        findings: list[Finding] = []
        async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
            if self.api_key:
                urls = await self._search_with_api(client, domain)
            else:
                urls = await self._search_scrape(client, domain)
            for url in urls:
                findings.append(
                    Finding(
                        source=self.name,
                        type="url",
                        value=url,
                        context=f"domain reference: {domain}",
                        url_found_on=f'https://publicwww.com/websites/"{domain}"/',
                        severity="info",
                        confidence=0.5,
                        raw={"url": url, "domain": domain},
                        found_at=datetime.now(timezone.utc).isoformat(),
                    )
                )
        return findings


publicwww_module = PublicWWWModule()


@celery_app.task(name="dorking.publicwww")
def run_publicwww_task(job_id: str, target: str) -> list[dict]:
    async def _run() -> list[dict]:
        findings = await publicwww_module.run(target)
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
