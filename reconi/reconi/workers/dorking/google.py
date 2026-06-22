"""Google dorking module — search indexed URLs for a target domain."""

import asyncio
import os
from datetime import datetime, timezone

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, ReconJob
from ...core.plugin import Finding, ReconModule


class GoogleModule(ReconModule):
    name = "google"
    category = "dorking"
    description = "Generate Google dorks and retrieve indexed URLs for a domain"
    requires_api_key = False
    rate_limit_delay = 2.0

    DORKS = [
        "site:{domain}",
        "inurl:{domain}",
        "intitle:{domain}",
        'filetype:env site:{domain}',
        'filetype:sql site:{domain}',
        'filetype:log site:{domain}',
        'inurl:backup site:{domain}',
        'intitle:"index of" site:{domain}',
        "inurl:admin site:{domain}",
        '"password" site:{domain}',
    ]

    def __init__(self) -> None:
        self.api_key = os.environ.get("GOOGLE_API_KEY", "")
        self.cse_id = os.environ.get("GOOGLE_CSE_ID", "")

    async def _search_google_api(self, client: httpx.AsyncClient, dork: str) -> list[dict]:
        url = "https://www.googleapis.com/customsearch/v1"
        params = {"key": self.api_key, "cx": self.cse_id, "q": dork, "num": 10}
        try:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
            return data.get("items", [])
        except Exception:
            return []

    async def _search_scrape(self, client: httpx.AsyncClient, dork: str) -> list[str]:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/125.0.0.0 Safari/537.36"
            )
        }
        url = f"https://www.google.com/search?q={httpx.QueryParams({'q': dork})}"
        try:
            resp = await client.get(
                "https://www.google.com/search", params={"q": dork}, headers=headers
            )
            # Minimal extract — Google SERP parsing is complex; just log existence
            _ = resp.text
            return []
        except Exception:
            return []

    async def run(self, target: str) -> list[Finding]:
        domain = target.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]
        findings: list[Finding] = []
        async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
            for dork_template in self.DORKS:
                dork = dork_template.format(domain=domain)
                urls: list[str] = []
                if self.api_key and self.cse_id:
                    items = await self._search_google_api(client, dork)
                    for item in items:
                        link = item.get("link", "")
                        if link:
                            urls.append(link)
                else:
                    scraped = await self._search_scrape(client, dork)
                    urls.extend(scraped)
                for url in urls:
                    findings.append(
                        Finding(
                            source=self.name,
                            type="url",
                            value=url,
                            context=f"dork: {dork}",
                            url_found_on=f"https://www.google.com/search?q={dork}",
                            severity="info",
                            confidence=0.6,
                            raw={"dork": dork, "url": url},
                            found_at=datetime.now(timezone.utc).isoformat(),
                        )
                    )
                await asyncio.sleep(self.rate_limit_delay)
        return findings


google_module = GoogleModule()


@celery_app.task(name="dorking.google")
def run_google_task(job_id: str, target: str) -> list[dict]:
    async def _run() -> list[dict]:
        findings = await google_module.run(target)
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
