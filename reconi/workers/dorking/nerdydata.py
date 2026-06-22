"""NerdyData dorking module — scrape search results for domain references."""

import asyncio
from datetime import datetime, timezone

import httpx
from bs4 import BeautifulSoup

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, ReconJob
from ...core.plugin import Finding, ReconModule


class NerdyDataModule(ReconModule):
    name = "nerdydata"
    category = "dorking"
    description = "Scrape NerdyData search results for domain references"
    requires_api_key = False
    rate_limit_delay = 2.0

    async def _scrape_search(self, client: httpx.AsyncClient, domain: str) -> list[str]:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/125.0.0.0 Safari/537.36"
            )
        }
        try:
            resp = await client.get(
                "https://www.nerdydata.com/search",
                params={"query": domain},
                headers=headers,
            )
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")
            urls: list[str] = []
            for link in soup.find_all("a", href=True):
                href = link["href"]
                if isinstance(href, str) and href.startswith("http"):
                    urls.append(href)
            return list(dict.fromkeys(urls))
        except Exception:
            return []

    async def run(self, target: str) -> list[Finding]:
        domain = target.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]
        findings: list[Finding] = []
        async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
            urls = await self._scrape_search(client, domain)
            for url in urls:
                findings.append(
                    Finding(
                        source=self.name,
                        type="url",
                        value=url,
                        context=f"domain reference: {domain}",
                        url_found_on=f"https://www.nerdydata.com/search?query={domain}",
                        severity="info",
                        confidence=0.4,
                        raw={"url": url, "domain": domain},
                        found_at=datetime.now(timezone.utc).isoformat(),
                    )
                )
        return findings


nerdydata_module = NerdyDataModule()


@celery_app.task(name="dorking.nerdydata")
def run_nerdydata_task(job_id: str, target: str) -> list[dict]:
    async def _run() -> list[dict]:
        findings = await nerdydata_module.run(target)
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
