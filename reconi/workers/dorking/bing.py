"""Bing dorking module — search indexed URLs for a target domain via Bing API."""

import asyncio
import os
from datetime import datetime, timezone

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, ReconJob
from ...core.plugin import Finding, ReconModule


class BingModule(ReconModule):
    name = "bing"
    category = "dorking"
    description = "Search Bing API with dork queries for a domain"
    requires_api_key = True
    rate_limit_delay = 1.5

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
        self.api_key = os.environ.get("BING_API_KEY", "")

    async def _search_bing(self, client: httpx.AsyncClient, dork: str) -> list[dict]:
        if not self.api_key:
            return []
        url = "https://api.bing.microsoft.com/v7.0/search"
        headers = {"Ocp-Apim-Subscription-Key": self.api_key}
        params = {"q": dork, "count": 10}
        try:
            resp = await client.get(url, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json()
            return data.get("webPages", {}).get("value", [])
        except Exception:
            return []

    async def run(self, target: str) -> list[Finding]:
        domain = target.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]
        findings: list[Finding] = []
        if not self.api_key:
            return findings
        async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
            for dork_template in self.DORKS:
                dork = dork_template.format(domain=domain)
                results = await self._search_bing(client, dork)
                for item in results:
                    link = item.get("url", "")
                    if not link:
                        continue
                    findings.append(
                        Finding(
                            source=self.name,
                            type="url",
                            value=link,
                            context=f"dork: {dork}",
                            url_found_on=f"https://api.bing.microsoft.com/v7.0/search?q={dork}",
                            severity="info",
                            confidence=0.6,
                            raw={"dork": dork, "snippet": item.get("snippet", ""), "url": link},
                            found_at=datetime.now(timezone.utc).isoformat(),
                        )
                    )
                await asyncio.sleep(self.rate_limit_delay)
        return findings


bing_module = BingModule()


@celery_app.task(name="dorking.bing")
def run_bing_task(job_id: str, target: str) -> list[dict]:
    async def _run() -> list[dict]:
        findings = await bing_module.run(target)
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
