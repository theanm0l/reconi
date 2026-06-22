"""DuckDuckGo dorking module — search indexed URLs via Instant Answer API."""

import asyncio
from datetime import datetime, timezone

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, ReconJob
from ...core.plugin import Finding, ReconModule


class DuckDuckGoModule(ReconModule):
    name = "duckduckgo"
    category = "dorking"
    description = "Search DuckDuckGo Instant Answer API for a domain"
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

    async def _search_ddg(self, client: httpx.AsyncClient, query: str) -> list[str]:
        urls: list[str] = []
        try:
            resp = await client.get(
                "https://api.duckduckgo.com/",
                params={"q": query, "format": "json", "no_html": "1", "skip_disambig": "1"},
            )
            resp.raise_for_status()
            data = resp.json()
            for key in ("Results", "RelatedTopics"):
                entries = data.get(key, [])
                for entry in entries:
                    if isinstance(entry, dict):
                        link = entry.get("FirstURL", "")
                        if link:
                            urls.append(link)
            abstract_url = data.get("AbstractURL", "")
            if abstract_url:
                urls.append(abstract_url)
            return list(dict.fromkeys(urls))
        except Exception:
            return []

    async def run(self, target: str) -> list[Finding]:
        domain = target.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]
        findings: list[Finding] = []
        async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
            base_query = f"site:{domain}"
            base_urls = await self._search_ddg(client, base_query)
            for url in base_urls:
                findings.append(
                    Finding(
                        source=self.name,
                        type="url",
                        value=url,
                        context=f"dork: {base_query}",
                        url_found_on=f"https://api.duckduckgo.com/?q={base_query}",
                        severity="info",
                        confidence=0.5,
                        raw={"dork": base_query, "url": url},
                        found_at=datetime.now(timezone.utc).isoformat(),
                    )
                )
            await asyncio.sleep(self.rate_limit_delay)
            for dork_template in self.DORKS:
                dork = dork_template.format(domain=domain)
                urls = await self._search_ddg(client, dork)
                for url in urls:
                    findings.append(
                        Finding(
                            source=self.name,
                            type="url",
                            value=url,
                            context=f"dork: {dork}",
                            url_found_on=f"https://api.duckduckgo.com/?q={dork}",
                            severity="info",
                            confidence=0.5,
                            raw={"dork": dork, "url": url},
                            found_at=datetime.now(timezone.utc).isoformat(),
                        )
                    )
                await asyncio.sleep(self.rate_limit_delay)
        return findings


duckduckgo_module = DuckDuckGoModule()


@celery_app.task(name="dorking.duckduckgo")
def run_duckduckgo_task(job_id: str, target: str) -> list[dict]:
    async def _run() -> list[dict]:
        findings = await duckduckgo_module.run(target)
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
