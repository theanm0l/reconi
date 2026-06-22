"""GAU Plus — extended URL aggregator including JS/JSON/XML endpoints from multiple sources."""
import asyncio
import random
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class GauPlusModule(ReconModule):
    name = "gauplus"
    category = "url_discovery"
    description = "Extended URL aggregator including unfiltered JS/JSON/XML endpoints from Wayback, CommonCrawl, AlienVault"
    requires_api_key = False
    rate_limit_delay = 1.0

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)
        seen: set[str] = set()

        async with httpx.AsyncClient(timeout=httpx.Timeout(60)) as client:
            for result in await self._fetch_wayback(client, domain, seen):
                findings.append(result)
            await asyncio.sleep(random.uniform(0.5, 1.5))

            for result in await self._fetch_commoncrawl(client, domain, seen):
                findings.append(result)
            await asyncio.sleep(random.uniform(0.5, 1.5))

            for result in await self._fetch_alienvault(client, domain, seen):
                findings.append(result)

        return findings

    async def _fetch_wayback(self, client: httpx.AsyncClient, domain: str, seen: set[str]) -> list[Finding]:
        results: list[Finding] = []
        filters = ["", "&filter=mimetype:application/javascript", "&filter=mimetype:application/json",
                    "&filter=mimetype:text/xml", "&filter=mimetype:application/xml",
                    "&filter=mimetype:text/html", "&filter=statuscode:200"]
        for filt in filters:
            try:
                url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=10000{filt}"
                resp = await client.get(url)
                resp.raise_for_status()
                for line in resp.text.strip().splitlines():
                    line = line.strip()
                    if line and not line.startswith("original") and line not in seen:
                        seen.add(line)
                        results.append(Finding(
                            source=self.name,
                            type="url",
                            value=line,
                            context="Found via Wayback Machine (GAU Plus extended)",
                            url_found_on=url,
                            severity="info",
                            confidence=0.7,
                        ))
                await asyncio.sleep(random.uniform(0.3, 0.8))
            except Exception:
                continue
        return results

    async def _fetch_commoncrawl(self, client: httpx.AsyncClient, domain: str, seen: set[str]) -> list[Finding]:
        results: list[Finding] = []
        try:
            index_url = "https://index.commoncrawl.org/collinfo.json"
            resp = await client.get(index_url)
            resp.raise_for_status()
            indices = resp.json()
            for idx_entry in indices[-5:]:
                index_id = idx_entry.get("id", "")
                if not index_id:
                    continue
                search_url = f"https://index.commoncrawl.org/{index_id}-index?url=*.{domain}/*&output=json&fl=url"
                try:
                    resp2 = await client.get(search_url)
                    for line in resp2.text.strip().splitlines():
                        try:
                            data = __import__("json").loads(line)
                            entry_url = data.get("url", "")
                            if entry_url and entry_url not in seen:
                                seen.add(entry_url)
                                results.append(Finding(
                                    source=self.name,
                                    type="url",
                                    value=entry_url,
                                    context=f"Found via CommonCrawl index {index_id}",
                                    url_found_on=search_url,
                                    severity="info",
                                    confidence=0.6,
                                    raw={"index_id": index_id},
                                ))
                        except Exception:
                            continue
                    await asyncio.sleep(random.uniform(0.5, 1.0))
                except Exception:
                    continue
        except Exception:
            pass
        return results

    async def _fetch_alienvault(self, client: httpx.AsyncClient, domain: str, seen: set[str]) -> list[Finding]:
        results: list[Finding] = []
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500"
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
            for entry in data.get("url_list", []):
                entry_url = entry.get("url", "")
                if entry_url and entry_url not in seen:
                    seen.add(entry_url)
                    results.append(Finding(
                        source=self.name,
                        type="url",
                        value=entry_url,
                        context="Found via AlienVault OTX (GAU Plus)",
                        url_found_on=url,
                        severity="info",
                        confidence=0.7,
                        raw=entry,
                    ))
        except Exception:
            pass
        return results


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
        return netloc
    return target.split(":")[0].split("/")[0]


@celery_app.task(name="url_discovery.gauplus")
def run_gauplus_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = GauPlusModule()
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
