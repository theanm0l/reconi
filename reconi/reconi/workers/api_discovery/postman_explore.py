"""Postman Explore — scrape Postman search results for collections."""
import asyncio
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class PostmanExploreModule(ReconModule):
    name = "postman_explore"
    category = "api_discovery"
    description = "Scrape Postman search results for public collections related to the target domain"
    requires_api_key = False
    rate_limit_delay = 1.5

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        try:
            search_url = f"https://www.postman.com/search?q={domain}&scope=public&type=collection"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }
            async with httpx.AsyncClient(timeout=httpx.Timeout(30), follow_redirects=True) as client:
                resp = await client.get(search_url, headers=headers)
                resp.raise_for_status()
                html = resp.text

            soup = BeautifulSoup(html, "html.parser")

            for card in soup.select('[class*="collection"] a, [class*="Collection"] a, a[href*="/collection/"]'):
                href = card.get("href", "")
                text = card.get_text(strip=True)
                if href and "/collection/" in href:
                    full_url = f"https://www.postman.com{href}" if href.startswith("/") else href
                    findings.append(Finding(
                        source=self.name,
                        type="postman_collection",
                        value=full_url,
                        context=text or "Postman collection from search results",
                        url_found_on=search_url,
                        severity="info",
                        confidence=0.6,
                    ))

            for link in soup.find_all("a", href=True):
                href = link.get("href", "")
                if "/collection/" in href and href not in {f.value for f in findings}:
                    full_url = f"https://www.postman.com{href}" if href.startswith("/") else href
                    desc = link.get("title") or link.get_text(strip=True) or link.get("aria-label", "")
                    findings.append(Finding(
                        source=self.name,
                        type="postman_collection",
                        value=full_url,
                        context=desc,
                        url_found_on=search_url,
                        severity="info",
                        confidence=0.5,
                    ))

            if not findings:
                api_search_url = f"https://www.postman.com/_api/ws/search-all?queryText={domain}&size=30&from=0"
                api_resp = await client.get(api_search_url)
                api_resp.raise_for_status()
                api_data = api_resp.json()

                for item in api_data.get("data", {}).get("collections", []):
                    uid = item.get("uid") or item.get("id")
                    name = item.get("name", "")
                    publisher = item.get("publisher", {}).get("handle") or item.get("publisherHandle", "")
                    collection_url = f"https://www.postman.com/collections/{uid}" if uid else ""
                    findings.append(Finding(
                        source=self.name,
                        type="postman_collection",
                        value=collection_url or name,
                        context=f"Name: {name}, Publisher: {publisher}",
                        url_found_on=api_search_url,
                        severity="info",
                        confidence=0.5,
                        raw=item,
                    ))

                await asyncio.sleep(0.5)

        except Exception as e:
            findings.append(Finding(
                source=self.name,
                type="error",
                value=str(e),
                severity="info",
                confidence=0.0,
            ))

        return findings


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
        return netloc
    return target.split(":")[0].split("/")[0]


@celery_app.task(name="api_discovery.postman_explore")
def run_postman_explore_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = PostmanExploreModule()
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
