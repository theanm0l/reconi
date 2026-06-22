"""ProgrammableWeb — discover APIs listed on ProgrammableWeb for a domain."""
import asyncio
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class ProgrammableWebModule(ReconModule):
    name = "programmableweb"
    category = "api_discovery"
    description = "Search ProgrammableWeb for API listings matching the target domain"
    requires_api_key = False
    rate_limit_delay = 1.5

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        try:
            search_url = f"https://www.programmableweb.com/search/{domain}"
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

            for entry in soup.select(".views-row, .search-result, article, .api-listing, .node"):
                name_el = (
                    entry.select_one("h2 a, h3 a, .title a, .api-name a, .field-name-title a")
                    or entry.select_one("h2, h3, .title, .api-name")
                )
                desc_el = entry.select_one(".field-body, .description, .api-description, .field-name-body, p")
                link_el = entry.select_one("a[href]")
                category_el = entry.select_one(".field-category, .api-category, .category")

                name = name_el.get_text(strip=True) if name_el else ""
                description = desc_el.get_text(strip=True)[:300] if desc_el else ""
                link = ""
                if link_el:
                    link = link_el.get("href", "")
                    if link.startswith("/"):
                        link = f"https://www.programmableweb.com{link}"
                category = category_el.get_text(strip=True) if category_el else ""

                if name or link:
                    context_parts = []
                    if description:
                        context_parts.append(description)
                    if category:
                        context_parts.append(f"Category: {category}")

                    findings.append(Finding(
                        source=self.name,
                        type="programmableweb_api",
                        value=link or name,
                        context="; ".join(context_parts) if context_parts else "ProgrammableWeb API listing",
                        url_found_on=search_url,
                        severity="info",
                        confidence=0.6,
                    ))

            if not findings:
                for link in soup.find_all("a", href=True):
                    href = link.get("href", "")
                    text = link.get_text(strip=True)
                    if domain.lower() in href.lower() or domain.lower() in text.lower():
                        full_url = href if href.startswith("http") else f"https://www.programmableweb.com{href}"
                        findings.append(Finding(
                            source=self.name,
                            type="programmableweb_api",
                            value=full_url,
                            context=text or "ProgrammableWeb result from search",
                            url_found_on=search_url,
                            severity="info",
                            confidence=0.4,
                        ))

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


@celery_app.task(name="api_discovery.programmableweb")
def run_programmableweb_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = ProgrammableWebModule()
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
