"""GitMemory scraping — search cached GitHub content mentioning a domain."""
import asyncio
import re
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
        return netloc
    return target.split(":")[0].split("/")[0]


class GitmemoryModule(ReconModule):
    name = "gitmemory"
    category = "code_mining"
    description = "Scrape gitmemory.com for cached GitHub content referencing a domain"
    requires_api_key = False
    rate_limit_delay = 1.5

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)
        search_url = f"https://www.gitmemory.com/search?q={domain}"

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(30),
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
            ) as client:
                resp = await client.get(search_url)
                resp.raise_for_status()
                text = resp.text

            link_patterns = [
                re.compile(r'href="(https?://www\.gitmemory\.com/[^"]+)"'),
                re.compile(r'href="(/[^"]+)"'),
                re.compile(r'https?://www\.gitmemory\.com/([A-Za-z0-9/_.-]+)'),
            ]

            seen = set()
            for pattern in link_patterns:
                for match in pattern.finditer(text):
                    link = match.group(0) if match.groups() is None else match.group(0)
                    if "gitmemory.com" in link and link not in seen:
                        seen.add(link)
                        full_url = link if link.startswith("http") else f"https://www.gitmemory.com{link}"
                        findings.append(Finding(
                            source=self.name,
                            type="code",
                            value=full_url,
                            context=f"GitMemory cached content matching {domain}",
                            url_found_on=search_url,
                            severity="info",
                            confidence=0.4,
                        ))

            if not seen:
                text_links = re.findall(r'href="(/[^"]*)"', text)
                for link in text_links[:30]:
                    if link in seen or link == "/":
                        continue
                    seen.add(link)
                    findings.append(Finding(
                        source=self.name,
                        type="code",
                        value=f"https://www.gitmemory.com{link}",
                        context=f"GitMemory result for {domain}",
                        url_found_on=search_url,
                        severity="info",
                        confidence=0.4,
                    ))

        except Exception as e:
            findings.append(Finding(source=self.name, type="error", value=str(e), severity="info", confidence=0.0))

        return findings


@celery_app.task(name="code_mining.gitmemory")
def run_gitmemory_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = GitmemoryModule()
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
