"""Wayback Machine CDX Text — URL discovery module."""
import asyncio
import random
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class WaybackUrlsModule(ReconModule):
    name = "waybackurls"
    category = "url_discovery"
    description = "Fetch historical URLs from the Wayback Machine CDX API in text format"
    requires_api_key = False
    rate_limit_delay = 1.5

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        try:
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=50000"
            async with httpx.AsyncClient(timeout=httpx.Timeout(120)) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                text = resp.text

            for line in text.strip().splitlines():
                line = line.strip()
                if line and not line.startswith("original"):
                    findings.append(Finding(
                        source=self.name,
                        type="url",
                        value=line,
                        context="Found in Wayback Machine text output",
                        url_found_on=url,
                        severity="info",
                        confidence=0.7,
                    ))

            await asyncio.sleep(random.uniform(0.5, 1.5))
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


@celery_app.task(name="url_discovery.waybackurls")
def run_waybackurls_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = WaybackUrlsModule()
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
