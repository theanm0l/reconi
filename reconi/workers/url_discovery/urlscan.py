"""URLScan.io URL discovery module."""
import asyncio
import json
import random
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class UrlscanModule(ReconModule):
    name = "urlscan"
    category = "url_discovery"
    description = "Discover URLs and screenshots from URLScan.io search results"
    requires_api_key = False
    rate_limit_delay = 2.0

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        try:
            search_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
            async with httpx.AsyncClient(timeout=httpx.Timeout(60)) as client:
                resp = await client.get(search_url)
                resp.raise_for_status()
                data = resp.json()

            for result in data.get("results", []):
                page = result.get("page", {})

                page_url = page.get("url", "")
                if page_url:
                    findings.append(Finding(
                        source=self.name,
                        type="url",
                        value=page_url,
                        context="Found via URLScan.io search",
                        url_found_on=search_url,
                        severity="info",
                        confidence=0.8,
                        raw={"task_url": result.get("task", {}).get("url", "")},
                    ))

                screenshot = result.get("screenshot", "")
                if screenshot:
                    findings.append(Finding(
                        source=self.name,
                        type="screenshot",
                        value=screenshot,
                        context=f"Screenshot of {page_url}",
                        url_found_on=search_url,
                        severity="info",
                        confidence=0.8,
                        raw={"page_url": page_url},
                    ))

                page_domain = page.get("domain", "")
                if page_domain and page_domain != domain and _is_sub_or_related(page_domain, domain):
                    findings.append(Finding(
                        source=self.name,
                        type="subdomain",
                        value=page_domain,
                        context=f"Related domain found via URLScan.io",
                        url_found_on=search_url,
                        severity="info",
                        confidence=0.7,
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


def _is_sub_or_related(domain: str, target_domain: str) -> bool:
    return domain.endswith("." + target_domain) or domain == target_domain


@celery_app.task(name="url_discovery.urlscan")
def run_urlscan_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = UrlscanModule()
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
