"""CommonCrawl URL discovery — fetches URLs from CommonCrawl index."""
import asyncio
import json
import random
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class CommonCrawlModule(ReconModule):
    name = "commoncrawl"
    category = "url_discovery"
    description = "Discover URLs from CommonCrawl web index"
    requires_api_key = False
    rate_limit_delay = 1.0

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)
        seen: set[str] = set()

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(60)) as client:
                index_list_url = "https://index.commoncrawl.org/collinfo.json"
                resp = await client.get(index_list_url)
                resp.raise_for_status()
                indices = resp.json()

                for idx_entry in indices[-3:]:
                    index_id = idx_entry.get("id", "")
                    if not index_id:
                        continue
                    search_url = f"https://index.commoncrawl.org/{index_id}-index?url=*.{domain}/*&output=json&fl=url"
                    try:
                        resp2 = await client.get(search_url)
                        for line in resp2.text.strip().splitlines():
                            if not line.strip():
                                continue
                            try:
                                data = json.loads(line)
                                entry_url = data.get("url", "")
                                if entry_url and entry_url not in seen:
                                    seen.add(entry_url)
                                    findings.append(Finding(
                                        source=self.name,
                                        type="url",
                                        value=entry_url,
                                        context=f"Found in CommonCrawl index {index_id}",
                                        url_found_on=search_url,
                                        severity="info",
                                        confidence=0.6,
                                        raw={"index_id": index_id},
                                    ))
                            except json.JSONDecodeError:
                                continue
                        await asyncio.sleep(random.uniform(0.5, 1.5))
                    except Exception:
                        continue
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


@celery_app.task(name="url_discovery.commoncrawl")
def run_commoncrawl_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = CommonCrawlModule()
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
