"""crt.sh certificate transparency subdomain discovery module."""
import asyncio
import random
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class CrtshModule(ReconModule):
    name = "crtsh"
    category = "url_discovery"
    description = "Discover subdomains via crt.sh certificate transparency logs"
    requires_api_key = False
    rate_limit_delay = 1.0

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)
        seen: set[str] = set()

        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            async with httpx.AsyncClient(timeout=httpx.Timeout(60)) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()

            for entry in data:
                name_value = entry.get("name_value", "")
                if name_value:
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name and name not in seen:
                            seen.add(name)
                            finding_type = "subdomain" if name.endswith("." + domain) or name == domain else "domain"
                            findings.append(Finding(
                                source=self.name,
                                type=finding_type,
                                value=name,
                                context=f"Found in crt.sh certificate (issuer: {entry.get('issuer_name', 'unknown')})",
                                url_found_on=url,
                                severity="info",
                                confidence=0.8,
                                raw={
                                    "issuer_name": entry.get("issuer_name"),
                                    "entry_timestamp": entry.get("entry_timestamp"),
                                    "not_before": entry.get("not_before"),
                                    "not_after": entry.get("not_after"),
                                },
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


@celery_app.task(name="url_discovery.crtsh")
def run_crtsh_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = CrtshModule()
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
