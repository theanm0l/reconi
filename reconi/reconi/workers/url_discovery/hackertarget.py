"""HackerTarget host search discovery module."""
import asyncio
import random
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class HackertargetModule(ReconModule):
    name = "hackertarget"
    category = "url_discovery"
    description = "Discover hostnames and IPs via HackerTarget host search API"
    requires_api_key = False
    rate_limit_delay = 1.0

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            async with httpx.AsyncClient(timeout=httpx.Timeout(60)) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                text = resp.text

            for line in text.strip().splitlines():
                line = line.strip()
                if not line or "error" in line.lower():
                    continue

                parts = line.split(",")
                if len(parts) >= 2:
                    subdomain = parts[0].strip()
                    ip = parts[1].strip()

                    if subdomain:
                        findings.append(Finding(
                            source=self.name,
                            type="subdomain",
                            value=subdomain,
                            context=f"HackerTarget host search (IP: {ip})",
                            url_found_on=url,
                            severity="info",
                            confidence=0.7,
                            raw={"ip": ip},
                        ))

                    if ip:
                        findings.append(Finding(
                            source=self.name,
                            type="ip",
                            value=ip,
                            context=f"HackerTarget IP for {subdomain}",
                            url_found_on=url,
                            severity="info",
                            confidence=0.7,
                            raw={"subdomain": subdomain},
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


@celery_app.task(name="url_discovery.hackertarget")
def run_hackertarget_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = HackertargetModule()
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
