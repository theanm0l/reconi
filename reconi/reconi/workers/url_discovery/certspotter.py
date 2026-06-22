"""CertSpotter certificate issuance DNS names discovery module."""
import asyncio
import random
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class CertspotterModule(ReconModule):
    name = "certspotter"
    category = "url_discovery"
    description = "Discover DNS names from CertSpotter certificate issuances"
    requires_api_key = False
    rate_limit_delay = 1.0

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)
        seen: set[str] = set()

        try:
            url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            async with httpx.AsyncClient(timeout=httpx.Timeout(60)) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()

            for issuance in data:
                dns_names = issuance.get("dns_names", [])
                issuer = issuance.get("issuer", {}).get("name", "unknown")
                cert_id = issuance.get("id", "")

                for name in dns_names:
                    if isinstance(name, str) and name.strip() and name not in seen:
                        name = name.strip().lower()
                        seen.add(name)
                        findings.append(Finding(
                            source=self.name,
                            type="subdomain",
                            value=name,
                            context=f"DNS name from CertSpotter issuance (issuer: {issuer})",
                            url_found_on=url,
                            severity="info",
                            confidence=0.8,
                            raw={
                                "issuer": issuer,
                                "cert_id": cert_id,
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


@celery_app.task(name="url_discovery.certspotter")
def run_certspotter_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = CertspotterModule()
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
