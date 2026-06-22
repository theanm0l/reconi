"""Censys certificate-based subdomain discovery module."""
import asyncio
import base64
import os
import random
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class CensysModule(ReconModule):
    name = "censys"
    category = "url_discovery"
    description = "Discover subdomains and certificates from Censys search"
    requires_api_key = True
    rate_limit_delay = 2.0

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)
        api_id = os.environ.get("CENSYS_API_KEY", "")
        api_secret = os.environ.get("CENSYS_SECRET", "")

        if not api_id or not api_secret:
            findings.append(Finding(
                source=self.name,
                type="error",
                value="CENSYS_API_KEY and/or CENSYS_SECRET not set",
                severity="info",
                confidence=0.0,
            ))
            return findings

        auth_token = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        headers = {
            "Authorization": f"Basic {auth_token}",
            "Accept": "application/json",
        }

        try:
            url = f"https://search.censys.io/api/v2/certificates/search?q=names:{domain}"
            async with httpx.AsyncClient(timeout=httpx.Timeout(60)) as client:
                resp = await client.get(url, headers=headers)
                resp.raise_for_status()
                data = resp.json()

            results = data.get("result", {}).get("hits", [])
            seen: set[str] = set()

            for hit in results:
                names = hit.get("names", [])
                cert_id = hit.get("fingerprint_sha256", "")

                for name in names:
                    if isinstance(name, str) and name.strip() and name not in seen:
                        name = name.strip().lower()
                        seen.add(name)

                        finding_type = "subdomain"
                        if name == domain:
                            finding_type = "domain"
                        elif not name.endswith("." + domain):
                            finding_type = "domain"

                        findings.append(Finding(
                            source=self.name,
                            type=finding_type,
                            value=name,
                            context=f"Censys certificate SAN entry (SHA256: {cert_id[:16]}...)",
                            url_found_on=url,
                            severity="info",
                            confidence=0.8,
                            raw={
                                "cert_fingerprint": cert_id,
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


@celery_app.task(name="url_discovery.censys")
def run_censys_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = CensysModule()
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
