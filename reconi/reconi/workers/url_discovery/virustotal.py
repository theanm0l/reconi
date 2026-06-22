"""VirusTotal domain URL and subdomain discovery module."""
import asyncio
import os
import random
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class VirustotalModule(ReconModule):
    name = "virustotal"
    category = "url_discovery"
    description = "Discover URLs and subdomains from VirusTotal domain report"
    requires_api_key = True
    rate_limit_delay = 16.0

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)
        api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")

        if not api_key:
            findings.append(Finding(
                source=self.name,
                type="error",
                value="VIRUSTOTAL_API_KEY not set",
                severity="info",
                confidence=0.0,
            ))
            return findings

        try:
            headers = {"x-apikey": api_key}
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"

            async with httpx.AsyncClient(timeout=httpx.Timeout(60)) as client:
                resp = await client.get(url, headers=headers)
                resp.raise_for_status()
                data = resp.json()

            resolved_urls = data.get("data", {}).get("attributes", {}).get("last_https_response_certificate", {})
            cert_data = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})

            for engine, result in cert_data.items():
                if isinstance(result, dict):
                    category = result.get("category", "")
                    if category == "malicious":
                        findings.append(Finding(
                            source=self.name,
                            type="alert",
                            value=f"{domain} flagged by {engine}",
                            context=f"VirusTotal detection: {category}",
                            url_found_on=url,
                            severity="medium",
                            confidence=0.8,
                            raw=result,
                        ))

            cert = data.get("data", {}).get("attributes", {}).get("last_https_response_certificate", {})
            if isinstance(cert, dict):
                cert_info = cert.get("certificate", {})
                if isinstance(cert_info, dict):
                    subject = cert_info.get("subject", {})
                    if isinstance(subject, dict):
                        cn = subject.get("CN", "")
                        if cn:
                            findings.append(Finding(
                                source=self.name,
                                type="cert_subject",
                                value=cn,
                                context="Certificate subject from VirusTotal",
                                url_found_on=url,
                                severity="info",
                                confidence=0.7,
                            ))

                    extensions = cert_info.get("extensions", {})
                    if isinstance(extensions, dict):
                        san = extensions.get("subject_alternative_name", [])
                        for name in san:
                            if isinstance(name, str):
                                findings.append(Finding(
                                    source=self.name,
                                    type="subdomain",
                                    value=name,
                                    context="Subject Alternative Name from VirusTotal cert",
                                    url_found_on=url,
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


@celery_app.task(name="url_discovery.virustotal")
def run_virustotal_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = VirustotalModule()
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
