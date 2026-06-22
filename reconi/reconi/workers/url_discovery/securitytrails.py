"""SecurityTrails subdomain and historical DNS discovery module."""
import asyncio
import os
import random
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class SecuritytrailsModule(ReconModule):
    name = "securitytrails"
    category = "url_discovery"
    description = "Discover subdomains and historical DNS records from SecurityTrails"
    requires_api_key = True
    rate_limit_delay = 2.0

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)
        api_key = os.environ.get("SECURITYTRAILS_API_KEY", "")

        if not api_key:
            findings.append(Finding(
                source=self.name,
                type="error",
                value="SECURITYTRAILS_API_KEY not set",
                severity="info",
                confidence=0.0,
            ))
            return findings

        headers = {"apikey": api_key}

        async with httpx.AsyncClient(timeout=httpx.Timeout(60)) as client:
            for result in await self._fetch_subdomains(client, domain, headers):
                findings.append(result)
            await asyncio.sleep(random.uniform(0.5, 1.5))

            for result in await self._fetch_historical_dns(client, domain, headers):
                findings.append(result)

        return findings

    async def _fetch_subdomains(self, client: httpx.AsyncClient, domain: str, headers: dict) -> list[Finding]:
        results: list[Finding] = []
        try:
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()

            subdomains = data.get("subdomains", [])
            for sub in subdomains:
                if isinstance(sub, str) and sub.strip():
                    fqdn = f"{sub}.{domain}"
                    results.append(Finding(
                        source=self.name,
                        type="subdomain",
                        value=fqdn,
                        context="Found via SecurityTrails subdomains",
                        url_found_on=url,
                        severity="info",
                        confidence=0.8,
                    ))

            suffixes = data.get("suffixes", [])
            for suffix in suffixes:
                if isinstance(suffix, str) and suffix.strip():
                    results.append(Finding(
                        source=self.name,
                        type="subdomain",
                        value=suffix,
                        context="Found via SecurityTrails subdomain suffix",
                        url_found_on=url,
                        severity="info",
                        confidence=0.7,
                    ))
        except Exception:
            pass
        return results

    async def _fetch_historical_dns(self, client: httpx.AsyncClient, domain: str, headers: dict) -> list[Finding]:
        results: list[Finding] = []
        try:
            url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()

            records = data.get("records", [])
            for record in records:
                values = record.get("values", [])
                for val in values:
                    ip = val.get("ip", "")
                    if ip:
                        results.append(Finding(
                            source=self.name,
                            type="ip",
                            value=ip,
                            context=f"Historical A record for {domain} (org: {record.get('organizations', [])})",
                            url_found_on=url,
                            severity="info",
                            confidence=0.7,
                            raw=val,
                        ))
        except Exception:
            pass
        return results


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
        return netloc
    return target.split(":")[0].split("/")[0]


@celery_app.task(name="url_discovery.securitytrails")
def run_securitytrails_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = SecuritytrailsModule()
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
