"""AlienVault OTX URL and passive DNS discovery module."""
import asyncio
import random
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class AlienvaultModule(ReconModule):
    name = "alienvault"
    category = "url_discovery"
    description = "Discover URLs and passive DNS records from AlienVault OTX"
    requires_api_key = False
    rate_limit_delay = 1.0

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        async with httpx.AsyncClient(timeout=httpx.Timeout(60)) as client:
            for result in await self._fetch_url_list(client, domain):
                findings.append(result)
            await asyncio.sleep(random.uniform(0.5, 1.5))

            for result in await self._fetch_passive_dns(client, domain):
                findings.append(result)

        return findings

    async def _fetch_url_list(self, client: httpx.AsyncClient, domain: str) -> list[Finding]:
        results: list[Finding] = []
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500"
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()

            for entry in data.get("url_list", []):
                entry_url = entry.get("url", "")
                if entry_url:
                    results.append(Finding(
                        source=self.name,
                        type="url",
                        value=entry_url,
                        context="Found via AlienVault OTX URL list",
                        url_found_on=url,
                        severity="info",
                        confidence=0.7,
                        raw=entry,
                    ))
        except Exception:
            pass
        return results

    async def _fetch_passive_dns(self, client: httpx.AsyncClient, domain: str) -> list[Finding]:
        results: list[Finding] = []
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()

            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "")
                address = entry.get("address", "")
                record_type = entry.get("record_type", "")

                if hostname:
                    results.append(Finding(
                        source=self.name,
                        type="subdomain" if hostname.endswith("." + domain) else "hostname",
                        value=hostname,
                        context=f"Passive DNS record ({record_type} -> {address})",
                        url_found_on=url,
                        severity="info",
                        confidence=0.6,
                        raw=entry,
                    ))

                if address:
                    results.append(Finding(
                        source=self.name,
                        type="ip",
                        value=address,
                        context=f"Passive DNS IP for {hostname} ({record_type})",
                        url_found_on=url,
                        severity="info",
                        confidence=0.6,
                        raw=entry,
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


@celery_app.task(name="url_discovery.alienvault")
def run_alienvault_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = AlienvaultModule()
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
