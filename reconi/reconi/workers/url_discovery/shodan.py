"""Shodan DNS and host discovery module."""
import asyncio
import os
import random
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class ShodanModule(ReconModule):
    name = "shodan"
    category = "url_discovery"
    description = "Discover DNS records and host information from Shodan"
    requires_api_key = True
    rate_limit_delay = 2.0

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)
        api_key = os.environ.get("SHODAN_API_KEY", "")

        if not api_key:
            findings.append(Finding(
                source=self.name,
                type="error",
                value="SHODAN_API_KEY not set",
                severity="info",
                confidence=0.0,
            ))
            return findings

        async with httpx.AsyncClient(timeout=httpx.Timeout(60)) as client:
            for result in await self._fetch_dns(client, domain, api_key):
                findings.append(result)
            await asyncio.sleep(random.uniform(0.5, 1.5))

            for result in await self._fetch_host_search(client, domain, api_key):
                findings.append(result)

        return findings

    async def _fetch_dns(self, client: httpx.AsyncClient, domain: str, api_key: str) -> list[Finding]:
        results: list[Finding] = []
        try:
            url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
            resp = await client.get(url)
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
                        context="Found via Shodan DNS resolution",
                        url_found_on=url,
                        severity="info",
                        confidence=0.7,
                    ))

            for record_type in ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]:
                records = data.get("data", [])
                for rec in records:
                    if rec.get("type") == record_type:
                        value = rec.get("value", "")
                        rec_subdomain = rec.get("subdomain", "")
                        if value:
                            results.append(Finding(
                                source=self.name,
                                type=f"dns_{record_type.lower()}",
                                value=value,
                                context=f"DNS {record_type} record{f' for {rec_subdomain}' if rec_subdomain else ''}",
                                url_found_on=url,
                                severity="info",
                                confidence=0.8,
                                raw={"subdomain": rec_subdomain, "type": record_type},
                            ))
        except Exception:
            pass
        return results

    async def _fetch_host_search(self, client: httpx.AsyncClient, domain: str, api_key: str) -> list[Finding]:
        results: list[Finding] = []
        try:
            url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=hostname:{domain}"
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()

            matches = data.get("matches", [])
            for match in matches:
                ip_str = match.get("ip_str", "")
                port = match.get("port", 0)
                org = match.get("org", "")
                hostnames = match.get("hostnames", [])
                product = match.get("product", "")

                if ip_str:
                    results.append(Finding(
                        source=self.name,
                        type="host",
                        value=f"{ip_str}:{port}" if port else ip_str,
                        context=f"Shodan host: {org}, product: {product}",
                        url_found_on=url,
                        severity="info",
                        confidence=0.7,
                        raw={
                            "ip": ip_str,
                            "port": port,
                            "org": org,
                            "hostnames": hostnames,
                            "product": product,
                        },
                    ))

                for hostname in hostnames:
                    if hostname:
                        results.append(Finding(
                            source=self.name,
                            type="hostname",
                            value=hostname,
                            context=f"Hostname associated with IP {ip_str}",
                            url_found_on=url,
                            severity="info",
                            confidence=0.6,
                            raw={"ip": ip_str},
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


@celery_app.task(name="url_discovery.shodan")
def run_shodan_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = ShodanModule()
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
