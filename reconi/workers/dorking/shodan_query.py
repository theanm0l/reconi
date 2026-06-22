"""Shodan dorking module — search Shodan for hosts matching a domain."""

import asyncio
import os
from datetime import datetime, timezone

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, ReconJob
from ...core.plugin import Finding, ReconModule


class ShodanQueryModule(ReconModule):
    name = "shodan_query"
    category = "dorking"
    description = "Query Shodan for hosts related to a domain"
    requires_api_key = True
    rate_limit_delay = 1.5

    QUERIES = [
        'org:"{domain}"',
        "hostname:{domain}",
        'ssl:"{domain}"',
        'http.title:"{domain}"',
    ]

    def __init__(self) -> None:
        self.api_key = os.environ.get("SHODAN_API_KEY", "")

    async def _shodan_search(self, client: httpx.AsyncClient, query: str) -> list[dict]:
        if not self.api_key:
            return []
        url = "https://api.shodan.io/shodan/host/search"
        params = {"key": self.api_key, "query": query}
        try:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
            return data.get("matches", [])
        except Exception:
            return []

    async def run(self, target: str) -> list[Finding]:
        domain = target.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]
        findings: list[Finding] = []
        if not self.api_key:
            return findings
        async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
            for query_template in self.QUERIES:
                query = query_template.format(domain=domain)
                matches = await self._shodan_search(client, query)
                for match in matches:
                    ip_str = match.get("ip_str", "")
                    port = match.get("port", 0)
                    value = f"{ip_str}:{port}"
                    banner_info = ""
                    data_str = match.get("data", "")
                    if data_str:
                        banner_info = data_str[:200]
                    org = match.get("org", "")
                    findings.append(
                        Finding(
                            source=self.name,
                            type="host",
                            value=value,
                            context=f"org: {org}, banner: {banner_info}",
                            url_found_on=f"https://api.shodan.io/shodan/host/search?query={query}",
                            severity="info",
                            confidence=0.7,
                            raw={
                                "ip": ip_str,
                                "port": port,
                                "org": org,
                                "hostnames": match.get("hostnames", []),
                                "query": query,
                            },
                            found_at=datetime.now(timezone.utc).isoformat(),
                        )
                    )
                await asyncio.sleep(self.rate_limit_delay)
        return findings


shodan_query_module = ShodanQueryModule()


@celery_app.task(name="dorking.shodan_query")
def run_shodan_query_task(job_id: str, target: str) -> list[dict]:
    async def _run() -> list[dict]:
        findings = await shodan_query_module.run(target)
        return [f.__dict__ for f in findings]

    results = asyncio.run(_run())
    db = SessionLocal()
    try:
        job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
        if job:
            job.items_found = len(results)
            job.status = "completed"
            job.completed_at = datetime.now(timezone.utc)
            db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()
    return results
