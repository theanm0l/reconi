"""DNSDumpster subdomain and host discovery module with CSRF token handling."""
import asyncio
import random
import re
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class DnsdumpsterModule(ReconModule):
    name = "dnsdumpster"
    category = "url_discovery"
    description = "Discover subdomains and hosts from DNSDumpster via HTML scraping"
    requires_api_key = False
    rate_limit_delay = 2.0

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)
        seen: set[str] = set()

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(60)) as client:
                csrf_token = await self._fetch_csrf_token(client)
                if not csrf_token:
                    findings.append(Finding(
                        source=self.name,
                        type="error",
                        value="Could not fetch CSRF token from DNSDumpster",
                        severity="info",
                        confidence=0.0,
                    ))
                    return findings

                headers = {
                    "Referer": "https://dnsdumpster.com/",
                    "Content-Type": "application/x-www-form-urlencoded",
                }
                data_payload = {
                    "csrfmiddlewaretoken": csrf_token,
                    "targetip": domain,
                    "user": "free",
                }

                resp = await client.post(
                    "https://dnsdumpster.com/",
                    headers=headers,
                    data=data_payload,
                )
                resp.raise_for_status()
                html = resp.text

                table_pattern = re.compile(r'<td class="col-md-4">(.*?)</td>', re.DOTALL)
                for match in table_pattern.finditer(html):
                    hostname = match.group(1).strip()
                    hostname = re.sub(r'<.*?>', '', hostname).strip()
                    if hostname and hostname not in seen and "." in hostname:
                        seen.add(hostname)
                        findings.append(Finding(
                            source=self.name,
                            type="subdomain",
                            value=hostname,
                            context="Found via DNSDumpster DNS recon",
                            url_found_on="https://dnsdumpster.com/",
                            severity="info",
                            confidence=0.6,
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

    async def _fetch_csrf_token(self, client: httpx.AsyncClient) -> str | None:
        try:
            resp = await client.get("https://dnsdumpster.com/")
            resp.raise_for_status()
            html = resp.text

            match = re.search(
                r'<input\s+type=["\']hidden["\']\s+name=["\']csrfmiddlewaretoken["\']\s+value=["\']([^"\']+)["\']',
                html,
            )
            if match:
                return match.group(1)
        except Exception:
            pass
        return None


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
        return netloc
    return target.split(":")[0].split("/")[0]


@celery_app.task(name="url_discovery.dnsdumpster")
def run_dnsdumpster_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = DnsdumpsterModule()
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
