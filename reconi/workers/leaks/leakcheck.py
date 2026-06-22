"""LeakCheck — leaked credential search module."""

import asyncio
import os
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class LeakcheckModule(ReconModule):
    name = "leakcheck"
    category = "leaks"
    description = "Search LeakCheck for exposed credentials tied to a domain"
    requires_api_key = True
    rate_limit_delay = 1.0

    def __init__(self) -> None:
        self.api_key = os.environ.get("LEAKCHECK_API_KEY", "")

    async def _query(self, client: httpx.AsyncClient, check: str) -> list[dict]:
        url = "https://leakcheck.io/api/public"
        params = {"key": self.api_key, "check": check}
        try:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
            if data.get("success") and isinstance(data.get("result"), list):
                return data["result"]
            if isinstance(data, list):
                return data
            return []
        except Exception:
            return []

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        if not self.api_key:
            findings.append(Finding(
                source=self.name,
                type="error",
                value="LEAKCHECK_API_KEY not set",
                severity="info",
                confidence=0.0,
            ))
            return findings

        search_terms = [domain]

        root_domain = _root_domain(domain)
        if root_domain != domain:
            search_terms.append(f"@{root_domain}")

        async with httpx.AsyncClient(timeout=httpx.Timeout(60)) as client:
            for term in search_terms:
                results = await self._query(client, term)
                for entry in results:
                    email_val = entry.get("email", "") or entry.get("line", "")
                    password = entry.get("password", "") or entry.get("pass", "")
                    source_name = entry.get("source", "") or entry.get("sources", "")

                    if not email_val:
                        continue

                    has_password = bool(password)
                    context_parts = []
                    if source_name:
                        context_parts.append(f"source: {source_name}")
                    if password:
                        context_parts.append(f"password: {password[:8]}...")

                    findings.append(Finding(
                        source=self.name,
                        type="leaked_credential",
                        value=email_val,
                        context=" | ".join(context_parts) if context_parts else "LeakCheck record",
                        url_found_on=f"https://leakcheck.io/api/public?check={term}",
                        severity="critical" if has_password else "high",
                        confidence=0.9 if has_password else 0.65,
                        raw=entry,
                    ))

                await asyncio.sleep(self.rate_limit_delay)

        return findings


def _extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.netloc:
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.rsplit(":", 1)[0]
        return netloc
    return target.split(":")[0].split("/")[0]


def _root_domain(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) > 2:
        return ".".join(parts[-2:])
    return domain


@celery_app.task(name="leaks.leakcheck")
def run_leakcheck_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = LeakcheckModule()
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
