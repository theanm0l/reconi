"""Dehashed — leaked credential search module."""

import asyncio
import os
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class DehashedModule(ReconModule):
    name = "dehashed"
    category = "leaks"
    description = "Search Dehashed for leaked credentials tied to a domain"
    requires_api_key = True
    rate_limit_delay = 0.2

    def __init__(self) -> None:
        self.api_key = os.environ.get("DEHASHED_API_KEY", "")
        self.email = os.environ.get("DEHASHED_EMAIL", "")

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        if not self.api_key or not self.email:
            findings.append(Finding(
                source=self.name,
                type="error",
                value="DEHASHED_API_KEY and DEHASHED_EMAIL must be set",
                severity="info",
                confidence=0.0,
            ))
            return findings

        queries = [
            f"email:{domain}",
            f"username:{domain}",
            f"domain:{domain}",
        ]

        auth = httpx.BasicAuth(self.email, self.api_key)
        base_url = "https://api.dehashed.com/search"

        async with httpx.AsyncClient(timeout=httpx.Timeout(60), auth=auth) as client:
            for query in queries:
                try:
                    resp = await client.get(base_url, params={"query": query})
                    resp.raise_for_status()
                    data = resp.json()
                    entries = data.get("entries", [])
                    total = data.get("total", 0)

                    for entry in entries:
                        email_val = entry.get("email", "")
                        password = entry.get("password", "")
                        hashed = entry.get("hashed_password", "")
                        db_name = entry.get("database_name", "")
                        username = entry.get("username", "")
                        name = entry.get("name", "")
                        address = entry.get("address", "")
                        phone = entry.get("phone", "")
                        ip_address = entry.get("ip_address", "")

                        value = email_val or username or name or db_name
                        if not value:
                            continue

                        has_password = bool(password or hashed)
                        context_parts = []
                        if db_name:
                            context_parts.append(f"db: {db_name}")
                        if username:
                            context_parts.append(f"user: {username}")
                        if name:
                            context_parts.append(f"name: {name}")
                        if address:
                            context_parts.append(f"addr: {address}")
                        if phone:
                            context_parts.append(f"phone: {phone}")
                        if ip_address:
                            context_parts.append(f"ip: {ip_address}")

                        findings.append(Finding(
                            source=self.name,
                            type="leaked_credential",
                            value=value,
                            context=" | ".join(context_parts) if context_parts else f"Dehashed record (total: {total})",
                            url_found_on=resp.url,
                            severity="critical" if has_password else "high",
                            confidence=0.85 if has_password else 0.6,
                            raw=entry,
                        ))

                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 429:
                        await asyncio.sleep(2.0)
                    else:
                        findings.append(Finding(
                            source=self.name,
                            type="error",
                            value=f"HTTP {e.response.status_code} for query '{query}'",
                            severity="info",
                            confidence=0.0,
                        ))
                except Exception as e:
                    findings.append(Finding(
                        source=self.name,
                        type="error",
                        value=str(e),
                        severity="info",
                        confidence=0.0,
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


@celery_app.task(name="leaks.dehashed")
def run_dehashed_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = DehashedModule()
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
