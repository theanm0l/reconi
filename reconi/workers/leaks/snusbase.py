"""Snusbase — leaked credential and breach data search module."""

import asyncio
import os
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class SnusbaseModule(ReconModule):
    name = "snusbase"
    category = "leaks"
    description = "Search Snusbase for leaked credentials associated with a domain"
    requires_api_key = True
    rate_limit_delay = 1.5

    def __init__(self) -> None:
        self.api_key = os.environ.get("SNUSBASE_API_KEY", "")
        self.auth = os.environ.get("SNUSBASE_AUTH", "")

    async def _search(self, client: httpx.AsyncClient, terms: list[str], search_type: str) -> list[dict]:
        url = "https://api.snusbase.com/data/search"
        headers = {"Auth": self.auth, "Content-Type": "application/json"}
        payload = {"terms": terms, "types": [search_type]}
        try:
            resp = await client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", {})
            entries = []
            for term_key, term_results in results.items():
                if isinstance(term_results, list):
                    entries.extend(term_results)
                elif isinstance(term_results, dict):
                    entries.append(term_results)
            return entries
        except Exception:
            return []

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        if not self.api_key or not self.auth:
            findings.append(Finding(
                source=self.name,
                type="error",
                value="SNUSBASE_API_KEY and SNUSBASE_AUTH must be set",
                severity="info",
                confidence=0.0,
            ))
            return findings

        root_domain = _root_domain(domain)
        cctld = domain.rsplit(".", 1)[-1] if "." in domain else ""

        terms = [domain, f"@{domain}"]
        if root_domain != domain:
            terms.append(root_domain)
            terms.append(f"@{root_domain}")
        if cctld and len(cctld) <= 4:
            terms.append(cctld)

        search_types = ["email", "username", "name"]

        async with httpx.AsyncClient(timeout=httpx.Timeout(60)) as client:
            for search_type in search_types:
                entries = await self._search(client, terms, search_type)
                for entry in entries:
                    email_val = entry.get("email", "")
                    password = entry.get("password", "")
                    hash_val = entry.get("hash", "")
                    salt = entry.get("salt", "")
                    name = entry.get("name", "")
                    username = entry.get("username", "")
                    lastip = entry.get("lastip", "")
                    lastdate = entry.get("lastdate", "")

                    value = email_val or username or name
                    if not value:
                        continue

                    has_password = bool(password or hash_val)
                    context_parts = []
                    if username and value != username:
                        context_parts.append(f"user: {username}")
                    if name and value != name:
                        context_parts.append(f"name: {name}")
                    if password:
                        context_parts.append(f"password: {password[:8]}...")
                    if hash_val:
                        context_parts.append(f"hash: {hash_val[:16]}...")
                    if salt:
                        context_parts.append(f"salt: {salt}")
                    if lastip:
                        context_parts.append(f"ip: {lastip}")
                    if lastdate:
                        context_parts.append(f"date: {lastdate}")

                    findings.append(Finding(
                        source=self.name,
                        type="leaked_credential",
                        value=value,
                        context=" | ".join(context_parts) if context_parts else "Snusbase record",
                        url_found_on="https://api.snusbase.com/data/search",
                        severity="critical" if has_password else "high",
                        confidence=0.9 if has_password else 0.6,
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


@celery_app.task(name="leaks.snusbase")
def run_snusbase_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = SnusbaseModule()
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
