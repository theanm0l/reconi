"""Have I Been Pwned — breach and pastebin lookup module."""

import asyncio
import os
from urllib.parse import urlparse

import httpx

from ...core.celery_app import celery_app
from ...core.database import SessionLocal, Finding as DBFinding, ReconJob
from ...core.plugin import Finding, ReconModule


class HaveibeenpwnedModule(ReconModule):
    name = "haveibeenpwned"
    category = "leaks"
    description = "Check Have I Been Pwned for domain breaches and pastebin leaks"
    requires_api_key = False
    rate_limit_delay = 1.5

    def __init__(self) -> None:
        self.api_key = os.environ.get("HIBP_API_KEY", "")

    async def _breaches(self, client: httpx.AsyncClient, domain: str) -> list[dict]:
        url = f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}"
        headers = {}
        if self.api_key:
            headers["hibp-api-key"] = self.api_key
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 404:
                return []
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return []

    async def _paste_account(self, client: httpx.AsyncClient, email: str) -> list[dict]:
        url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}"
        headers = {}
        if self.api_key:
            headers["hibp-api-key"] = self.api_key
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 404:
                return []
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return []

    async def run(self, target: str) -> list[Finding]:
        findings: list[Finding] = []
        domain = _extract_domain(target)

        async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
            breaches = await self._breaches(client, domain)

            for breach in breaches:
                name = breach.get("Name", "") or breach.get("Title", "")
                title = breach.get("Title", "")
                breach_date = breach.get("BreachDate", "")
                data_classes = breach.get("DataClasses", [])
                description = breach.get("Description", "")

                context_parts = []
                if title:
                    context_parts.append(title)
                if breach_date:
                    context_parts.append(f"date: {breach_date}")
                if data_classes:
                    context_parts.append(f"data: {', '.join(data_classes[:5])}")

                findings.append(Finding(
                    source=self.name,
                    type="breach_info",
                    value=name,
                    context=" | ".join(context_parts),
                    url_found_on=f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}",
                    severity="high",
                    confidence=0.85,
                    raw={
                        "name": name,
                        "title": title,
                        "breach_date": breach_date,
                        "data_classes": data_classes,
                        "description": description[:300] if description else "",
                    },
                ))

            common_emails = [f"admin@{domain}", f"info@{domain}", f"contact@{domain}",
                             f"support@{domain}", f"hello@{domain}"]
            for email in common_emails:
                pastes = await self._paste_account(client, email)
                for paste in pastes:
                    paste_id = paste.get("Id", "")
                    paste_source = paste.get("Source", "")
                    paste_title = paste.get("Title", "")
                    paste_date = paste.get("Date", "")

                    findings.append(Finding(
                        source=self.name,
                        type="breach_info",
                        value=email,
                        context=f"Paste found: {paste_title} (source: {paste_source}, date: {paste_date})",
                        url_found_on=f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}",
                        severity="high",
                        confidence=0.75,
                        raw={"paste_id": paste_id, "source": paste_source,
                             "title": paste_title, "date": paste_date, "email": email},
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


@celery_app.task(name="leaks.haveibeenpwned")
def run_haveibeenpwned_task(job_id: str, target: str):
    async def _run():
        db = SessionLocal()
        try:
            job = db.query(ReconJob).filter(ReconJob.id == job_id).first()
            if job:
                job.status = "running"
                db.commit()

            module = HaveibeenpwnedModule()
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
